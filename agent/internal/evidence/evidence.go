package evidence

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"vm-monitor/agent/internal/config"
	"vm-monitor/agent/internal/spool"
)

var taskID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Task struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Lease    string `json:"lease_token"`
	Duration int    `json:"duration_seconds"`
	MaxBytes int64  `json:"max_bytes"`
	Snaplen  int    `json:"snaplen"`
}
type Metadata struct {
	Packets     uint64    `json:"packets"`
	Drops       uint64    `json:"queue_drops"`
	KernelDrops uint64    `json:"kernel_drops_observed"`
	Truncated   uint64    `json:"snaplen_truncated"`
	Started     time.Time `json:"started_at"`
	Ended       time.Time `json:"ended_at"`
	Stop        string    `json:"stop_reason"`
	Interfaces  []string  `json:"interfaces"`
}
type saved struct {
	Task Task     `json:"task"`
	Meta Metadata `json:"metadata"`
	Done bool     `json:"done"`
}
type frame struct {
	data []byte
	wire int
	at   time.Time
}
type active struct {
	ip          netip.Addr
	snaplen     int
	end         time.Time
	frames      chan frame
	drops       atomic.Uint64
	kernelDrops atomic.Uint64
}
type Recorder struct {
	mu            sync.RWMutex
	active        *active
	recording     atomic.Bool
	c             config.Config
	client        *http.Client
	nextUpload    time.Time
	uploadBackoff time.Duration
}

func New(c config.Config) *Recorder {
	timeout := time.Duration((32<<20)/max(128*1024, c.EvidenceUploadKiBps*1024)+30) * time.Second
	return &Recorder{c: c, client: &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Packet only copies selected frames into a bounded queue. It never writes to disk or waits for an uploader.
func (r *Recorder) Packet(data []byte, wire int, iface string, at time.Time) {
	if !r.recording.Load() {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	a := r.active
	if a == nil || at.After(a.end) || !matches(data, a.ip) {
		return
	}
	if len(a.frames) == cap(a.frames) {
		a.drops.Add(1)
		return
	}
	b := append([]byte(nil), data[:min(len(data), a.snaplen)]...)
	select {
	case a.frames <- frame{b, wire, at}:
	default:
		a.drops.Add(1)
	}
}

// Socket counters are read in five-second intervals, which can overlap the capture boundaries.
func (r *Recorder) KernelDrops(n uint64) {
	if !r.recording.Load() {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active != nil {
		r.active.kernelDrops.Add(n)
	}
}

func matches(b []byte, ip netip.Addr) bool {
	if len(b) < 14 {
		return false
	}
	typ := binary.BigEndian.Uint16(b[12:14])
	off := 14
	for n := 0; typ == 0x8100 || typ == 0x88a8; n++ {
		if n >= 2 || len(b) < off+4 {
			return false
		}
		typ = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
	}
	if typ == 0x0800 && len(b) >= off+20 && b[off]>>4 == 4 {
		return netip.AddrFrom4([4]byte(b[off+12:off+16])) == ip || netip.AddrFrom4([4]byte(b[off+16:off+20])) == ip
	}
	if typ == 0x86dd && len(b) >= off+40 && b[off]>>4 == 6 {
		return netip.AddrFrom16([16]byte(b[off+8:off+24])) == ip || netip.AddrFrom16([16]byte(b[off+24:off+40])) == ip
	}
	return false
}

func (r *Recorder) Run(ctx context.Context) {
	dir := filepath.Join(r.c.DataDir, "evidence")
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("evidence: directory unavailable")
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		r.prune()
		if !r.c.EvidenceEnabled {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			continue
		}
		r.sendPending(ctx)
		task, err := r.claim(ctx)
		if err != nil {
			log.Printf("evidence: %v", err)
		} else if task != nil {
			if err = r.record(ctx, *task); err != nil {
				log.Printf("evidence: capture failed: %v", err)
				r.fail(ctx, *task, "采集失败：磁盘预算、空间或文件写入不足")
			} else {
				r.sendPending(ctx)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (r *Recorder) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	q, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(r.c.ServerURL, "/")+path, body)
	if e == nil {
		q.Header.Set("Authorization", "Bearer "+r.c.Token)
		q.Header.Set("X-Node-ID", r.c.NodeID)
	}
	return q, e
}
func (r *Recorder) claim(ctx context.Context) (*Task, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	q, e := r.request(ctx, http.MethodGet, "/api/v1/agent/captures/claim", nil)
	if e != nil {
		return nil, e
	}
	s, e := r.client.Do(q)
	if e != nil {
		return nil, e
	}
	defer s.Body.Close()
	if s.StatusCode != 200 {
		return nil, fmt.Errorf("capture control HTTP %d", s.StatusCode)
	}
	var reply struct {
		Task *Task `json:"task"`
	}
	if e = json.NewDecoder(io.LimitReader(s.Body, 4096)).Decode(&reply); e != nil {
		return nil, e
	}
	if reply.Task != nil && !r.valid(*reply.Task) {
		return nil, errors.New("invalid capture instruction")
	}
	return reply.Task, nil
}
func (r *Recorder) valid(t Task) bool {
	ip, e := netip.ParseAddr(t.IP)
	if e != nil || !taskID.MatchString(t.ID) || len(t.Lease) != 64 || t.Duration < 1 || t.Duration > 60 || t.MaxBytes < 24 || t.MaxBytes > 32<<20 || t.Snaplen < 64 || t.Snaplen > 65535 {
		return false
	}
	for _, cidr := range r.c.CIDRs {
		p, e := netip.ParsePrefix(cidr)
		if e == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}
func (r *Recorder) record(ctx context.Context, t Task) error {
	r.prune()
	dir := filepath.Join(r.c.DataDir, "evidence")
	nonSpool := spool.DirBytes(r.c.DataDir) - spool.DirBytes(filepath.Join(r.c.DataDir, "spool"))
	if spool.DirBytes(dir)+t.MaxBytes > r.c.EvidenceLimitMiB<<20 || nonSpool+t.MaxBytes+(r.c.SpoolLimitMiB+128)<<20 > r.c.DiskLimitMiB<<20 || !freeSpace(dir, t.MaxBytes+128<<20) {
		return errors.New("insufficient reserved evidence space")
	}
	part := filepath.Join(dir, t.ID+".part")
	f, e := os.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer os.Remove(part)
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], uint32(t.Snaplen))
	binary.LittleEndian.PutUint32(h[20:], 1)
	if _, e = f.Write(h); e != nil {
		f.Close()
		return e
	}
	a := &active{ip: netip.MustParseAddr(t.IP), snaplen: t.Snaplen, end: time.Now().Add(time.Duration(t.Duration) * time.Second), frames: make(chan frame, 128)}
	meta := Metadata{Started: time.Now().UTC(), Stop: "duration", Interfaces: r.c.Interfaces}
	writer := bufio.NewWriterSize(f, 256<<10)
	r.mu.Lock()
	r.active = a
	r.recording.Store(true)
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.active = nil; r.recording.Store(false); r.mu.Unlock() }()
	timer := time.NewTimer(time.Until(a.end))
	defer timer.Stop()
	var n int64 = 24
loop:
	for {
		select {
		case <-ctx.Done():
			meta.Stop = "shutdown"
			break loop
		case <-timer.C:
			break loop
		case p := <-a.frames:
			if n+16+int64(len(p.data)) > t.MaxBytes {
				meta.Stop = "size"
				break loop
			}
			record := make([]byte, 16)
			binary.LittleEndian.PutUint32(record, uint32(p.at.Unix()))
			binary.LittleEndian.PutUint32(record[4:], uint32(p.at.Nanosecond()/1000))
			binary.LittleEndian.PutUint32(record[8:], uint32(len(p.data)))
			binary.LittleEndian.PutUint32(record[12:], uint32(p.wire))
			if _, e = writer.Write(record); e == nil {
				_, e = writer.Write(p.data)
			}
			if e != nil {
				break loop
			}
			n += 16 + int64(len(p.data))
			meta.Packets++
			if len(p.data) < p.wire {
				meta.Truncated++
			}
		}
	}
	r.mu.Lock()
	r.active = nil
	r.recording.Store(false)
	r.mu.Unlock()
	meta.Drops = a.drops.Load() + uint64(len(a.frames))
	meta.KernelDrops = a.kernelDrops.Load()
	meta.Ended = time.Now().UTC()
	if flushErr := writer.Flush(); e == nil {
		e = flushErr
	}
	if syncErr := f.Sync(); e == nil {
		e = syncErr
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Rename(part, filepath.Join(dir, t.ID+".pcap")); e != nil {
		return e
	}
	return writeJSON(filepath.Join(dir, t.ID+".json"), saved{Task: t, Meta: meta})
}
func writeJSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if e = os.WriteFile(path+".tmp", b, 0600); e != nil {
		return e
	}
	return os.Rename(path+".tmp", path)
}
func (r *Recorder) fail(ctx context.Context, t Task, message string) {
	q, e := r.request(ctx, http.MethodPost, "/api/v1/agent/captures/"+t.ID+"/complete", nil)
	if e != nil {
		return
	}
	q.Header.Set("X-Capture-Lease", t.Lease)
	q.Header.Set("X-Capture-Failure", message)
	s, e := r.client.Do(q)
	if e == nil {
		s.Body.Close()
	}
}
func (r *Recorder) sendPending(ctx context.Context) {
	if time.Now().Before(r.nextUpload) {
		return
	}
	files, _ := filepath.Glob(filepath.Join(r.c.DataDir, "evidence", "*.json"))
	for _, path := range files {
		b, e := os.ReadFile(path)
		if e != nil || len(b) > 8192 {
			continue
		}
		var item saved
		if json.Unmarshal(b, &item) != nil || item.Done || !r.valid(item.Task) {
			continue
		}
		f, e := os.Open(strings.TrimSuffix(path, ".json") + ".pcap")
		if e != nil {
			continue
		}
		q, e := r.request(ctx, http.MethodPost, "/api/v1/agent/captures/"+item.Task.ID+"/complete", &paced{ctx: ctx, r: f, rate: int64(r.c.EvidenceUploadKiBps) * 1024, start: time.Now()})
		if e != nil {
			f.Close()
			continue
		}
		info, _ := f.Stat()
		if info == nil || info.Size() > item.Task.MaxBytes {
			f.Close()
			continue
		}
		q.ContentLength = info.Size()
		meta, _ := json.Marshal(item.Meta)
		q.Header.Set("X-Capture-Metadata", base64.StdEncoding.EncodeToString(meta))
		q.Header.Set("X-Capture-Lease", item.Task.Lease)
		q.Header.Set("Content-Type", "application/vnd.tcpdump.pcap")
		s, e := r.client.Do(q)
		f.Close()
		if e != nil {
			r.deferUpload()
			return
		}
		s.Body.Close()
		if s.StatusCode == 200 || s.StatusCode == 409 || s.StatusCode == 404 || s.StatusCode == 422 || s.StatusCode == 413 {
			r.uploadBackoff = 0
			r.nextUpload = time.Time{}
			item.Done = true
			writeJSON(path, item)
			if s.StatusCode != 200 {
				log.Printf("evidence: PCAP retained locally; upload HTTP %d", s.StatusCode)
			}
		} else {
			r.deferUpload()
			log.Printf("evidence: upload HTTP %d; retained locally", s.StatusCode)
			return
		}
	}
}

func (r *Recorder) deferUpload() {
	if r.uploadBackoff == 0 {
		r.uploadBackoff = 10 * time.Second
	} else {
		r.uploadBackoff *= 2
	}
	if r.uploadBackoff > 5*time.Minute {
		r.uploadBackoff = 5 * time.Minute
	}
	r.nextUpload = time.Now().Add(r.uploadBackoff)
}

type paced struct {
	ctx   context.Context
	r     io.Reader
	rate  int64
	bytes int64
	start time.Time
}

func (p *paced) Read(b []byte) (int, error) {
	if p.rate <= 0 {
		return 0, errors.New("invalid upload rate")
	}
	wait := time.Duration(p.bytes*int64(time.Second)/p.rate) - time.Since(p.start)
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
			return 0, p.ctx.Err()
		case <-timer.C:
		}
	}
	n, e := p.r.Read(b[:min(len(b), 64<<10)])
	p.bytes += int64(n)
	return n, e
}
func (r *Recorder) prune() {
	dir := filepath.Join(r.c.DataDir, "evidence")
	files, _ := os.ReadDir(dir)
	sort.Slice(files, func(i, j int) bool {
		a, _ := files[i].Info()
		b, _ := files[j].Info()
		if a == nil || b == nil {
			return files[i].Name() < files[j].Name()
		}
		return a.ModTime().Before(b.ModTime())
	})
	total := spool.DirBytes(dir)
	count := 0
	for _, d := range files {
		if strings.HasSuffix(d.Name(), ".pcap") {
			count++
		}
	}
	for _, d := range files {
		info, e := d.Info()
		if e != nil || d.IsDir() {
			continue
		}
		path := filepath.Join(dir, d.Name())
		if strings.HasSuffix(d.Name(), ".part") || strings.HasSuffix(d.Name(), ".tmp") {
			if time.Since(info.ModTime()) > time.Hour {
				os.Remove(path)
			}
			continue
		}
		if !strings.HasSuffix(d.Name(), ".pcap") {
			continue
		}
		if time.Since(info.ModTime()) > time.Duration(r.c.EvidenceKeepHours)*time.Hour || total+(32<<20) > r.c.EvidenceLimitMiB<<20 || count >= 128 {
			if os.Remove(path) == nil {
				total -= info.Size()
				count--
				os.Remove(strings.TrimSuffix(path, ".pcap") + ".json")
			}
		}
	}
}
