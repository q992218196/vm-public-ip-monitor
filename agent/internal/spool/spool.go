package spool

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"vm-monitor/agent/internal/config"
	"vm-monitor/agent/internal/wire"
)

type Spool struct {
	mu      sync.Mutex
	c       config.Config
	dropped uint64
	client  *http.Client
}

func New(c config.Config) (*Spool, error) {
	if e := os.MkdirAll(filepath.Join(c.DataDir, "spool"), 0700); e != nil {
		return nil, e
	}
	// Incomplete files are never acknowledged and cannot be replayed. Remove
	// crash leftovers so they cannot permanently exhaust the bounded cache.
	files, _ := filepath.Glob(filepath.Join(c.DataDir, "spool", "*.tmp"))
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			return nil, err
		}
	}
	return &Spool{c: c, client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func DirBytes(root string) int64 {
	var n int64
	filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e == nil && !d.IsDir() {
			if i, e := d.Info(); e == nil {
				n += i.Size()
			}
		}
		return nil
	})
	return n
}
func (s *Spool) Status() (int64, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return DirBytes(filepath.Join(s.c.DataDir, "spool")), s.dropped
}
func (s *Spool) Put(b wire.Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, e := json.Marshal(b)
	if e != nil {
		return e
	}
	if len(data) > 8*1024*1024 {
		s.dropped++
		return errors.New("batch exceeds 8 MiB API limit")
	}
	dir := filepath.Join(s.c.DataDir, "spool")
	used := DirBytes(dir)
	total := DirBytes(s.c.DataDir)
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	priority := len(b.Sites) > 0 || b.Health.KernelDrops+b.Health.StateDropped+b.Health.SpoolDropped > 0
	for _, m := range b.Metrics {
		if m.UniqueTargets >= 32 || m.MaxPortsPerTarget >= 20 || m.AuthAttempts >= 20 {
			priority = true
			break
		}
	}
	var normalBytes int64
	for _, f := range files {
		if !strings.HasPrefix(filepath.Base(f), "0-") {
			if i, e := os.Stat(f); e == nil {
				normalBytes += i.Size()
			}
		}
	}
	// Reserve one quarter for potentially important evidence. Normal batches
	// never evict priority batches. Priority overflow is still counted as loss.
	sort.Slice(files, func(i, j int) bool {
		pi := strings.HasPrefix(filepath.Base(files[i]), "0-")
		pj := strings.HasPrefix(filepath.Base(files[j]), "0-")
		if pi != pj {
			return !pi
		}
		return files[i] < files[j]
	})
	for _, f := range files {
		if used+int64(len(data)) <= s.c.SpoolLimitMiB*1024*1024 && total+int64(len(data)) <= s.c.DiskLimitMiB*1024*1024 && (priority || normalBytes+int64(len(data)) <= s.c.SpoolLimitMiB*1024*1024*3/4) {
			break
		}
		isPriority := strings.HasPrefix(filepath.Base(f), "0-")
		if !priority && isPriority {
			continue
		}
		i, e := os.Stat(f)
		if e == nil && os.Remove(f) == nil {
			used -= i.Size()
			total -= i.Size()
			if !isPriority {
				normalBytes -= i.Size()
			}
			s.dropped++
		}
	}
	if used+int64(len(data)) > s.c.SpoolLimitMiB*1024*1024 || total+int64(len(data)) > s.c.DiskLimitMiB*1024*1024 || (!priority && normalBytes+int64(len(data)) > s.c.SpoolLimitMiB*1024*1024*3/4) {
		s.dropped++
		return errors.New("disk budget exhausted; batch dropped")
	}
	prefix := "1"
	if priority {
		prefix = "0"
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%020d-%s.json", prefix, time.Now().UnixNano(), b.ID))
	f, e := os.OpenFile(path+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		os.Remove(path + ".tmp")
		return e
	}
	return os.Rename(path+".tmp", path)
}
func (s *Spool) SendOne(ctx context.Context) (bool, error) {
	s.mu.Lock()
	files, _ := filepath.Glob(filepath.Join(s.c.DataDir, "spool", "*.json"))
	sort.Strings(files)
	if len(files) == 0 {
		s.mu.Unlock()
		return false, nil
	}
	path := files[0]
	data, e := os.ReadFile(path)
	s.mu.Unlock()
	if e != nil {
		return false, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(s.c.ServerURL, "/")+"/api/v1/agent/batches", bytes.NewReader(data))
	if e != nil {
		return false, e
	}
	req.Header.Set("Authorization", "Bearer "+s.c.Token)
	req.Header.Set("X-Node-ID", s.c.NodeID)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, e := s.client.Do(req)
	if e != nil {
		return false, e
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode == 400 || res.StatusCode == 413 || res.StatusCode == 422 {
		s.mu.Lock()
		defer s.mu.Unlock()
		if e := os.Remove(path); e == nil {
			s.dropped++
		}
		return false, fmt.Errorf("permanently rejected batch HTTP %d discarded and counted", res.StatusCode)
	}
	var ack struct {
		Accepted bool `json:"accepted"`
	}
	if res.StatusCode != 200 || json.Unmarshal(body, &ack) != nil || !ack.Accepted {
		return false, fmt.Errorf("upload rejected HTTP %d (retained locally)", res.StatusCode)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e = os.Remove(path); e != nil && !os.IsNotExist(e) {
		return false, e
	}
	return true, nil
}
