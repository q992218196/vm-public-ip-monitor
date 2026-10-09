package evidence

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
	"vm-monitor/agent/internal/config"
)

func configForTest(t *testing.T) config.Config {
	t.Helper()
	c := config.Config{DataDir: t.TempDir(), CIDRs: []string{"203.0.113.0/24", "2001:db8::/32"}, Interfaces: []string{"eno1"}, EvidenceEnabled: true, EvidenceLimitMiB: 512, EvidenceKeepHours: 24, EvidenceUploadKiBps: 2048, DiskLimitMiB: 2048, SpoolLimitMiB: 512, Token: "test-token", NodeID: "test-node"}
	os.MkdirAll(filepath.Join(c.DataDir, "evidence"), 0700)
	return c
}
func testTask() Task {
	return Task{ID: "00000000-0000-4000-8000-000000000001", IP: "203.0.113.10", Lease: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Duration: 1, MaxBytes: 32 << 20, Snaplen: 64}
}
func ipv4(src, dst string) []byte {
	b := make([]byte, 100)
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	b[14] = 0x45
	copy(b[26:30], netip.MustParseAddr(src).AsSlice())
	copy(b[30:34], netip.MustParseAddr(dst).AsSlice())
	return b
}
func TestCaptureFiltersBothDirectionsAndWritesBoundedPcap(t *testing.T) {
	c := configForTest(t)
	r := New(c)
	task := testTask()
	task.MaxBytes = 24 + 16 + 64
	done := make(chan error, 1)
	go func() { done <- r.record(context.Background(), task) }()
	deadline := time.Now().Add(time.Second)
	for {
		r.mu.RLock()
		ready := r.active != nil
		r.mu.RUnlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("capture did not start")
		}
		time.Sleep(time.Millisecond)
	}
	r.Packet(ipv4("203.0.113.11", "1.1.1.1"), 100, "eno1", time.Now())
	r.Packet(ipv4("1.1.1.1", "203.0.113.10"), 100, "eno1", time.Now())
	r.Packet(ipv4("203.0.113.10", "1.1.1.1"), 100, "eno1", time.Now())
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(c.DataDir, "evidence", task.ID+".pcap"))
	if e != nil {
		t.Fatal(e)
	}
	if len(b) != 104 || binary.LittleEndian.Uint32(b) != 0xa1b2c3d4 || binary.LittleEndian.Uint32(b[32:]) != 64 || binary.LittleEndian.Uint32(b[36:]) != 100 {
		t.Fatal("invalid PCAP lengths")
	}
	var item saved
	meta, _ := os.ReadFile(filepath.Join(c.DataDir, "evidence", task.ID+".json"))
	json.Unmarshal(meta, &item)
	if item.Meta.Packets != 1 || item.Meta.Truncated != 1 || item.Meta.Stop != "size" {
		t.Fatalf("wrong metadata: %+v", item.Meta)
	}
	if !r.valid(task) {
		t.Fatal("valid task rejected")
	}
	task.IP = "8.8.8.8"
	if r.valid(task) {
		t.Fatal("out of scope task accepted")
	}
}
func TestCaptureQueueNeverBlocksAndCountsDrops(t *testing.T) {
	r := New(configForTest(t))
	a := &active{ip: netip.MustParseAddr("203.0.113.10"), snaplen: 64, end: time.Now().Add(time.Minute), frames: make(chan frame, 2)}
	r.active = a
	r.recording.Store(true)
	for i := 0; i < 10; i++ {
		r.Packet(ipv4("203.0.113.10", "1.1.1.1"), 100, "eno1", time.Now())
	}
	if len(a.frames) != 2 || a.drops.Load() != 8 {
		t.Fatal("queue is not bounded")
	}
}

func TestCapturePacketLengthAndFileBudgetAreIndependent(t *testing.T) {
	for _, snaplen := range []int{256, 512, 2048, 65535} {
		t.Run(fmt.Sprint(snaplen), func(t *testing.T) {
			c := configForTest(t)
			r := New(c)
			task := testTask()
			task.Snaplen = snaplen
			packet := append(ipv4("203.0.113.10", "1.1.1.1"), make([]byte, 4000)...)
			storedLength := min(len(packet), snaplen)
			task.MaxBytes = int64(24 + 16 + storedLength)
			done := make(chan error, 1)
			go func() { done <- r.record(context.Background(), task) }()
			deadline := time.Now().Add(time.Second)
			for !r.recording.Load() {
				if time.Now().After(deadline) {
					t.Fatal("capture did not start")
				}
				time.Sleep(time.Millisecond)
			}
			r.Packet(packet, len(packet), "eno1", time.Now())
			r.Packet(packet, len(packet), "eno1", time.Now())
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			pcap, err := os.ReadFile(filepath.Join(c.DataDir, "evidence", task.ID+".pcap"))
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(pcap)) != task.MaxBytes || binary.LittleEndian.Uint32(pcap[16:]) != uint32(snaplen) || binary.LittleEndian.Uint32(pcap[32:]) != uint32(storedLength) || binary.LittleEndian.Uint32(pcap[36:]) != uint32(len(packet)) {
				t.Fatal("packet truncation or file budget was not respected")
			}
			metadata, _ := os.ReadFile(filepath.Join(c.DataDir, "evidence", task.ID+".json"))
			var item saved
			if err := json.Unmarshal(metadata, &item); err != nil {
				t.Fatal(err)
			}
			if item.Meta.Stop != "size" || item.Meta.Packets != 1 || (item.Meta.Truncated == 1) != (snaplen < len(packet)) {
				t.Fatalf("wrong stop or truncation metadata: %+v", item.Meta)
			}
		})
	}
}
func TestUploadUsesNodeLeaseAndNeverFollowsRedirects(t *testing.T) {
	c := configForTest(t)
	task := testTask()
	item := saved{Task: task, Meta: Metadata{Packets: 1, Started: time.Now(), Ended: time.Now(), Stop: "duration", Interfaces: c.Interfaces}}
	path := filepath.Join(c.DataDir, "evidence", task.ID+".json")
	writeJSON(path, item)
	os.WriteFile(filepath.Join(c.DataDir, "evidence", task.ID+".pcap"), make([]byte, 24), 0600)
	called := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		called++
		if q.Header.Get("Authorization") != "Bearer test-token" || q.Header.Get("X-Capture-Lease") != task.Lease || q.Header.Get("X-Node-ID") != c.NodeID {
			t.Error("missing upload authentication")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	c.ServerURL = server.URL
	r := New(c)
	r.sendPending(context.Background())
	r.sendPending(context.Background())
	if called != 1 {
		t.Fatal("uploaded twice")
	}
}
func TestEvidenceSpaceDoesNotConsumeSpoolReservation(t *testing.T) {
	c := configForTest(t)
	c.DiskLimitMiB = 640
	r := New(c)
	if r.record(context.Background(), testTask()) == nil {
		t.Fatal("spool reservation was consumed")
	}
}
