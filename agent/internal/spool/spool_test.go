package spool

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"vm-monitor/agent/internal/config"
	"vm-monitor/agent/internal/wire"
)

func TestAckBoundaryAndAuth(t *testing.T) {
	status := 503
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Node-ID") != "node" {
			t.Error("missing auth")
		}
		w.WriteHeader(status)
		fmt.Fprint(w, `{"accepted":true}`)
	}))
	defer server.Close()
	s, _ := New(config.Config{DataDir: t.TempDir(), SpoolLimitMiB: 1, DiskLimitMiB: 2, ServerURL: server.URL, Token: "secret", NodeID: "node"})
	if e := s.Put(wire.Batch{ID: "a"}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.SendOne(context.Background()); e == nil {
		t.Fatal("expected failure")
	}
	if n, _ := s.Status(); n == 0 {
		t.Fatal("unacked batch deleted")
	}
	status = 200
	if ok, e := s.SendOne(context.Background()); !ok || e != nil {
		t.Fatal(e)
	}
	if n, _ := s.Status(); n != 0 {
		t.Fatal("acked batch retained")
	}
}
func TestDiskBudgetAndEvictionReported(t *testing.T) {
	root := t.TempDir()
	s, _ := New(config.Config{DataDir: root, SpoolLimitMiB: 1, DiskLimitMiB: 2})
	for i := 0; i < 5; i++ {
		if e := s.Put(wire.Batch{ID: fmt.Sprint(i), WindowStart: strings.Repeat("x", 400000)}); e != nil {
			t.Fatal(e)
		}
	}
	used, lost := s.Status()
	if used > 1048576 || lost == 0 {
		t.Fatalf("%d %d", used, lost)
	}
	os.WriteFile(filepath.Join(root, "other"), make([]byte, 2*1048576), 0600)
	if e := s.Put(wire.Batch{ID: "overflow"}); e == nil {
		t.Fatal("must respect total directory budget")
	}
}

func TestPermanentRejectionDoesNotBlockQueue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		fmt.Fprint(w, `{"message":"The given data was invalid.","errors":{"metrics.0.ip":["Address is outside this node's CIDRs."]}}`)
	}))
	defer server.Close()
	s, _ := New(config.Config{DataDir: t.TempDir(), SpoolLimitMiB: 1, DiskLimitMiB: 2, ServerURL: server.URL})
	s.Put(wire.Batch{ID: "bad"})
	if _, e := s.SendOne(context.Background()); e == nil || !strings.Contains(e.Error(), "metrics.0.ip: Address is outside this node's CIDRs.") {
		t.Fatalf("expected bounded validation reason, got %v", e)
	}
	used, dropped := s.Status()
	if used != 0 || dropped != 1 {
		t.Fatalf("%d %d", used, dropped)
	}
}

func TestRetryableRejectionShowsReasonAndRetainsBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		fmt.Fprint(w, `{"message":"Node inbox is full; wait for processing."}`)
	}))
	defer server.Close()
	s, _ := New(config.Config{DataDir: t.TempDir(), SpoolLimitMiB: 1, DiskLimitMiB: 2, ServerURL: server.URL})
	s.Put(wire.Batch{ID: "retry"})
	if _, err := s.SendOne(context.Background()); err == nil || !strings.Contains(err.Error(), "Node inbox is full; wait for processing.") {
		t.Fatalf("expected retryable reason, got %v", err)
	}
	if used, dropped := s.Status(); used == 0 || dropped != 0 {
		t.Fatalf("retryable batch was lost: used=%d dropped=%d", used, dropped)
	}
}

func TestNormalTrafficCannotEvictPriorityEvidence(t *testing.T) {
	s, _ := New(config.Config{DataDir: t.TempDir(), SpoolLimitMiB: 1, DiskLimitMiB: 2})
	if err := s.Put(wire.Batch{ID: "priority", WindowStart: strings.Repeat("x", 400000), Sites: []wire.Site{{IP: "203.0.113.1", Port: 80}}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		s.Put(wire.Batch{ID: fmt.Sprint(i), WindowStart: strings.Repeat("x", 400000)})
	}
	files, _ := filepath.Glob(filepath.Join(s.c.DataDir, "spool", "0-*.json"))
	if len(files) != 1 {
		t.Fatal("priority evidence evicted by normal batch")
	}
}
