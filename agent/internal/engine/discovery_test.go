package engine

import (
	"testing"
	"time"
)

func TestRDPFlowDoesNotTurnSubsequentTLSIntoWebsite(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	rdp := []byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0}
	e.Process(frame("198.51.100.1", "203.0.113.1", 40000, 3389, 1, 24, string(rdp)), 100, "eth0", now)
	// A valid no-extension TLS hello, from the same RDP client.
	body := make([]byte, 34)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	h := append([]byte{22, 3, 1, 0, byte(len(body) + 4), 1, 0, 0, byte(len(body))}, body...)
	e.Process(frame("198.51.100.1", "203.0.113.1", 40000, 3389, 20, 24, string(h)), 100, "eth0", now.Add(time.Second))
	b := e.Snapshot(now.Add(2 * time.Second))
	if len(b.Sites) != 1 || b.Sites[0].Source != "rdp_negotiation" {
		t.Fatalf("%+v", b.Sites)
	}
	e.Process(frame("198.51.100.1", "203.0.113.1", 40000, 3389, 100, 2, ""), 100, "eth0", now.Add(3*time.Second))
	e.Process(frame("198.51.100.1", "203.0.113.1", 40000, 3389, 101, 24, string(h)), 100, "eth0", now.Add(4*time.Second))
	b = e.Snapshot(now.Add(5 * time.Second))
	if len(b.Sites) != 1 || b.Sites[0].Source != "tls_sni" {
		t.Fatal("reused tuple inherits RDP")
	}
	e.rdpFlows[flowKey{}] = now
	e.Sweep(now.Add(time.Minute))
	if len(e.rdpFlows) != 0 {
		t.Fatal("RDP cache not expired")
	}
}
