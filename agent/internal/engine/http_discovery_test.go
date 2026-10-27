package engine

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func httpDiscoveryFrame(src, dst string, sp, dp uint16, seq, ack uint32, flags byte, payload string) []byte {
	p := frame(src, dst, sp, dp, seq, flags, payload)
	off := 14 + 20
	if netip.MustParseAddr(src).Is6() {
		off = 14 + 40
	}
	binary.BigEndian.PutUint32(p[off+8:off+12], ack)
	return p
}

func TestIncomingHTTPRequiresMatchingServerResponseOnEveryPort(t *testing.T) {
	for _, port := range []uint16{22, 80, 18080} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			now := time.Now()
			e := New(cfg(), now)
			request := "GET / HTTP/1.1\r\nHost: customer.example\r\n\r\n"
			p := httpDiscoveryFrame("198.51.100.1", "203.0.113.1", 40000, port, 100, 1000, 24, request)
			e.Process(p, len(p), "eno1", now)
			if len(e.Snapshot(now.Add(time.Second)).Sites) != 0 {
				t.Fatal("request-only observations must not create websites")
			}
			st := e.streams[flowKey{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("203.0.113.1"), 40000, port}]
			if st == nil || !st.httpPending || len(st.buf) != 0 {
				t.Fatal("waiting state must not retain request headers or body")
			}
			response := httpDiscoveryFrame("203.0.113.1", "198.51.100.1", port, 40000, 1000, uint32(100+len(request)), 24, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"+strings.Repeat("private-response-body", 2000))
			e.Process(response, len(response), "eno1", now.Add(2*time.Second))
			b := e.Snapshot(now.Add(3 * time.Second))
			if len(b.Sites) != 1 || b.Sites[0].Source != "http_response" || b.Sites[0].HTTPStatus != 403 || b.Sites[0].Host != "customer.example" || b.Sites[0].Port != port || len(e.streams) != 0 {
				t.Fatalf("unexpected HTTP evidence: %+v", b.Sites)
			}
		})
	}
}

func TestIncomingHTTPResponseRejectsUnpairedInvalidOrClosedConnections(t *testing.T) {
	for _, scenario := range []string{"ssh_banner", "rst", "rst_with_http", "no_reply", "wrong_peer", "wrong_port", "wrong_sequence", "wrong_ack", "missing_ack", "gap", "overlap", "new_syn", "expired", "swept", "fin_without_response", "status_too_long", "response_before_request"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now()
			e := New(cfg(), now)
			request := "GET / HTTP/1.1\r\nHost: requested.example\r\n\r\n"
			p := httpDiscoveryFrame("198.51.100.1", "203.0.113.1", 40000, 22, 100, 1000, 24, request)
			e.Process(p, len(p), "eno1", now)
			src, dst, sp, dp, seq, ack, flags, text := "203.0.113.1", "198.51.100.1", uint16(22), uint16(40000), uint32(1000), uint32(100+len(request)), byte(24), "HTTP/1.1 200 OK\r\n"
			switch scenario {
			case "ssh_banner":
				text = "SSH-2.0-OpenSSH_9.0\r\n"
			case "rst":
				flags, text = 20, ""
			case "rst_with_http":
				flags = 20
			case "no_reply":
				text = ""
			case "wrong_peer":
				dst = "198.51.100.2"
			case "wrong_port":
				sp = 80
			case "wrong_sequence":
				seq = 999
			case "wrong_ack":
				ack = 100
			case "missing_ack":
				flags = 8
			case "gap", "overlap":
				first := httpDiscoveryFrame(src, dst, sp, dp, seq, ack, flags, "HTTP/1.1 2")
				e.Process(first, len(first), "eno1", now.Add(time.Second))
				seq += uint32(len("HTTP/1.1 2"))
				if scenario == "gap" {
					seq++
				} else {
					seq--
				}
				text = "00 OK\r\n"
			case "new_syn":
				syn := httpDiscoveryFrame(dst, src, dp, sp, 5000, 0, 2, "")
				e.Process(syn, len(syn), "eno1", now.Add(time.Second))
			case "expired":
				now = now.Add(11 * time.Second)
			case "response_before_request":
				now = now.Add(-3 * time.Second)
			case "swept":
				e.Sweep(now.Add(11 * time.Second))
			case "fin_without_response":
				closed := httpDiscoveryFrame(src, dst, sp, dp, seq, ack, 17, "")
				e.Process(closed, len(closed), "eno1", now.Add(time.Second))
			case "status_too_long":
				text = "HTTP/1.1 200 " + strings.Repeat("x", 1024)
			}
			response := httpDiscoveryFrame(src, dst, sp, dp, seq, ack, flags, text)
			e.Process(response, len(response), "eno1", now.Add(2*time.Second))
			if sites := e.Snapshot(now.Add(3 * time.Second)).Sites; len(sites) != 0 {
				t.Fatalf("%s generated false HTTP evidence: %+v", scenario, sites)
			}
		})
	}
}

func TestIncomingHTTPOrphanResponsesAreNotPairedRetroactively(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	request := "GET / HTTP/1.1\r\nHost: one.example\r\n\r\n"
	response := httpDiscoveryFrame("203.0.113.1", "198.51.100.1", 80, 40000, 1000, uint32(100+len(request)), 24, "HTTP/1.1 200 OK\r\n")
	e.Process(response, len(response), "eno1", now)
	p := httpDiscoveryFrame("198.51.100.1", "203.0.113.1", 40000, 80, 100, 1000, 24, request)
	e.Process(p, len(p), "eno1", now.Add(time.Second))
	if sites := e.Snapshot(now.Add(2 * time.Second)).Sites; len(sites) != 0 {
		t.Fatalf("orphan response was paired with a later request: %+v", sites)
	}
}

func TestIncomingHTTPResponseSupportsBoundedFragmentsAndDuplicateSegments(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	request := "GET / HTTP/1.1\r\nHost: ipv6.example\r\n\r\n"
	p := httpDiscoveryFrame("2001:db8:ffff::1", "2001:db8::1", 40000, 22, 100, 1000, 24, request)
	e.Process(p, len(p), "eno1", now)
	first := httpDiscoveryFrame("2001:db8::1", "2001:db8:ffff::1", 22, 40000, 1000, uint32(100+len(request)), 24, "HTTP/1.1 2")
	for i := 0; i < 2; i++ {
		e.Process(first, len(first), "eno1", now.Add(time.Second))
	}
	if len(e.Snapshot(now.Add(2*time.Second)).Sites) != 0 {
		t.Fatal("partial status line must not create a website")
	}
	second := httpDiscoveryFrame("2001:db8::1", "2001:db8:ffff::1", 22, 40000, 1000+uint32(len("HTTP/1.1 2")), uint32(100+len(request)), 25, "00 OK\r\n\r\n")
	e.Process(second, len(second), "eno1", now.Add(3*time.Second))
	b := e.Snapshot(now.Add(4 * time.Second))
	if len(b.Sites) != 1 || b.Sites[0].HTTPStatus != 200 || b.Sites[0].Host != "ipv6.example" {
		t.Fatalf("unexpected fragment evidence: %+v", b.Sites)
	}
}

func TestWaitingHTTPRequestStateSharesReassemblyBudget(t *testing.T) {
	now := time.Now()
	c := cfg()
	c.MaxReassembly = 1
	e := New(c, now)
	for _, port := range []uint16{40000, 40001} {
		request := httpDiscoveryFrame("198.51.100.1", "203.0.113.1", port, 22, 100, 1000, 24, "GET / HTTP/1.1\r\nHost: one.example\r\n\r\n")
		e.Process(request, len(request), "eno1", now)
	}
	if len(e.streams) != 1 || e.health.ReassemblyDropped != 1 {
		t.Fatal("waiting HTTP state exceeded shared reassembly budget")
	}
	e.Sweep(now.Add(11 * time.Second))
	if len(e.streams) != 0 {
		t.Fatal("expired request state was not released")
	}
}
