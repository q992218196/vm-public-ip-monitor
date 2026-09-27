package engine

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
	"vm-monitor/agent/internal/config"
)

func cfg() config.Config {
	return config.Config{CIDRs: []string{"203.0.113.0/24", "2001:db8::/48"}, MaxIPs: 10, MaxFlows: 1000, MaxReassembly: 10, MaxSites: 20}
}
func frame(src, dst string, sp, dp uint16, seq uint32, flags byte, payload string) []byte {
	a, b := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	iplen := 20
	if a.Is6() {
		iplen = 40
	}
	p := make([]byte, 14+iplen+20+len(payload))
	if a.Is6() {
		binary.BigEndian.PutUint16(p[12:14], 0x86dd)
		p[14] = 0x60
		binary.BigEndian.PutUint16(p[18:20], uint16(20+len(payload)))
		p[20] = 6
		copy(p[22:38], a.AsSlice())
		copy(p[38:54], b.AsSlice())
	} else {
		binary.BigEndian.PutUint16(p[12:14], 0x0800)
		p[14] = 0x45
		binary.BigEndian.PutUint16(p[16:18], uint16(iplen+20+len(payload)))
		p[23] = 6
		copy(p[26:30], a.AsSlice())
		copy(p[30:34], b.AsSlice())
	}
	off := 14 + iplen
	binary.BigEndian.PutUint16(p[off:off+2], sp)
	binary.BigEndian.PutUint16(p[off+2:off+4], dp)
	binary.BigEndian.PutUint32(p[off+4:off+8], seq)
	p[off+12] = 0x50
	p[off+13] = flags
	copy(p[off+20:], payload)
	return p
}
func TestAttemptsAndCrossInterfaceDuplicates(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	p := frame("203.0.113.1", "1.1.1.1", 30000, 22, 10, 2, "")
	e.Process(p, len(p), "a", now)
	e.Process(p, len(p), "b", now)
	e.Process(p, len(p), "a", now.Add(time.Second))
	b := e.Snapshot(now.Add(30 * time.Second))
	if len(b.Metrics) != 1 || b.Metrics[0].TCPAttempts != 1 || b.Metrics[0].PacketsOut != 2 || b.Health.DuplicatePackets != 1 {
		t.Fatalf("unexpected %+v", b)
	}
}
func TestIncomingOnlyAndNonstandardPortReassembly(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	first := "GET / HTTP/1.1\r\nHo"
	second := "st: Example.COM:18080\r\n\r\n"
	for _, x := range []struct {
		seq uint32
		p   string
	}{{1, first}, {uint32(1 + len(first)), second}} {
		p := frame("1.1.1.1", "203.0.113.1", 50000, 18080, x.seq, 16, x.p)
		e.Process(p, len(p), "a", now)
	}
	outbound := frame("203.0.113.1", "1.1.1.1", 51000, 80, 1, 16, "GET / HTTP/1.1\r\nHost: visited.example\r\n\r\n")
	e.Process(outbound, len(outbound), "a", now)
	b := e.Snapshot(now.Add(30 * time.Second))
	if len(b.Sites) != 1 || b.Sites[0].Host != "example.com" || b.Sites[0].Port != 18080 {
		t.Fatalf("%+v", b.Sites)
	}
}
func TestIPv6AndStateCap(t *testing.T) {
	now := time.Now()
	c := cfg()
	c.MaxIPs = 1
	e := New(c, now)
	for _, ip := range []string{"2001:db8::1", "2001:db8::2"} {
		p := frame(ip, "2606:4700::1111", 40000, 443, 1, 2, "")
		e.Process(p, len(p), "a", now)
	}
	b := e.Snapshot(now.Add(time.Second))
	if len(b.Metrics) != 1 || b.Metrics[0].IP != "2001:db8::1" || b.Health.StateDropped == 0 {
		t.Fatalf("%+v", b)
	}
}
func TestScanCountsDistinctPortsWithoutSYNACK(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	for port := uint16(1); port <= 60; port++ {
		p := frame("203.0.113.1", "1.1.1.1", 40000+port, port, 1, 2, "")
		e.Process(p, len(p), "a", now)
	}
	p := frame("203.0.113.1", "1.1.1.1", 22, 55000, 1, 18, "")
	e.Process(p, len(p), "a", now)
	b := e.Snapshot(now.Add(time.Second))
	m := b.Metrics[0]
	if m.TCPAttempts != 60 || m.MaxPortsPerTarget != 60 || m.UniqueTargets != 1 {
		t.Fatalf("%+v", m)
	}
	if len(m.Ports) != 60 || m.Ports[0] != 1 || m.Ports[59] != 60 || len(m.TargetEndpoints) != 32 || !m.EndpointSamplesTruncated || m.PortSamplesTruncated {
		t.Fatalf("missing bounded port evidence: %+v", m)
	}
}
func TestPortEvidenceIsBounded(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	for port := uint16(1); port <= 70; port++ {
		p := frame("203.0.113.1", "1.1.1.1", 40000+port, port, 1, 2, "")
		e.Process(p, len(p), "a", now)
	}
	m := e.Snapshot(now.Add(time.Second)).Metrics[0]
	if len(m.Ports) != 64 || m.Ports[0] != 1 || m.Ports[63] != 64 || !m.PortSamplesTruncated {
		t.Fatalf("unexpected port sample: %+v", m)
	}
}
func TestOutOfOrderStreamIsNotInvented(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	for _, x := range []struct {
		seq uint32
		p   string
	}{{1, "GET / HTTP/1.1\r\n"}, {99, "Host: fake.example\r\n\r\n"}} {
		p := frame("1.1.1.1", "203.0.113.1", 50000, 80, x.seq, 16, x.p)
		e.Process(p, len(p), "a", now)
	}
	b := e.Snapshot(now.Add(time.Second))
	if len(b.Sites) != 0 || b.Health.ReassemblyDropped != 1 {
		t.Fatalf("%+v", b)
	}
}

func TestFloodKeepsStateBounded(t *testing.T) {
	now := time.Now()
	c := cfg()
	c.MaxFlows = 100
	c.MaxReassembly = 2
	c.MaxIPs = 2
	e := New(c, now)
	for i := 0; i < 10000; i++ {
		p := frame("203.0.113.1", "1.1.1.1", uint16(1000+i), uint16(1+i%500), 1, 2, "")
		e.Process(p, len(p), "a", now)
	}
	if len(e.syns) > c.MaxFlows || len(e.ips) > c.MaxIPs || len(e.streams) > c.MaxReassembly {
		t.Fatal("state cap exceeded")
	}
	b := e.Snapshot(now.Add(30 * time.Second))
	if b.Health.StateDropped == 0 {
		t.Fatal("state loss must be visible")
	}
}
