package engine

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"
	"vm-monitor/agent/internal/config"
)

func TestProxySuspicionNeedsBidirectionalPeersAndEgressFanout(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	clientPayload := make([]byte, 700)
	for i := range clientPayload {
		clientPayload[i] = byte(i)
	}
	serverPayload := string(make([]byte, 700))
	for i := 1; i <= 3; i++ {
		peer := fmt.Sprintf("198.51.100.%d", i)
		syn := frame(peer, "203.0.113.1", uint16(40000+i), 8443, 1, 2, "")
		e.Process(syn, len(syn), "a", now)
		for chunk := 0; chunk < 2; chunk++ {
			client := frame(peer, "203.0.113.1", uint16(40000+i), 8443, uint32(2+chunk*700), 24, string(clientPayload))
			server := frame("203.0.113.1", peer, 8443, uint16(40000+i), uint32(2+chunk*700), 24, serverPayload)
			e.Process(client, len(client), "a", now.Add(time.Duration(chunk+1)*time.Second))
			e.Process(server, len(server), "a", now.Add(time.Duration(chunk+4)*time.Second))
		}
	}
	if got := e.Snapshot(now.Add(10 * time.Second)).Proxies; len(got) != 0 {
		t.Fatalf("without independent outbound targets this is not a proxy clue: %+v", got)
	}
	for i := 1; i <= 3; i++ {
		peer := fmt.Sprintf("198.51.100.%d", i)
		syn := frame(peer, "203.0.113.1", uint16(41000+i), 8443, 1, 2, "")
		e.Process(syn, len(syn), "a", now.Add(11*time.Second))
		for chunk := 0; chunk < 2; chunk++ {
			client := frame(peer, "203.0.113.1", uint16(41000+i), 8443, uint32(2+chunk*700), 24, string(clientPayload))
			server := frame("203.0.113.1", peer, 8443, uint16(41000+i), uint32(2+chunk*700), 24, serverPayload)
			e.Process(client, len(client), "a", now.Add(time.Duration(12+chunk)*time.Second))
			e.Process(server, len(server), "a", now.Add(time.Duration(15+chunk)*time.Second))
		}
	}
	for i := 1; i <= 5; i++ {
		target := fmt.Sprintf("192.0.2.%d", i)
		outbound := frame("203.0.113.1", target, uint16(50000+i), 443, 1, 2, "")
		e.Process(outbound, len(outbound), "a", now.Add(17*time.Second))
	}
	got := e.Snapshot(now.Add(30 * time.Second)).Proxies
	if len(got) != 1 || got[0].Transport != "opaque_tcp" || got[0].PeerCount != 3 || got[0].EgressTargetCount != 5 || got[0].LocalPort != 8443 {
		t.Fatalf("unexpected bounded proxy clue: %+v", got)
	}
}

func cfg() config.Config {
	return config.Config{CIDRs: []string{"203.0.113.0/24", "2001:db8::/48"}, MaxIPs: 10, MaxFlows: 1000, MaxReassembly: 10, MaxSites: 20}
}
func TestUDPEndpointStateAndUploadSamplesStayBounded(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	for i := 1; i <= 100; i++ {
		p := udpFrame("203.0.113.1", fmt.Sprintf("192.0.2.%d", i), 40000, 53, nil)
		e.Process(p, len(p), "a", now)
	}
	if len(e.ips[netip.MustParseAddr("203.0.113.1")].udpEndpoints) != 64 {
		t.Fatal("UDP endpoint state exceeded bound")
	}
	m := e.Snapshot(now.Add(30 * time.Second)).Metrics[0]
	if m.UDPFlowsOut != 100 || m.UDPPacketsOut != 100 || len(m.UDPEndpoints) != 8 || !m.UDPEndpointsTruncated || m.UDPFlowsCapped {
		t.Fatalf("unexpected bounded UDP evidence: %+v", m)
	}
}
func TestPairedHandshakeResetsAndMatureNoReplyAreWindowBounded(t *testing.T) {
	for _, addresses := range [][2]string{{"203.0.113.1", "192.0.2.1"}, {"2001:db8::1", "2001:db9::1"}} {
		now := time.Now()
		e := New(cfg(), now)
		vm, peer := addresses[0], addresses[1]
		send := func(src, dst string, sp, dp uint16, seq, ack uint32, flags byte, second int) {
			p := frame(src, dst, sp, dp, seq, flags, "")
			off := 34
			if netip.MustParseAddr(src).Is6() {
				off = 54
			}
			binary.BigEndian.PutUint32(p[off+8:off+12], ack)
			e.Process(p, len(p), "a", now.Add(time.Duration(second)*time.Second))
		}
		send(vm, peer, 40000, 443, 100, 0, 2, 0)
		send(peer, vm, 443, 40000, 200, 999, 18, 1)
		send(peer, vm, 443, 40000, 200, 101, 18, 2)
		send(vm, peer, 40000, 443, 101, 999, 16, 3)
		send(vm, peer, 40000, 443, 101, 201, 16, 4)
		send(vm, peer, 40000, 443, 101, 201, 16, 5)
		send(peer, vm, 443, 40000, 201, 101, 20, 6)
		send(peer, vm, 443, 40000, 201, 101, 20, 7)
		send(vm, peer, 40001, 22, 300, 0, 2, 0)
		send(vm, peer, 40002, 22, 400, 0, 2, 9)
		m := e.Snapshot(now.Add(10 * time.Second)).Metrics[0]
		if m.TCPAttempts != 3 || m.SYNACKReplies != 1 || m.CompletedHandshakes != 1 || m.RSTReplies != 1 || m.MatureAttempts != 2 || m.MatureNoReply != 1 {
			t.Fatalf("invalid cohort counters: %+v", m)
		}
		for _, ep := range m.OutboundEndpoints {
			if ep.PeerPort == 443 && (ep.MaxObservedSpanMS != 7000 || ep.CompletedHandshakes != 1 || ep.RSTReplies != 1) {
				t.Fatalf("invalid endpoint: %+v", ep)
			}
		}
		send(peer, vm, 22, 40001, 500, 301, 18, 11)
		send(vm, peer, 40001, 22, 301, 501, 16, 12)
		next := e.Snapshot(now.Add(13 * time.Second)).Metrics[0]
		if next.TCPAttempts != 0 || next.SYNACKReplies != 0 || next.CompletedHandshakes != 0 || next.MatureAttempts != 0 {
			t.Fatalf("cross-window counters inflated: %+v", next)
		}
	}
}
func TestPortTargetSamplePrioritizesLargestFanout(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	for i := 1; i <= 12; i++ {
		for port := 1; port <= i; port++ {
			p := frame("203.0.113.1", fmt.Sprintf("192.0.2.%d", i), uint16(40000+port), uint16(port), 1, 2, "")
			e.Process(p, len(p), "a", now)
		}
	}
	m := e.Snapshot(now.Add(30 * time.Second)).Metrics[0]
	if len(m.PortScanTargets) != 8 || m.PortScanTargets[0].PeerIP != "192.0.2.12" || m.PortScanTargets[0].PortCount != 12 {
		t.Fatalf("wrong port target samples: %+v", m.PortScanTargets)
	}
}
func BenchmarkTrackedConnections500IPs(b *testing.B) {
	c := cfg()
	c.CIDRs = []string{"203.0.0.0/16"}
	c.MaxIPs = 600
	c.MaxFlows = 2000
	now := time.Now()
	e := New(c, now)
	packets := make([][]byte, 500)
	for i := range packets {
		vm := fmt.Sprintf("203.0.%d.%d", i/250+1, i%250+1)
		p := frame(vm, "192.0.2.1", 40000, 443, 1, 2, "")
		e.Process(p, len(p), "a", now)
		packets[i] = frame(vm, "192.0.2.1", 40000, 443, 2, 16, "")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := packets[i%500]
		e.Process(p, len(p), "a", now.Add(time.Second))
	}
}
func TestOutboundEvidenceIsBoundedAndNotHostedWebsite(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	for i := 1; i <= 10; i++ {
		peer := fmt.Sprintf("192.0.2.%d", i)
		sp := uint16(40000 + i)
		for _, p := range [][]byte{
			frame("203.0.113.1", peer, sp, 8080, 1, 2, ""),
			frame(peer, "203.0.113.1", 8080, sp, 1, 18, ""),
			frame("203.0.113.1", peer, sp, 8080, 2, 24, "GET /api/check?token=SECRET&id=123 HTTP/1.1\r\nHost: example.com\r\nCookie: private=SECRET\r\n\r\n"),
			frame(peer, "203.0.113.1", 8080, sp, 2, 24, "HTTP/1.1 200 OK\r\n\r\nhello"),
		} {
			e.Process(p, len(p), "a", now)
		}
	}
	b := e.Snapshot(now.Add(30 * time.Second))
	m := b.Metrics[0]
	if len(b.Sites) != 0 || len(m.OutboundEndpoints) != 8 || !m.OutboundSamplesTruncated {
		t.Fatalf("incorrect scope or bounds: %+v", b)
	}
	first := m.OutboundEndpoints[0]
	if first.Attempts != 1 || first.SYNACKReplies != 1 || first.PayloadIn == 0 || first.HTTPPath != "/api/check" || first.Host != "example.com" || len(first.QueryKeys) != 2 {
		t.Fatalf("incorrect connection evidence: %+v", first)
	}
}
func TestCrossWindowReplyDoesNotInflateCurrentHandshakeRatio(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	p := frame("203.0.113.1", "192.0.2.1", 40000, 443, 1, 2, "")
	e.Process(p, len(p), "a", now)
	e.Snapshot(now.Add(time.Second))
	p = frame("192.0.2.1", "203.0.113.1", 443, 40000, 1, 18, "")
	e.Process(p, len(p), "a", now.Add(2*time.Second))
	m := e.Snapshot(now.Add(3 * time.Second)).Metrics[0]
	if m.TCPAttempts != 0 || m.SYNACKReplies != 0 {
		t.Fatalf("cross-window reply must not count as paired: %+v", m)
	}
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
	if flags&16 != 0 {
		binary.BigEndian.PutUint32(p[off+8:off+12], 2)
	}
	p[off+12] = 0x50
	p[off+13] = flags
	copy(p[off+20:], payload)
	return p
}
func udpFrame(src, dst string, sp, dp uint16, payload []byte) []byte {
	a, b := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	ipLength := 20
	if a.Is6() {
		ipLength = 40
	}
	p := make([]byte, 14+ipLength+8+len(payload))
	if a.Is6() {
		binary.BigEndian.PutUint16(p[12:14], 0x86dd)
		p[14] = 0x60
		binary.BigEndian.PutUint16(p[18:20], uint16(8+len(payload)))
		p[20] = 17
		copy(p[22:38], a.AsSlice())
		copy(p[38:54], b.AsSlice())
	} else {
		binary.BigEndian.PutUint16(p[12:14], 0x0800)
		p[14] = 0x45
		binary.BigEndian.PutUint16(p[16:18], uint16(20+8+len(payload)))
		p[23] = 17
		copy(p[26:30], a.AsSlice())
		copy(p[30:34], b.AsSlice())
	}
	offset := 14 + ipLength
	binary.BigEndian.PutUint16(p[offset:offset+2], sp)
	binary.BigEndian.PutUint16(p[offset+2:offset+4], dp)
	binary.BigEndian.PutUint16(p[offset+4:offset+6], uint16(8+len(payload)))
	copy(p[offset+8:], payload)
	return p
}
func TestUDPCountsTuplesPacketsDirectionsAndWindowReset(t *testing.T) {
	for _, addresses := range [][2]string{{"203.0.113.1", "192.0.2.1"}, {"2001:db8::1", "2001:db9::1"}} {
		now := time.Now()
		e := New(cfg(), now)
		vm, peer := addresses[0], addresses[1]
		send := func(src, dst string, sp, dp uint16, iface string) {
			p := udpFrame(src, dst, sp, dp, []byte("test"))
			e.Process(p, len(p), iface, now)
		}
		send(vm, peer, 40000, 53, "a")
		send(vm, peer, 40000, 53, "b")
		send(vm, peer, 40000, 53, "a")
		send(vm, peer, 40001, 53, "a")
		send(peer, vm, 53, 40000, "a")
		result := e.Snapshot(now.Add(30 * time.Second))
		m := result.Metrics[0]
		if m.UDPStatsVersion != 1 || m.UDPFlowsOut != 2 || m.UDPPacketsOut != 3 || m.UDPPacketsIn != 1 || len(m.UDPEndpoints) != 1 || m.UDPEndpoints[0].Flows != 2 || result.Health.DuplicatePackets != 1 || m.TCPAttempts != 0 {
			t.Fatalf("UDP evidence: %+v, health %+v", m, result.Health)
		}
		now = now.Add(31 * time.Second)
		send(vm, peer, 40000, 53, "a")
		m = e.Snapshot(now.Add(30 * time.Second)).Metrics[0]
		if m.UDPFlowsOut != 1 || m.UDPPacketsOut != 1 || m.UDPPacketsIn != 0 {
			t.Fatalf("window not reset: %+v", m)
		}
	}
}
func TestUDPStateCapDoesNotStopPacketCountingOrConsumeTCPStates(t *testing.T) {
	now := time.Now()
	c := cfg()
	c.MaxFlows = 2
	e := New(c, now)
	for i := 0; i < 4; i++ {
		p := udpFrame("203.0.113.1", "192.0.2.1", uint16(40000+i), 53, nil)
		e.Process(p, len(p), "a", now)
	}
	tcp := frame("203.0.113.1", "192.0.2.1", 50000, 22, 100, 2, "")
	e.Process(tcp, len(tcp), "a", now)
	m := e.Snapshot(now.Add(30 * time.Second)).Metrics[0]
	if m.UDPFlowsOut != 2 || !m.UDPFlowsCapped || m.UDPPacketsOut != 4 || m.TCPAttempts != 1 {
		t.Fatalf("UDP cap interferes with counting/TCP: %+v", m)
	}
}
func TestUDPRulesExcludeDestination53OnlyAndReset(t *testing.T) {
	for _, addresses := range [][2]string{{"203.0.113.1", "192.0.2.1"}, {"2001:db8::1", "2001:db9::1"}} {
		now := time.Now()
		e := New(cfg(), now)
		send := func(sp, dp uint16, iface string) {
			p := udpFrame(addresses[0], addresses[1], sp, dp, []byte("test"))
			e.Process(p, len(p), iface, now)
		}
		send(40000, 53, "a")
		send(40000, 53, "a")
		send(40001, 53, "a")
		send(40000, 443, "a")
		send(40000, 443, "b") // Duplicate seen on another interface.
		send(40000, 443, "a")
		send(53, 40002, "a") // A DNS server reply is not a destination-53 query.
		m := e.Snapshot(now.Add(30 * time.Second)).Metrics[0]
		if m.UDPFilterVersion != 1 || m.UDPFlowsOut != 4 || m.UDPPacketsOut != 6 || m.UDPNonDNSFlowsOut != 2 || m.UDPNonDNSPacketsOut != 3 || len(m.UDPNonDNSEndpoints) != 2 {
			t.Fatalf("destination-53 filter/dedup: %+v", m)
		}
		for _, endpoint := range m.UDPNonDNSEndpoints {
			if endpoint.PeerPort == 53 {
				t.Fatal("DNS query leaked into rule evidence")
			}
		}
		now = now.Add(31 * time.Second)
		send(40000, 53, "a")
		m = e.Snapshot(now.Add(30 * time.Second)).Metrics[0]
		if m.UDPNonDNSFlowsOut != 0 || m.UDPNonDNSPacketsOut != 0 || len(m.UDPNonDNSEndpoints) != 0 || m.UDPPacketsOut != 1 {
			t.Fatalf("filtered counters did not reset: %+v", m)
		}
	}
}

func TestUDPDNSCapDoesNotHideNonDNSPacketRate(t *testing.T) {
	now := time.Now()
	c := cfg()
	c.MaxFlows = 1
	e := New(c, now)
	for _, port := range []uint16{53, 443, 443} {
		p := udpFrame("203.0.113.1", "192.0.2.1", 40000, port, nil)
		e.Process(p, len(p), "a", now)
	}
	m := e.Snapshot(now.Add(30 * time.Second)).Metrics[0]
	if !m.UDPFlowsCapped || m.UDPNonDNSFlowsOut != 0 || m.UDPNonDNSPacketsOut != 2 || m.UDPPacketsOut != 3 {
		t.Fatalf("capped flows must remain a lower bound; packet rate must continue: %+v", m)
	}
}
func TestUDPNonDNSEvidenceSurvivesDNSHeavyTopSamples(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	for i := 1; i <= 10; i++ {
		peer := fmt.Sprintf("192.0.2.%d", i)
		p := udpFrame("203.0.113.1", peer, 40000, 53, nil)
		for j := 0; j < 3; j++ {
			e.Process(p, len(p), "a", now)
		}
	}
	p := udpFrame("203.0.113.1", "192.0.2.100", 40000, 443, nil)
	e.Process(p, len(p), "a", now)
	m := e.Snapshot(now.Add(30 * time.Second)).Metrics[0]
	if len(m.UDPEndpoints) != 8 || len(m.UDPNonDNSEndpoints) != 1 || m.UDPNonDNSEndpoints[0].PeerPort != 443 || m.UDPNonDNSFlowsOut != 1 || m.UDPNonDNSPacketsOut != 1 {
		t.Fatalf("raw DNS top samples must not hide filtered evidence: %+v", m)
	}
}
func TestVPNRequiresMatchingBidirectionalHandshake(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	req := make([]byte, 148)
	req[0] = 1
	binary.LittleEndian.PutUint32(req[4:8], 123)
	reqPacket := udpFrame("203.0.113.1", "1.1.1.1", 40000, 51820, req)
	e.Process(reqPacket, len(reqPacket), "a", now)
	if got := e.Snapshot(now.Add(time.Second)).VPN; len(got) != 0 {
		t.Fatalf("one-way probe must not be reported: %+v", got)
	}
	e.Process(reqPacket, len(reqPacket), "a", now.Add(2*time.Second))
	response := make([]byte, 92)
	response[0] = 2
	binary.LittleEndian.PutUint32(response[4:8], 456)
	binary.LittleEndian.PutUint32(response[8:12], 123)
	responsePacket := udpFrame("1.1.1.1", "203.0.113.1", 51820, 40000, response)
	e.Process(responsePacket, len(responsePacket), "a", now.Add(3*time.Second))
	got := e.Snapshot(now.Add(30 * time.Second)).VPN
	if len(got) != 1 || got[0].Protocol != "wireguard" || got[0].PeerIP != "1.1.1.1" || got[0].PeerPort != 51820 || got[0].Initiator != "vm" {
		t.Fatalf("unexpected VPN evidence: %+v", got)
	}
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
func TestSYNACKReplyCountsOnlyMatchingOutboundAttemptOnce(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	syn := frame("203.0.113.1", "198.51.100.2", 40001, 31402, 1, 2, "")
	reply := frame("198.51.100.2", "203.0.113.1", 31402, 40001, 1, 18, "")
	unmatched := frame("198.51.100.3", "203.0.113.1", 31402, 40002, 1, 18, "")
	for _, p := range [][]byte{syn, reply, reply, unmatched} {
		e.Process(p, len(p), "a", now)
	}
	m := e.Snapshot(now.Add(time.Second)).Metrics[0]
	if m.TCPAttempts != 1 || m.SYNACKReplies != 1 {
		t.Fatalf("unexpected SYN-ACK evidence: %+v", m)
	}
}
func TestPortEvidenceIsBounded(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	for port := uint16(1); port <= 150; port++ {
		p := frame("203.0.113.1", "1.1.1.1", 40000+port, port, 1, 2, "")
		e.Process(p, len(p), "a", now)
	}
	m := e.Snapshot(now.Add(time.Second)).Metrics[0]
	if len(m.Ports) != 150 || m.Ports[0] != 1 || m.Ports[149] != 150 || m.PortSamplesTruncated || len(m.PortScanTargets[0].Ports) != 128 || !m.PortScanTargets[0].Truncated {
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

func TestCompleteBusinessPortProfileAboveOldSampleLimits(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	for i := 0; i < 90; i++ {
		p := frame("203.0.113.1", "198.51.100.2", uint16(40000+i), uint16(11000+i), 1, 2, "")
		e.Process(p, len(p), "a", now)
	}
	m := e.Snapshot(now.Add(30 * time.Second)).Metrics[0]
	if len(m.Ports) != 90 || m.PortSamplesTruncated || len(m.PortScanTargets) != 1 || len(m.PortScanTargets[0].Ports) != 90 || m.PortScanTargets[0].Truncated {
		t.Fatalf("approved business port profile must be complete above previous 32/64 sample limits: %+v", m)
	}
}
