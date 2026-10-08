package engine

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestServiceTargetsIgnoreRetransmissionsAndEstablishedPackets(t *testing.T) {
	for _, addresses := range [][2]string{{"203.0.113.1", "192.0.2.1"}, {"2001:db8::1", "2001:db9::1"}} {
		t.Run(addresses[0], func(t *testing.T) {
			now := time.Now()
			e := New(cfg(), now)
			vm, peer := addresses[0], addresses[1]
			send := func(src, dst string, sp, dp uint16, seq, ack uint32, flags byte, payload string, second int) {
				p := frame(src, dst, sp, dp, seq, flags, payload)
				offset := 34
				if netip.MustParseAddr(src).Is6() {
					offset = 54
				}
				binary.BigEndian.PutUint32(p[offset+8:], ack)
				e.Process(p, len(p), "a", now.Add(time.Duration(second)*time.Second))
			}
			send(vm, peer, 40000, 3389, 100, 0, 2, "", 0)
			send(vm, peer, 40000, 3389, 100, 0, 2, "", 1)
			send(peer, vm, 3389, 40000, 200, 101, 18, "", 2)
			send(vm, peer, 40000, 3389, 101, 201, 16, "", 3)
			send(vm, peer, 40000, 3389, 101, 201, 24, "established RDP data", 4)
			send(peer, vm, 3389, 40000, 201, 101, 24, "service reply", 5)
			send(peer, vm, 3389, 40000, 201, 101, 20, "", 6)
			send(vm, peer, 40001, 3389, 300, 0, 2, "", 7)
			send(peer, vm, 50000, 3389, 400, 0, 2, "", 8)
			send(vm, peer, 40002, 443, 500, 0, 2, "", 9)
			m := e.Snapshot(now.Add(30 * time.Second)).Metrics[0]
			if m.TCPAttempts != 3 || m.CompletedHandshakes != 1 || m.ServiceTargetStatsVersion != 1 || len(m.ServiceTargets) != 1 {
				t.Fatalf("invalid SYN-only service counters: %+v", m)
			}
			stats := m.ServiceTargets[0]
			if stats.Service != "rdp" || stats.Attempts != 2 || stats.TargetsCapped || !reflect.DeepEqual(stats.Targets, []string{peer}) || !reflect.DeepEqual(stats.Ports, []uint16{3389}) {
				t.Fatalf("established/inbound packets inflated service target evidence: %+v", stats)
			}
		})
	}
}

func TestServiceTargetsMergeFTPPortsAndSortIPv6Targets(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	for i, connection := range []struct {
		peer string
		port uint16
	}{
		{"2001:db9::2", 990},
		{"2001:db9::1", 21},
		{"2001:db9::2", 21},
		{"2001:db9::2", 3389},
		{"2001:db9::2", 22},
		{"2001:db9::2", 22},
	} {
		p := frame("2001:db8::1", connection.peer, uint16(40000+i), connection.port, uint32(i+1), 2, "")
		e.Process(p, len(p), "a", now)
	}
	m := e.Snapshot(now.Add(30 * time.Second)).Metrics[0]
	if len(m.ServiceTargets) != 3 || m.ServiceTargets[0].Service != "ssh" || m.ServiceTargets[1].Service != "rdp" || m.ServiceTargets[2].Service != "ftp" {
		t.Fatalf("service ordering is unstable: %+v", m.ServiceTargets)
	}
	if m.ServiceTargets[0].Attempts != 2 || len(m.ServiceTargets[0].Targets) != 1 {
		t.Fatalf("same-target SSH sessions counted as different targets: %+v", m.ServiceTargets[0])
	}
	ftp := m.ServiceTargets[2]
	if ftp.Attempts != 3 || !reflect.DeepEqual(ftp.Targets, []string{"2001:db9::1", "2001:db9::2"}) || !reflect.DeepEqual(ftp.Ports, []uint16{21, 990}) {
		t.Fatalf("FTP service ports did not share a target set: %+v", ftp)
	}
}

func TestServiceTargetsSurviveGenericEndpointCapacityAndTopEight(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	for i := 1; i <= 256; i++ {
		peer := fmt.Sprintf("2001:db9::%x", i)
		for attempt := 0; attempt < 2; attempt++ {
			p := frame("2001:db8::1", peer, uint16(40000+attempt), 443, uint32(i), 2, "")
			e.Process(p, len(p), "a", now)
		}
	}
	p := frame("2001:db8::1", "2001:db9::ffff", 50000, 3389, 100, 2, "")
	e.Process(p, len(p), "a", now)
	m := e.Snapshot(now.Add(30 * time.Second)).Metrics[0]
	if !m.OutboundSamplesTruncated || len(m.OutboundEndpoints) != 8 {
		t.Fatalf("fixture did not exercise generic endpoint clipping: %+v", m)
	}
	for _, endpoint := range m.OutboundEndpoints {
		if endpoint.PeerPort == 3389 {
			t.Fatal("RDP endpoint unexpectedly survived the generic sample")
		}
	}
	if len(m.ServiceTargets) != 1 || m.ServiceTargets[0].Service != "rdp" || m.ServiceTargets[0].Attempts != 1 || !reflect.DeepEqual(m.ServiceTargets[0].Targets, []string{"2001:db9::ffff"}) || m.ServiceTargets[0].TargetsCapped {
		t.Fatalf("service statistics were limited by unrelated endpoints: %+v", m.ServiceTargets)
	}
}

func TestServiceTargetCapacityCountsAttemptsAndResetsEachWindow(t *testing.T) {
	now := time.Now()
	e := New(cfg(), now)
	for i := 1; i <= maxServiceTargets; i++ {
		p := frame("203.0.113.1", fmt.Sprintf("192.0.2.%d", i), uint16(40000+i), 22, uint32(i), 2, "")
		e.Process(p, len(p), "a", now)
	}
	if e.ips[netip.MustParseAddr("203.0.113.1")].serviceTargets["ssh"].capped {
		t.Fatal("reaching capacity alone must not report rejected targets")
	}
	for i, peer := range []string{"192.0.2.129", "192.0.2.1"} {
		p := frame("203.0.113.1", peer, uint16(50000+i), 22, 900, 2, "")
		e.Process(p, len(p), "a", now.Add(time.Second))
	}
	b := e.Snapshot(now.Add(30 * time.Second))
	stats := b.Metrics[0].ServiceTargets[0]
	if len(stats.Targets) != maxServiceTargets || !stats.TargetsCapped || stats.Attempts != maxServiceTargets+2 || b.Health.StateDropped != 0 {
		t.Fatalf("service capacity corrupted counting or global quality: %+v; health=%+v", stats, b.Health)
	}
	p := frame("203.0.113.1", "192.0.2.129", 51000, 22, 1000, 2, "")
	e.Process(p, len(p), "a", now.Add(31*time.Second))
	next := e.Snapshot(now.Add(60 * time.Second)).Metrics[0].ServiceTargets[0]
	if next.TargetsCapped || next.Attempts != 1 || !reflect.DeepEqual(next.Targets, []string{"192.0.2.129"}) {
		t.Fatalf("service target state leaked between windows: %+v", next)
	}
}

func TestServiceStatsAdvertiseSupportWithoutAllocatingAbsentServices(t *testing.T) {
	now := time.Now()
	c := cfg()
	c.MaxFlows = 1
	e := New(c, now)
	p := frame("203.0.113.1", "192.0.2.1", 40000, 443, 100, 2, "")
	e.Process(p, len(p), "a", now)
	if e.ips[netip.MustParseAddr("203.0.113.1")].serviceTargets != nil {
		t.Fatal("ordinary traffic allocated service target maps")
	}
	p = frame("203.0.113.1", "192.0.2.2", 40001, 22, 200, 2, "")
	e.Process(p, len(p), "a", now)
	b := e.Snapshot(now.Add(30 * time.Second))
	m := b.Metrics[0]
	if m.ServiceTargetStatsVersion != 1 || len(m.ServiceTargets) != 0 || m.TCPAttempts != 1 || b.Health.StateDropped != 1 {
		t.Fatalf("unsupported/empty service evidence or SYN capacity was misreported: %+v; health=%+v", m, b.Health)
	}
	encoded, err := json.Marshal(m)
	if err != nil || !strings.Contains(string(encoded), `"service_target_stats_version":1`) || !strings.Contains(string(encoded), `"service_targets":[]`) {
		t.Fatalf("missing support marker for empty service evidence: %s, %v", encoded, err)
	}
}

func TestServiceTargets500IPv6VMsFitDefaultBatchLimit(t *testing.T) {
	const vmCount = 500
	const attemptsPerVM = 100
	const batchLimit = 8 << 20
	now := time.Now()
	c := cfg()
	c.CIDRs = []string{"2001:db8:1000::/48"}
	c.MaxIPs = 4096
	c.MaxFlows = 50000
	e := New(c, now)
	ports := []uint16{22, 3389, 21, 990}
	for vm := 0; vm < vmCount; vm++ {
		local := fmt.Sprintf("2001:db8:1000:%04x:abcd:eeee:ffff:1111", vm+0x1000)
		for attempt := 0; attempt < attemptsPerVM; attempt++ {
			peer := fmt.Sprintf("2001:db8:f000:%04x:abcd:eeee:ffff:2222", vm*attemptsPerVM+attempt+0x1000)
			p := frame(local, peer, uint16(40000+attempt), ports[attempt%len(ports)], uint32(attempt+1), 2, "")
			e.Process(p, len(p), "a", now)
		}
	}
	if len(e.syns) != c.MaxFlows || len(e.ips) != vmCount {
		t.Fatalf("scale fixture did not exercise the default global SYN capacity: flows=%d, VMs=%d", len(e.syns), len(e.ips))
	}
	retainedIPStates := e.ips
	b := e.Snapshot(now.Add(30 * time.Second))
	if b.Health.StateDropped != 0 || len(b.Metrics) != vmCount {
		t.Fatalf("default SYN capacity dropped accepted service evidence: %+v", b.Health)
	}
	var serviceAttempts uint64
	serviceTargets := 0
	for _, metric := range b.Metrics {
		if metric.ServiceTargetStatsVersion != 1 || len(metric.ServiceTargets) != 3 {
			t.Fatalf("missing service evidence at scale: %+v", metric.ServiceTargets)
		}
		for _, service := range metric.ServiceTargets {
			if service.TargetsCapped {
				t.Fatal("100 targets per VM unexpectedly exceeded a service capacity")
			}
			serviceAttempts += service.Attempts
			serviceTargets += len(service.Targets)
		}
	}
	if serviceAttempts != uint64(c.MaxFlows) || serviceTargets != c.MaxFlows {
		t.Fatalf("target evidence disappeared at scale: attempts=%d, targets=%d", serviceAttempts, serviceTargets)
	}
	var withServiceMaps, withoutServiceMaps runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&withServiceMaps)
	for _, state := range retainedIPStates {
		state.serviceTargets = nil
	}
	runtime.GC()
	runtime.ReadMemStats(&withoutServiceMaps)
	runtime.KeepAlive(e)
	runtime.KeepAlive(retainedIPStates)
	serviceMapHeap := int64(withServiceMaps.HeapAlloc) - int64(withoutServiceMaps.HeapAlloc)
	encoded, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > batchLimit {
		t.Fatalf("500-VM service evidence exceeds the 8 MiB API/spool limit: %d bytes", len(encoded))
	}
	var baseline map[string]json.RawMessage
	if err = json.Unmarshal(encoded, &baseline); err != nil {
		t.Fatal(err)
	}
	var metrics []map[string]json.RawMessage
	if err = json.Unmarshal(baseline["metrics"], &metrics); err != nil {
		t.Fatal(err)
	}
	for _, metric := range metrics {
		delete(metric, "service_target_stats_version")
		delete(metric, "service_targets")
	}
	if baseline["metrics"], err = json.Marshal(metrics); err != nil {
		t.Fatal(err)
	}
	baselineJSON, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("500 IPv6 VMs, 50,000 SYN attempts: batch=%d bytes; service fields=%d bytes; baseline=%d bytes; approximate additional live service-map heap=%d bytes", len(encoded), len(encoded)-len(baselineJSON), len(baselineJSON), serviceMapHeap)
}
