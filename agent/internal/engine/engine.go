package engine

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"sync"
	"time"

	"vm-monitor/agent/internal/config"
	"vm-monitor/agent/internal/packet"
	"vm-monitor/agent/internal/wire"
)

type flowKey struct {
	Src, Dst netip.Addr
	SP, DP   uint16
}
type ipState struct {
	m       wire.Metric
	targets map[netip.Addr]int
	auth    map[netip.Addr]int
	edges   map[netip.AddrPort]bool
	ports   map[netip.Addr]int
}
type stream struct {
	buf  []byte
	next uint32
	at   time.Time
}
type seen struct {
	iface string
	at    time.Time
}
type Engine struct {
	mu         sync.Mutex
	c          config.Config
	prefixes   []netip.Prefix
	ips        map[netip.Addr]*ipState
	syns       map[flowKey]time.Time
	streams    map[flowKey]*stream
	sites      map[string]wire.Site
	duplicates map[uint64]seen
	health     wire.Health
	start      time.Time
}

func New(c config.Config, now time.Time) *Engine {
	e := &Engine{c: c, ips: map[netip.Addr]*ipState{}, syns: map[flowKey]time.Time{}, streams: map[flowKey]*stream{}, sites: map[string]wire.Site{}, duplicates: map[uint64]seen{}, start: now}
	for _, s := range c.CIDRs {
		p, err := netip.ParsePrefix(s)
		if err == nil {
			e.prefixes = append(e.prefixes, p.Masked())
		}
	}
	return e
}
func (e *Engine) managed(a netip.Addr) bool {
	for _, p := range e.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
func (e *Engine) state(a netip.Addr) *ipState {
	if s := e.ips[a]; s != nil {
		return s
	}
	if len(e.ips) >= e.c.MaxIPs {
		e.health.StateDropped++
		return nil
	}
	s := &ipState{m: wire.Metric{IP: a.String()}, targets: map[netip.Addr]int{}, auth: map[netip.Addr]int{}, edges: map[netip.AddrPort]bool{}, ports: map[netip.Addr]int{}}
	e.ips[a] = s
	return s
}
func (e *Engine) Process(b []byte, wireLen int, iface string, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.health.Captured++
	p, ok := packet.Decode(b, wireLen)
	if !ok {
		e.health.DecodeSkipped++
		return
	}
	src, dst := e.managed(p.Src), e.managed(p.Dst)
	if !src && !dst {
		return
	}
	// Only suppress copies seen on DIFFERENT selected interfaces. A retransmission
	// on the same interface remains traffic; TCP attempts are deduplicated below.
	h := fnv.New64a()
	h.Write(b)
	hash := h.Sum64()
	if prev, ok := e.duplicates[hash]; ok && prev.iface != iface && now.Sub(prev.at) < time.Second {
		e.health.DuplicatePackets++
		return
	}
	if len(e.duplicates) < 65536 {
		e.duplicates[hash] = seen{iface, now}
	}
	if src {
		if s := e.state(p.Src); s != nil {
			s.m.BytesOut += uint64(p.Size)
			s.m.PacketsOut++
		}
	}
	if dst {
		if s := e.state(p.Dst); s != nil {
			s.m.BytesIn += uint64(p.Size)
			s.m.PacketsIn++
		}
	}
	if p.Protocol != 6 {
		return
	}
	k := flowKey{p.Src, p.Dst, p.SrcPort, p.DstPort}
	if src && p.SYN && !p.ACK {
		if t, ok := e.syns[k]; ok && now.Sub(t) < 60*time.Second {
			return
		}
		if len(e.syns) >= e.c.MaxFlows {
			e.health.StateDropped++
			return
		}
		e.syns[k] = now
		s := e.state(p.Src)
		if s == nil {
			return
		}
		s.m.TCPAttempts++
		if _, ok := s.targets[p.Dst]; ok || len(s.targets) < 256 {
			s.targets[p.Dst]++
			if s.targets[p.Dst] > s.m.MaxAttemptsPerTarget {
				s.m.MaxAttemptsPerTarget = s.targets[p.Dst]
			}
			if authPort(p.DstPort) {
				s.auth[p.Dst]++
				if s.auth[p.Dst] > s.m.AuthAttempts {
					s.m.AuthAttempts = s.auth[p.Dst]
				}
			}
		} else {
			s.m.CardinalityCapped = true
		}
		edge := netip.AddrPortFrom(p.Dst, p.DstPort)
		if !s.edges[edge] {
			if len(s.edges) < 256 {
				s.edges[edge] = true
				s.ports[p.Dst]++
				if s.ports[p.Dst] > s.m.MaxPortsPerTarget {
					s.m.MaxPortsPerTarget = s.ports[p.Dst]
				}
			} else {
				s.m.CardinalityCapped = true
			}
		}
	}
	if !dst || len(p.Payload) == 0 {
		return
	}
	st := e.streams[k]
	if st == nil {
		if len(e.streams) >= e.c.MaxReassembly {
			e.health.ReassemblyDropped++
			return
		}
		st = &stream{next: p.Seq, at: now}
		e.streams[k] = st
	}
	if p.Seq != st.next {
		// Best-effort bounded reassembly: ignore wholly repeated segments; gaps or
		// partial overlap are discarded and counted rather than inventing a hostname.
		if int32(p.Seq-st.next) < 0 && int32(p.Seq+uint32(len(p.Payload))-st.next) <= 0 {
			return
		}
		delete(e.streams, k)
		e.health.ReassemblyDropped++
		return
	}
	if len(st.buf)+len(p.Payload) > 16384 {
		delete(e.streams, k)
		e.health.ReassemblyDropped++
		return
	}
	st.buf = append(st.buf, p.Payload...)
	st.next += uint32(len(p.Payload))
	scheme, host, complete := packet.Site(st.buf)
	if !complete {
		return
	}
	delete(e.streams, k)
	if scheme == "" {
		return
	}
	site := wire.Site{IP: p.Dst.String(), Port: p.DstPort, Scheme: scheme, Host: host, Source: "http_host"}
	if scheme == "https" {
		site.Source = "tls_sni"
	}
	key := fmt.Sprintf("%s|%d|%s|%s", site.IP, site.Port, site.Scheme, site.Host)
	if _, ok := e.sites[key]; !ok && len(e.sites) >= e.c.MaxSites {
		e.health.StateDropped++
		return
	}
	e.sites[key] = site
}
func authPort(p uint16) bool {
	switch p {
	case 21, 22, 23, 25, 110, 143, 389, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379:
		return true
	}
	return false
}
func (e *Engine) Sweep(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, t := range e.syns {
		if now.Sub(t) > 60*time.Second {
			delete(e.syns, k)
		}
	}
	for k, s := range e.streams {
		if now.Sub(s.at) > 10*time.Second {
			delete(e.streams, k)
			e.health.ReassemblyDropped++
		}
	}
	for k, s := range e.duplicates {
		if now.Sub(s.at) > time.Second {
			delete(e.duplicates, k)
		}
	}
}
func (e *Engine) KernelDrops(n uint64) { e.mu.Lock(); e.health.KernelDrops += n; e.mu.Unlock() }
func (e *Engine) Snapshot(now time.Time) wire.Batch {
	e.mu.Lock()
	defer e.mu.Unlock()
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		panic(err)
	}
	b := wire.Batch{ID: hex.EncodeToString(id), WindowStart: e.start.UTC().Format(time.RFC3339Nano), WindowEnd: now.UTC().Format(time.RFC3339Nano), Health: e.health, Metrics: []wire.Metric{}, Sites: []wire.Site{}}
	for _, s := range e.ips {
		s.m.UniqueTargets = len(s.targets)
		ts := make([]string, 0, len(s.targets))
		for t := range s.targets {
			ts = append(ts, t.String())
		}
		sort.Strings(ts)
		if len(ts) > 16 {
			ts = ts[:16]
		}
		s.m.Targets = ts
		b.Metrics = append(b.Metrics, s.m)
	}
	for _, s := range e.sites {
		b.Sites = append(b.Sites, s)
	}
	sort.Slice(b.Metrics, func(i, j int) bool { return b.Metrics[i].IP < b.Metrics[j].IP })
	e.ips = map[netip.Addr]*ipState{}
	e.sites = map[string]wire.Site{}
	e.health = wire.Health{}
	e.start = now
	return b
}
