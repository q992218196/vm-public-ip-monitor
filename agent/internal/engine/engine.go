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
type synState struct {
	at        time.Time
	responded bool
}
type vpnKey struct {
	VM, Peer            netip.Addr
	LocalPort, PeerPort uint16
	Protocol            string
	Session             uint64
}
type vpnState struct {
	observation wire.VPNObservation
}
type proxyFlow struct {
	vm, peer               netip.Addr
	localPort              uint16
	transport              string
	fromPackets, toPackets int
	fromBytes, toBytes     uint64
	firstAt, lastAt        time.Time
}
type proxyServiceKey struct {
	vm        netip.Addr
	localPort uint16
	transport string
}
type proxyService struct {
	peers     map[netip.Addr]bool
	sessions  int
	fromBytes uint64
	toBytes   uint64
}

const maxProxyFlows = 16384

type Engine struct {
	mu         sync.Mutex
	c          config.Config
	prefixes   []netip.Prefix
	ips        map[netip.Addr]*ipState
	syns       map[flowKey]synState
	streams    map[flowKey]*stream
	sites      map[string]wire.Site
	vpn        map[vpnKey]*vpnState
	proxyFlows map[flowKey]*proxyFlow
	duplicates map[uint64]seen
	health     wire.Health
	start      time.Time
}

func New(c config.Config, now time.Time) *Engine {
	e := &Engine{c: c, ips: map[netip.Addr]*ipState{}, syns: map[flowKey]synState{}, streams: map[flowKey]*stream{}, sites: map[string]wire.Site{}, vpn: map[vpnKey]*vpnState{}, proxyFlows: map[flowKey]*proxyFlow{}, duplicates: map[uint64]seen{}, start: now}
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
	if signature, matched := packet.VPN(p); matched {
		if src {
			e.observeVPN(p.Src, p.Dst, p.SrcPort, p.DstPort, "vm", signature)
		}
		if dst {
			e.observeVPN(p.Dst, p.Src, p.DstPort, p.SrcPort, "peer", signature)
		}
	} else {
		e.observeProxy(p, src, dst, now)
	}
	if p.Protocol != 6 {
		return
	}
	k := flowKey{p.Src, p.Dst, p.SrcPort, p.DstPort}
	if dst && p.SYN && p.ACK {
		reverse := flowKey{p.Dst, p.Src, p.DstPort, p.SrcPort}
		if attempt, ok := e.syns[reverse]; ok && !attempt.responded && now.Sub(attempt.at) < 60*time.Second {
			attempt.responded = true
			e.syns[reverse] = attempt
			if s := e.state(p.Dst); s != nil {
				s.m.SYNACKReplies++
			}
		}
	}
	if src && p.SYN && !p.ACK {
		if attempt, ok := e.syns[k]; ok && now.Sub(attempt.at) < 60*time.Second {
			return
		}
		if len(e.syns) >= e.c.MaxFlows {
			e.health.StateDropped++
			return
		}
		e.syns[k] = synState{at: now}
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
func (e *Engine) observeProxy(p packet.Packet, src, dst bool, now time.Time) {
	if src == dst || (p.Protocol != 6 && p.Protocol != 17) {
		return
	}
	var key flowKey
	if dst {
		key = flowKey{p.Src, p.Dst, p.SrcPort, p.DstPort}
	} else {
		key = flowKey{p.Dst, p.Src, p.DstPort, p.SrcPort}
	}
	flow := e.proxyFlows[key]
	if flow == nil {
		if !dst || (p.Protocol == 6 && (!p.SYN || p.ACK)) {
			return
		}
		if len(e.proxyFlows) >= min(e.c.MaxFlows, maxProxyFlows) {
			e.health.StateDropped++
			return
		}
		transport := ""
		if p.Protocol == 17 {
			transport = packet.ProxyTransport(p)
			if transport == "" {
				return
			}
		}
		flow = &proxyFlow{vm: p.Dst, peer: p.Src, localPort: p.DstPort, transport: transport, firstAt: now}
		e.proxyFlows[key] = flow
	}
	if len(p.Payload) == 0 {
		return
	}
	if dst {
		if flow.transport == "" {
			flow.transport = packet.ProxyTransport(p)
			if flow.transport == "" {
				delete(e.proxyFlows, key)
				return
			}
		}
		flow.fromPackets++
		flow.fromBytes += uint64(len(p.Payload))
	} else {
		flow.toPackets++
		flow.toBytes += uint64(len(p.Payload))
	}
	flow.lastAt = now
}
func (e *Engine) observeVPN(vm, peer netip.Addr, localPort, peerPort uint16, sender string, signature packet.VPNSignature) {
	key := vpnKey{VM: vm, Peer: peer, LocalPort: localPort, PeerPort: peerPort, Protocol: signature.Protocol, Session: signature.Session}
	state := e.vpn[key]
	if state == nil {
		if len(e.vpn) >= 2048 {
			e.health.StateDropped++
			return
		}
		state = &vpnState{observation: wire.VPNObservation{IP: vm.String(), PeerIP: peer.String(), LocalPort: localPort, PeerPort: peerPort, Protocol: signature.Protocol}}
		e.vpn[key] = state
	}
	o := &state.observation
	if signature.Phase == "request" {
		o.RequestCount++
		if o.RequestCount == 1 {
			o.Initiator = sender
			o.RequestLength = signature.Length
			o.RequestHeader = signature.HeaderHex
		}
	} else {
		o.ResponseCount++
		if o.ResponseCount == 1 {
			o.ResponseLength = signature.Length
			o.ResponseHeader = signature.HeaderHex
		}
	}
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
	for k, attempt := range e.syns {
		if now.Sub(attempt.at) > 60*time.Second {
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
	b := wire.Batch{ID: hex.EncodeToString(id), WindowStart: e.start.UTC().Format(time.RFC3339Nano), WindowEnd: now.UTC().Format(time.RFC3339Nano), Health: e.health, Metrics: []wire.Metric{}, Sites: []wire.Site{}, VPN: []wire.VPNObservation{}, Proxies: []wire.ProxyObservation{}}
	services := map[proxyServiceKey]*proxyService{}
	for _, flow := range e.proxyFlows {
		if flow.transport == "" || flow.transport == "ignored" || flow.fromPackets < 2 || flow.toPackets < 2 || flow.fromBytes < 1024 || flow.toBytes < 1024 || flow.lastAt.Sub(flow.firstAt) < 3*time.Second {
			continue
		}
		key := proxyServiceKey{flow.vm, flow.localPort, flow.transport}
		service := services[key]
		if service == nil {
			service = &proxyService{peers: map[netip.Addr]bool{}}
			services[key] = service
		}
		service.peers[flow.peer] = true
		service.sessions++
		service.fromBytes += flow.fromBytes
		service.toBytes += flow.toBytes
	}
	for key, service := range services {
		state := e.ips[key.vm]
		if state == nil || len(service.peers) < 3 || len(state.targets) < 5 {
			continue
		}
		if len(b.Proxies) >= 256 {
			e.health.StateDropped++
			continue
		}
		peers := make([]string, 0, len(service.peers))
		for peer := range service.peers {
			peers = append(peers, peer.String())
		}
		sort.Strings(peers)
		targets := make([]string, 0, len(state.targets))
		for target := range state.targets {
			targets = append(targets, target.String())
		}
		sort.Strings(targets)
		b.Proxies = append(b.Proxies, wire.ProxyObservation{IP: key.vm.String(), LocalPort: key.localPort, Transport: key.transport, PeerCount: len(peers), SessionCount: service.sessions, BytesFromPeers: service.fromBytes, BytesToPeers: service.toBytes, PeerSamples: peers[:min(8, len(peers))], EgressTargetCount: len(targets), EgressTargetSamples: targets[:min(8, len(targets))]})
	}
	sort.Slice(b.Proxies, func(i, j int) bool {
		if b.Proxies[i].IP == b.Proxies[j].IP {
			return b.Proxies[i].LocalPort < b.Proxies[j].LocalPort
		}
		return b.Proxies[i].IP < b.Proxies[j].IP
	})
	b.Health = e.health
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
		portSet := map[uint16]bool{}
		endpoints := make([]string, 0, len(s.edges))
		for endpoint := range s.edges {
			portSet[endpoint.Port()] = true
			endpoints = append(endpoints, endpoint.String())
		}
		ports := make([]int, 0, len(portSet))
		for port := range portSet {
			ports = append(ports, int(port))
		}
		sort.Ints(ports)
		s.m.PortSamplesTruncated = len(ports) > 64
		s.m.EndpointSamplesTruncated = len(endpoints) > 32
		s.m.Ports = make([]uint16, 0, min(len(ports), 64))
		for _, port := range ports[:min(len(ports), 64)] {
			s.m.Ports = append(s.m.Ports, uint16(port))
		}
		sort.Strings(endpoints)
		s.m.TargetEndpoints = endpoints[:min(len(endpoints), 32)]
		b.Metrics = append(b.Metrics, s.m)
	}
	for _, s := range e.sites {
		b.Sites = append(b.Sites, s)
	}
	for _, s := range e.vpn {
		if s.observation.RequestCount > 0 && s.observation.ResponseCount > 0 {
			b.VPN = append(b.VPN, s.observation)
		}
	}
	sort.Slice(b.VPN, func(i, j int) bool {
		if b.VPN[i].IP == b.VPN[j].IP {
			return b.VPN[i].PeerIP < b.VPN[j].PeerIP
		}
		return b.VPN[i].IP < b.VPN[j].IP
	})
	sort.Slice(b.Metrics, func(i, j int) bool { return b.Metrics[i].IP < b.Metrics[j].IP })
	e.ips = map[netip.Addr]*ipState{}
	e.sites = map[string]wire.Site{}
	e.vpn = map[vpnKey]*vpnState{}
	e.proxyFlows = map[flowKey]*proxyFlow{}
	e.health = wire.Health{}
	e.start = now
	return b
}
