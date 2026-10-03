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
	udpEndpoints  map[netip.AddrPort]*wire.UDPEndpoint
	m             wire.Metric
	targets       map[netip.Addr]int
	auth          map[netip.Addr]int
	edges         map[netip.AddrPort]bool
	ports         map[netip.Addr]int
	endpoints     map[netip.AddrPort]*wire.EndpointEvidence
	metadataCount int
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
	at           time.Time
	responded    bool
	completed    bool
	reset        bool
	seq, peerSeq uint32
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
	udpFlows   map[flowKey]bool
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
	e := &Engine{udpFlows: map[flowKey]bool{}, c: c, ips: map[netip.Addr]*ipState{}, syns: map[flowKey]synState{}, streams: map[flowKey]*stream{}, sites: map[string]wire.Site{}, vpn: map[vpnKey]*vpnState{}, proxyFlows: map[flowKey]*proxyFlow{}, duplicates: map[uint64]seen{}, start: now}
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
	s := &ipState{udpEndpoints: map[netip.AddrPort]*wire.UDPEndpoint{}, m: wire.Metric{IP: a.String()}, targets: map[netip.Addr]int{}, auth: map[netip.Addr]int{}, edges: map[netip.AddrPort]bool{}, ports: map[netip.Addr]int{}, endpoints: map[netip.AddrPort]*wire.EndpointEvidence{}}
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
	if p.Protocol == 17 {
		if src {
			e.observeUDP(p, true)
		}
		if dst {
			e.observeUDP(p, false)
		}
	}
	if p.Protocol != 6 {
		return
	}
	k := flowKey{p.Src, p.Dst, p.SrcPort, p.DstPort}
	if dst && p.SYN && p.ACK && !p.RST {
		reverse := flowKey{p.Dst, p.Src, p.DstPort, p.SrcPort}
		if attempt, ok := e.syns[reverse]; ok && !attempt.responded && p.AckSeq == attempt.seq+1 && now.Sub(attempt.at) < 60*time.Second {
			attempt.responded = true
			attempt.peerSeq = p.Seq
			e.syns[reverse] = attempt
			if s := e.state(p.Dst); s != nil && !attempt.at.Before(e.start) {
				s.m.SYNACKReplies++
				if endpoint := s.endpoints[netip.AddrPortFrom(p.Src, p.SrcPort)]; endpoint != nil {
					endpoint.SYNACKReplies++
				}
			}
		}
	}
	if src && p.SYN && !p.ACK && !p.RST {
		if attempt, ok := e.syns[k]; ok && attempt.seq == p.Seq && now.Sub(attempt.at) < 60*time.Second {
			return
		}
		if _, exists := e.syns[k]; !exists && len(e.syns) >= e.c.MaxFlows {
			e.health.StateDropped++
			return
		}
		e.syns[k] = synState{at: now, seq: p.Seq}
		s := e.state(p.Src)
		if s == nil {
			return
		}
		s.m.TCPAttempts++
		if endpoint := e.endpoint(s, p.Dst, p.DstPort); endpoint != nil {
			endpoint.Attempts++
		}
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
	outbound := false
	var endpoint *wire.EndpointEvidence
	if src {
		if attempt, ok := e.syns[k]; ok && now.Sub(attempt.at) < 60*time.Second {
			if s := e.state(p.Src); s != nil {
				endpoint = e.endpoint(s, p.Dst, p.DstPort)
				outbound = true
			}
		}
	}
	if endpoint != nil {
		endpoint.PayloadOut += uint64(len(p.Payload))
		attempt := e.syns[k]
		if p.ACK && !p.SYN && !p.RST && attempt.responded && !attempt.completed && p.AckSeq == attempt.peerSeq+1 && p.Seq == attempt.seq+1 {
			attempt.completed = true
			e.syns[k] = attempt
			if !attempt.at.Before(e.start) {
				e.ips[p.Src].m.CompletedHandshakes++
				endpoint.CompletedHandshakes++
			}
		}
		endpoint.MaxObservedSpanMS = max(endpoint.MaxObservedSpanMS, uint64(max(0, now.Sub(attempt.at).Milliseconds())))
	}
	inboundReply := false
	if dst {
		reverse := flowKey{p.Dst, p.Src, p.DstPort, p.SrcPort}
		if attempt, ok := e.syns[reverse]; ok && now.Sub(attempt.at) < 60*time.Second {
			inboundReply = true
			if s := e.state(p.Dst); s != nil {
				if reply := e.endpoint(s, p.Src, p.SrcPort); reply != nil {
					reply.PayloadIn += uint64(len(p.Payload))
					reply.MaxObservedSpanMS = max(reply.MaxObservedSpanMS, uint64(max(0, now.Sub(attempt.at).Milliseconds())))
					if p.RST && !attempt.reset && (attempt.completed || (p.ACK && p.AckSeq == attempt.seq+1)) {
						attempt.reset = true
						e.syns[reverse] = attempt
						if !attempt.at.Before(e.start) {
							s.m.RSTReplies++
							reply.RSTReplies++
						}
					}
				}
			}
		}
	}
	if (!dst && !outbound) || (inboundReply && !outbound) || len(p.Payload) == 0 {
		return
	}
	if outbound && endpoint != nil {
		s := e.ips[p.Src]
		if endpoint.Scheme != "" || s.metadataCount >= 8 {
			return
		}
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
	if outbound {
		if endpoint != nil {
			endpoint.Scheme, endpoint.Host = scheme, host
			if scheme == "http" {
				endpoint.HTTPMethod, endpoint.HTTPPath, endpoint.QueryKeys = packet.RequestMetadata(st.buf)
			}
			e.ips[p.Src].metadataCount++
		}
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

// UDP has no handshake: count each distinct outgoing tuple once per window,
// including service replies; packet counts never imply new connections or attack.
func (e *Engine) observeUDP(p packet.Packet, out bool) {
	vm, peer, localPort, peerPort := p.Src, p.Dst, p.SrcPort, p.DstPort
	if !out {
		vm, peer, localPort, peerPort = p.Dst, p.Src, p.DstPort, p.SrcPort
	}
	s := e.state(vm)
	if s == nil {
		return
	}
	if out {
		s.m.UDPPacketsOut++
		s.m.UDPBytesOut += uint64(p.Size)
	} else {
		s.m.UDPPacketsIn++
		s.m.UDPBytesIn += uint64(p.Size)
	}
	key := netip.AddrPortFrom(peer, peerPort)
	endpoint := s.udpEndpoints[key]
	if endpoint == nil && len(s.udpEndpoints) < 64 {
		endpoint = &wire.UDPEndpoint{PeerIP: peer.String(), PeerPort: peerPort}
		s.udpEndpoints[key] = endpoint
	}
	if endpoint == nil {
		s.m.UDPEndpointsTruncated = true
	}
	if out {
		flow := flowKey{vm, peer, localPort, peerPort}
		if !e.udpFlows[flow] {
			if len(e.udpFlows) < min(e.c.MaxFlows, 16384) {
				e.udpFlows[flow] = true
				s.m.UDPFlowsOut++
				if endpoint != nil {
					endpoint.Flows++
				}
			} else {
				s.m.UDPFlowsCapped = true
			}
		}
		if endpoint != nil {
			endpoint.PacketsOut++
			endpoint.BytesOut += uint64(p.Size)
		}
	} else if endpoint != nil {
		endpoint.PacketsIn++
		endpoint.BytesIn += uint64(p.Size)
	}
}
func (e *Engine) endpoint(s *ipState, peer netip.Addr, port uint16) *wire.EndpointEvidence {
	key := netip.AddrPortFrom(peer, port)
	if found := s.endpoints[key]; found != nil {
		return found
	}
	if len(s.endpoints) >= 256 {
		s.m.OutboundSamplesTruncated = true
		return nil
	}
	found := &wire.EndpointEvidence{PeerIP: peer.String(), PeerPort: port}
	s.endpoints[key] = found
	return found
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
	for key, attempt := range e.syns {
		if !attempt.at.Before(e.start) && now.Sub(attempt.at) >= 3*time.Second {
			if s := e.ips[key.Src]; s != nil {
				s.m.MatureAttempts++
				if !attempt.responded && !attempt.reset {
					s.m.MatureNoReply++
				}
			}
		}
	}
	for _, s := range e.ips {
		s.m.UDPStatsVersion = 1
		udpEndpoints := make([]wire.UDPEndpoint, 0, len(s.udpEndpoints))
		for _, endpoint := range s.udpEndpoints {
			udpEndpoints = append(udpEndpoints, *endpoint)
		}
		sort.Slice(udpEndpoints, func(i, j int) bool {
			if udpEndpoints[i].PacketsOut != udpEndpoints[j].PacketsOut {
				return udpEndpoints[i].PacketsOut > udpEndpoints[j].PacketsOut
			}
			if udpEndpoints[i].PeerIP != udpEndpoints[j].PeerIP {
				return udpEndpoints[i].PeerIP < udpEndpoints[j].PeerIP
			}
			return udpEndpoints[i].PeerPort < udpEndpoints[j].PeerPort
		})
		s.m.UDPEndpointsTruncated = s.m.UDPEndpointsTruncated || len(udpEndpoints) > 8
		s.m.UDPEndpoints = udpEndpoints[:min(len(udpEndpoints), 8)]
		s.m.ConnectionStatsVersion = 1
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
		portsByTarget := map[netip.Addr][]uint16{}
		endpoints := make([]string, 0, len(s.edges))
		for endpoint := range s.edges {
			portSet[endpoint.Port()] = true
			portsByTarget[endpoint.Addr()] = append(portsByTarget[endpoint.Addr()], endpoint.Port())
			endpoints = append(endpoints, endpoint.String())
		}
		ports := make([]int, 0, len(portSet))
		for port := range portSet {
			ports = append(ports, int(port))
		}
		sort.Ints(ports)
		s.m.PortSamplesTruncated = len(ports) > 256
		s.m.EndpointSamplesTruncated = len(endpoints) > 32
		s.m.Ports = make([]uint16, 0, min(len(ports), 256))
		for _, port := range ports[:min(len(ports), 256)] {
			s.m.Ports = append(s.m.Ports, uint16(port))
		}
		sort.Strings(endpoints)
		s.m.TargetEndpoints = endpoints[:min(len(endpoints), 32)]
		outbound := make([]wire.EndpointEvidence, 0, len(s.endpoints))
		for _, endpoint := range s.endpoints {
			outbound = append(outbound, *endpoint)
		}
		sort.Slice(outbound, func(i, j int) bool {
			if outbound[i].Attempts != outbound[j].Attempts {
				return outbound[i].Attempts > outbound[j].Attempts
			}
			if outbound[i].PeerIP != outbound[j].PeerIP {
				return outbound[i].PeerIP < outbound[j].PeerIP
			}
			return outbound[i].PeerPort < outbound[j].PeerPort
		})
		s.m.OutboundSamplesTruncated = s.m.OutboundSamplesTruncated || len(outbound) > 8
		s.m.OutboundEndpoints = outbound[:min(len(outbound), 8)]
		portTargets := make([]wire.PortTarget, 0, len(portsByTarget))
		for target, portList := range portsByTarget {
			sort.Slice(portList, func(i, j int) bool { return portList[i] < portList[j] })
			portTargets = append(portTargets, wire.PortTarget{PeerIP: target.String(), PortCount: len(portList), Ports: portList[:min(len(portList), 128)], Truncated: len(portList) > 128 || s.m.CardinalityCapped})
		}
		sort.Slice(portTargets, func(i, j int) bool {
			if portTargets[i].PortCount != portTargets[j].PortCount {
				return portTargets[i].PortCount > portTargets[j].PortCount
			}
			return portTargets[i].PeerIP < portTargets[j].PeerIP
		})
		s.m.PortScanTargets = portTargets[:min(len(portTargets), 8)]
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
	e.udpFlows = map[flowKey]bool{}
	e.ips = map[netip.Addr]*ipState{}
	e.sites = map[string]wire.Site{}
	e.vpn = map[vpnKey]*vpnState{}
	e.proxyFlows = map[flowKey]*proxyFlow{}
	e.health = wire.Health{}
	e.start = now
	return b
}
