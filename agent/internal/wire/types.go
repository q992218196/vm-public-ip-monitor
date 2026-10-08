package wire

type UDPEndpoint struct {
	PeerIP     string `json:"peer_ip"`
	PeerPort   uint16 `json:"peer_port"`
	Flows      uint64 `json:"flows"`
	PacketsOut uint64 `json:"packets_out"`
	PacketsIn  uint64 `json:"packets_in"`
	BytesOut   uint64 `json:"bytes_out"`
	BytesIn    uint64 `json:"bytes_in"`
}
type Metric struct {
	ServiceTargetStatsVersion int                  `json:"service_target_stats_version"`
	ServiceTargets            []ServiceTargetStats `json:"service_targets"`
	UDPFilterVersion          int                  `json:"udp_filter_version"`
	UDPNonDNSFlowsOut         uint64               `json:"udp_non_dns_flows_out"`
	UDPNonDNSPacketsOut       uint64               `json:"udp_non_dns_packets_out"`
	UDPNonDNSEndpoints        []UDPEndpoint        `json:"udp_non_dns_endpoints,omitempty"`
	UDPStatsVersion           int                  `json:"udp_stats_version"`
	UDPFlowsOut               uint64               `json:"udp_flows_out"`
	UDPFlowsCapped            bool                 `json:"udp_flows_capped"`
	UDPPacketsOut             uint64               `json:"udp_packets_out"`
	UDPPacketsIn              uint64               `json:"udp_packets_in"`
	UDPBytesOut               uint64               `json:"udp_bytes_out"`
	UDPBytesIn                uint64               `json:"udp_bytes_in"`
	UDPEndpoints              []UDPEndpoint        `json:"udp_endpoints,omitempty"`
	UDPEndpointsTruncated     bool                 `json:"udp_endpoints_truncated"`
	IP                        string               `json:"ip"`
	BytesOut                  uint64               `json:"bytes_out"`
	BytesIn                   uint64               `json:"bytes_in"`
	PacketsOut                uint64               `json:"packets_out"`
	PacketsIn                 uint64               `json:"packets_in"`
	TCPAttempts               uint64               `json:"tcp_attempts"`
	SYNACKReplies             uint64               `json:"synack_replies"`
	ConnectionStatsVersion    int                  `json:"connection_stats_version"`
	CompletedHandshakes       uint64               `json:"completed_handshakes"`
	RSTReplies                uint64               `json:"rst_replies"`
	MatureAttempts            uint64               `json:"mature_attempts"`
	MatureNoReply             uint64               `json:"mature_no_reply"`
	PortScanTargets           []PortTarget         `json:"port_scan_targets,omitempty"`
	UniqueTargets             int                  `json:"unique_targets"`
	MaxPortsPerTarget         int                  `json:"max_ports_per_target"`
	MaxAttemptsPerTarget      int                  `json:"max_attempts_per_target"`
	AuthAttempts              int                  `json:"auth_attempts"`
	Targets                   []string             `json:"targets"`
	Ports                     []uint16             `json:"ports"`
	TargetEndpoints           []string             `json:"target_endpoints"`
	PortSamplesTruncated      bool                 `json:"port_samples_truncated"`
	EndpointSamplesTruncated  bool                 `json:"endpoint_samples_truncated"`
	CardinalityCapped         bool                 `json:"cardinality_capped"`
	OutboundEndpoints         []EndpointEvidence   `json:"outbound_endpoints,omitempty"`
	OutboundSamplesTruncated  bool                 `json:"outbound_samples_truncated"`
}
type ServiceTargetStats struct {
	Service       string   `json:"service"`
	Targets       []string `json:"targets"`
	Ports         []uint16 `json:"ports"`
	TargetsCapped bool     `json:"targets_capped"`
	Attempts      uint64   `json:"attempts"`
}
type EndpointEvidence struct {
	PeerIP              string   `json:"peer_ip"`
	PeerPort            uint16   `json:"peer_port"`
	Attempts            uint64   `json:"attempts"`
	SYNACKReplies       uint64   `json:"synack_replies"`
	CompletedHandshakes uint64   `json:"completed_handshakes"`
	RSTReplies          uint64   `json:"rst_replies"`
	MaxObservedSpanMS   uint64   `json:"max_observed_span_ms"`
	PayloadOut          uint64   `json:"payload_out"`
	PayloadIn           uint64   `json:"payload_in"`
	Scheme              string   `json:"scheme,omitempty"`
	Host                string   `json:"host,omitempty"`
	HTTPMethod          string   `json:"http_method,omitempty"`
	HTTPPath            string   `json:"http_path,omitempty"`
	QueryKeys           []string `json:"query_keys,omitempty"`
}
type PortTarget struct {
	PeerIP    string   `json:"peer_ip"`
	PortCount int      `json:"port_count"`
	Ports     []uint16 `json:"ports"`
	Truncated bool     `json:"truncated"`
}
type Site struct {
	IP     string `json:"ip"`
	Port   uint16 `json:"port"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Source string `json:"source"`
}
type VPNObservation struct {
	IP             string `json:"ip"`
	PeerIP         string `json:"peer_ip"`
	LocalPort      uint16 `json:"local_port"`
	PeerPort       uint16 `json:"peer_port"`
	Protocol       string `json:"protocol"`
	Initiator      string `json:"initiator"`
	RequestCount   int    `json:"request_count"`
	ResponseCount  int    `json:"response_count"`
	RequestLength  int    `json:"request_length"`
	ResponseLength int    `json:"response_length"`
	RequestHeader  string `json:"request_header"`
	ResponseHeader string `json:"response_header"`
}
type ProxyObservation struct {
	IP                  string   `json:"ip"`
	LocalPort           uint16   `json:"local_port"`
	Transport           string   `json:"transport"`
	PeerCount           int      `json:"peer_count"`
	SessionCount        int      `json:"session_count"`
	BytesFromPeers      uint64   `json:"bytes_from_peers"`
	BytesToPeers        uint64   `json:"bytes_to_peers"`
	PeerSamples         []string `json:"peer_samples"`
	EgressTargetCount   int      `json:"egress_target_count"`
	EgressTargetSamples []string `json:"egress_target_samples"`
}
type Health struct {
	Version           string   `json:"version"`
	UpdateError       string   `json:"update_error,omitempty"`
	Captured          uint64   `json:"captured"`
	KernelDrops       uint64   `json:"kernel_drops"`
	DecodeSkipped     uint64   `json:"decode_skipped"`
	StateDropped      uint64   `json:"state_dropped"`
	SpoolDropped      uint64   `json:"spool_dropped"`
	DuplicatePackets  uint64   `json:"duplicate_packets"`
	ReassemblyDropped uint64   `json:"reassembly_dropped"`
	RSSBytes          uint64   `json:"rss_bytes"`
	HeapBytes         uint64   `json:"heap_bytes"`
	SpoolBytes        int64    `json:"spool_bytes"`
	DiskBytes         int64    `json:"disk_bytes"`
	Interfaces        []string `json:"interfaces"`
}
type Batch struct {
	ID          string             `json:"batch_id"`
	WindowStart string             `json:"window_start"`
	WindowEnd   string             `json:"window_end"`
	Health      Health             `json:"health"`
	Metrics     []Metric           `json:"metrics"`
	Sites       []Site             `json:"sites"`
	VPN         []VPNObservation   `json:"vpn"`
	Proxies     []ProxyObservation `json:"proxies"`
}
