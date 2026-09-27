package wire

type Metric struct {
	IP                       string   `json:"ip"`
	BytesOut                 uint64   `json:"bytes_out"`
	BytesIn                  uint64   `json:"bytes_in"`
	PacketsOut               uint64   `json:"packets_out"`
	PacketsIn                uint64   `json:"packets_in"`
	TCPAttempts              uint64   `json:"tcp_attempts"`
	UniqueTargets            int      `json:"unique_targets"`
	MaxPortsPerTarget        int      `json:"max_ports_per_target"`
	MaxAttemptsPerTarget     int      `json:"max_attempts_per_target"`
	AuthAttempts             int      `json:"auth_attempts"`
	Targets                  []string `json:"targets"`
	Ports                    []uint16 `json:"ports"`
	TargetEndpoints          []string `json:"target_endpoints"`
	PortSamplesTruncated     bool     `json:"port_samples_truncated"`
	EndpointSamplesTruncated bool     `json:"endpoint_samples_truncated"`
	CardinalityCapped        bool     `json:"cardinality_capped"`
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
type Health struct {
	Version           string   `json:"version"`
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
	ID          string           `json:"batch_id"`
	WindowStart string           `json:"window_start"`
	WindowEnd   string           `json:"window_end"`
	Health      Health           `json:"health"`
	Metrics     []Metric         `json:"metrics"`
	Sites       []Site           `json:"sites"`
	VPN         []VPNObservation `json:"vpn"`
}
