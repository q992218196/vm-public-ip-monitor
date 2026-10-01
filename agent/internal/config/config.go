package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
)

type Config struct {
	NodeID              string   `json:"node_id"`
	ServerURL           string   `json:"server_url"`
	Token               string   `json:"token"`
	Interfaces          []string `json:"interfaces"`
	CIDRs               []string `json:"cidrs"`
	DataDir             string   `json:"data_dir"`
	MemorySoftMiB       int64    `json:"memory_soft_mib"`
	MemoryHardMiB       int64    `json:"memory_hard_mib"`
	DiskLimitMiB        int64    `json:"disk_limit_mib"`
	SpoolLimitMiB       int64    `json:"spool_limit_mib"`
	CaptureBufferMiB    int      `json:"capture_buffer_mib"`
	FlushSeconds        int      `json:"flush_seconds"`
	MaxIPs              int      `json:"max_ips"`
	MaxFlows            int      `json:"max_flows"`
	MaxReassembly       int      `json:"max_reassembly"`
	MaxSites            int      `json:"max_sites"`
	AllowHTTPLocalhost  bool     `json:"allow_http_localhost"`
	EvidenceEnabled     bool     `json:"evidence_enabled"`
	EvidenceLimitMiB    int64    `json:"evidence_limit_mib"`
	EvidenceKeepHours   int      `json:"evidence_keep_hours"`
	EvidenceUploadKiBps int      `json:"evidence_upload_kibps"`
}

func Load(path string) (Config, error) {
	c := Config{MemorySoftMiB: 2048, MemoryHardMiB: 4096, DiskLimitMiB: 2048, SpoolLimitMiB: 512, CaptureBufferMiB: 16, FlushSeconds: 30, MaxIPs: 4096, MaxFlows: 50000, MaxReassembly: 2048, MaxSites: 4096, EvidenceEnabled: true, EvidenceKeepHours: 24, EvidenceUploadKiBps: 2048}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if c.EvidenceLimitMiB == 0 {
		c.EvidenceLimitMiB = min(512, max(0, c.DiskLimitMiB-c.SpoolLimitMiB-128))
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.EvidenceLimitMiB < 0 || c.EvidenceLimitMiB > 4096 || c.EvidenceLimitMiB+c.SpoolLimitMiB+128 > c.DiskLimitMiB || c.EvidenceKeepHours < 1 || c.EvidenceKeepHours > 168 || c.EvidenceUploadKiBps < 128 || c.EvidenceUploadKiBps > 4096 {
		return errors.New("invalid evidence disk, retention or upload limits")
	}
	if c.MemoryHardMiB < c.MemorySoftMiB+128 || c.MemoryHardMiB > 65536 {
		return errors.New("memory_hard_mib must exceed work budget by at least 128 MiB")
	}
	if c.NodeID == "" || len(c.Token) < 32 {
		return errors.New("node_id and token (at least 32 characters) are required")
	}
	u, e := url.Parse(c.ServerURL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("server_url must be an HTTPS origin")
	}
	if u.Scheme != "https" {
		a, err := netip.ParseAddr(u.Hostname())
		if !(c.AllowHTTPLocalhost && u.Scheme == "http" && err == nil && a.IsLoopback()) {
			return errors.New("HTTPS required; HTTP only allowed for explicit loopback development")
		}
	}
	if !filepath.IsAbs(c.DataDir) {
		return errors.New("data_dir must be absolute")
	}
	if len(c.Interfaces) < 1 || len(c.Interfaces) > 8 || len(c.CIDRs) < 1 || len(c.CIDRs) > 256 {
		return errors.New("configure 1..8 capture interfaces and 1..256 CIDRs")
	}
	seen := map[string]bool{}
	for _, s := range c.Interfaces {
		if s == "" || s == "any" || seen[s] {
			return errors.New("interfaces must be explicit, nonempty and unique")
		}
		seen[s] = true
	}
	for _, s := range c.CIDRs {
		if _, e := netip.ParsePrefix(s); e != nil {
			return fmt.Errorf("invalid CIDR %q", s)
		}
	}
	if c.MemorySoftMiB < 128 || c.MemorySoftMiB > 32768 || c.SpoolLimitMiB < 1 || c.DiskLimitMiB < c.SpoolLimitMiB+128 || c.DiskLimitMiB > 1048576 {
		return errors.New("invalid memory/disk budget; reserve at least 128 MiB above spool limit")
	}
	if c.FlushSeconds < 10 || c.FlushSeconds > 300 || c.CaptureBufferMiB < 1 || c.CaptureBufferMiB > 64 || c.MaxIPs < 1 || c.MaxIPs > 8192 || c.MaxFlows < 100 || c.MaxFlows > 200000 || c.MaxReassembly < 1 || c.MaxReassembly > 4096 || c.MaxSites < 1 || c.MaxSites > 4096 {
		return errors.New("capture/state limits outside supported bounds")
	}
	// Fixed bounds are deliberately conservative; maps and the Go heap need spare space.
	estimate := int64(c.MaxIPs)*131072 + int64(c.MaxFlows)*256 + int64(c.MaxReassembly)*20000 + int64(c.MaxSites)*1024 + 2048*512 + int64(min(c.MaxFlows, 16384))*256 + int64(len(c.Interfaces)*c.CaptureBufferMiB)*2*1024*1024 + 8*1024*1024
	if estimate > c.MemorySoftMiB*1024*1024/2 {
		return fmt.Errorf("state limits require a larger memory budget or smaller max_* values (estimated state %d MiB)", estimate/1024/1024)
	}
	return nil
}
