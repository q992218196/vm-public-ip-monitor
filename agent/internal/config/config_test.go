package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSampleConfigAndResourceValidation(t *testing.T) {
	raw, err := os.ReadFile("../../config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	// Test the shipped file with an OS-appropriate absolute path.
	path := filepath.Join(t.TempDir(), "agent.json")
	s := strings.ReplaceAll(string(raw), "/home/vm-monitor", filepath.ToSlash(t.TempDir()))
	s = strings.ReplaceAll(s, "replace-with-node-token", strings.Repeat("a", 64))
	os.WriteFile(path, []byte(s), 0600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.MemoryHardMiB != 4096 {
		t.Fatal("wrong default")
	}
	c.MemoryHardMiB = 128
	if c.Validate() == nil {
		t.Fatal("hard limit below work budget accepted")
	}
	c.MemoryHardMiB = 4096
	c.ServerURL = "http://example.com"
	if c.Validate() == nil {
		t.Fatal("plaintext remote API accepted")
	}
	c.ServerURL = "https://example.com"
	c.CIDRs = []string{"2001:db8::/129"}
	if c.Validate() == nil {
		t.Fatal("invalid IPv6 prefix accepted")
	}
}
