package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"vm-monitor/agent/internal/config"
)

func TestUpdateOnlyUsesFixedDownloadAndVerifiesDigest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		control string
		fetch   bool
	}{
		{"no update", `{"update":false}`, false},
		{"external path", `{"update":true,"version":"0.4.0","sha256":"` + strings.Repeat("a", 64) + `","path":"https://evil.example/agent"}`, false},
		{"wrong digest", `{"update":true,"version":"0.4.0","sha256":"` + strings.Repeat("a", 64) + `","path":"/downloads/vm-agent-linux-amd64"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetches := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/agent/update" {
					if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Node-ID") != "node-1" {
						t.Error("missing authentication")
					}
					w.Write([]byte(tc.control))
					return
				}
				fetches++
				w.Write([]byte("incorrect binary"))
			}))
			defer server.Close()
			root := t.TempDir()
			dir := filepath.Join(root, "bin")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			current := filepath.Join(dir, "vm-agent")
			if err := os.WriteFile(current, []byte("original"), 0700); err != nil {
				t.Fatal(err)
			}
			applied, err := CheckAndApply(context.Background(), config.Config{ServerURL: server.URL, Token: "secret", NodeID: "node-1", DataDir: root}, "0.3.0")
			if applied || (err == nil) != (tc.name == "no update") {
				t.Fatalf("applied=%v err=%v", applied, err)
			}
			if (fetches != 0) != tc.fetch {
				t.Fatalf("unexpected downloads: %d", fetches)
			}
			data, err := os.ReadFile(current)
			if err != nil || string(data) != "original" {
				t.Fatalf("installed Agent was modified: %q, %v", data, err)
			}
		})
	}
}
