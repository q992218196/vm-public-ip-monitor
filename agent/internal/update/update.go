package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"vm-monitor/agent/internal/config"
)

const maxBinaryBytes = 50 << 20

var versionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$`)

type instruction struct {
	Update  bool   `json:"update"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Path    string `json:"path"`
}

type httpError struct {
	stage  string
	status int
}

func (e httpError) Error() string { return fmt.Sprintf("update %s HTTP %d", e.stage, e.status) }

// Network failures retry promptly; invalid binaries retain a longer cooldown.
func RetryDelay(err error, failures int) time.Duration {
	var network net.Error
	var status httpError
	transient := errors.As(err, &network) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
	if errors.As(err, &status) {
		transient = status.status == 429 || status.status >= 500
	}
	if !transient {
		return 10 * time.Minute
	}
	return time.Duration(1<<min(max(failures-1, 0), 3)) * 15 * time.Second
}

func CheckAndApply(ctx context.Context, c config.Config, currentVersion string) (bool, error) {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 10 * time.Second, FallbackDelay: 300 * time.Millisecond}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, IdleConnTimeout: 15 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := strings.TrimRight(c.ServerURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/agent/update?version="+url.QueryEscape(currentVersion), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Node-ID", c.NodeID)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false, httpError{stage: "control", status: res.StatusCode}
	}
	var inst instruction
	if err := json.NewDecoder(io.LimitReader(res.Body, 2048)).Decode(&inst); err != nil {
		return false, fmt.Errorf("update control response: %w", err)
	}
	if !inst.Update {
		return false, nil
	}
	if !versionPattern.MatchString(inst.Version) || len(inst.SHA256) != 64 || inst.Path != "/downloads/vm-agent-linux-amd64" {
		return false, errors.New("invalid update instruction")
	}
	want, err := hex.DecodeString(inst.SHA256)
	if err != nil || len(want) != sha256.Size {
		return false, errors.New("invalid update digest")
	}

	dir := filepath.Join(c.DataDir, "bin")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return false, err
	}
	f, err := os.CreateTemp(dir, ".vm-agent-update-*")
	if err != nil {
		return false, err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	download, err := http.NewRequestWithContext(ctx, http.MethodGet, base+inst.Path, nil)
	if err != nil {
		f.Close()
		return false, err
	}
	downloadClient := *client
	downloadClient.Timeout = 3 * time.Minute
	response, err := downloadClient.Do(download)
	if err != nil {
		f.Close()
		return false, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		f.Close()
		return false, httpError{stage: "download", status: response.StatusCode}
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(response.Body, maxBinaryBytes+1))
	response.Body.Close()
	if syncErr := f.Sync(); copyErr == nil {
		copyErr = syncErr
	}
	if closeErr := f.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return false, copyErr
	}
	if n == 0 || n > maxBinaryBytes || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), hex.EncodeToString(want)) {
		return false, errors.New("update size or SHA-256 mismatch")
	}
	if err := os.Chmod(tmp, 0700); err != nil {
		return false, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	check := exec.CommandContext(checkCtx, tmp, "-config", filepath.Join(c.DataDir, "config", "agent.json"), "-check")
	if output, err := check.CombinedOutput(); err != nil {
		return false, fmt.Errorf("update self-check failed: %v: %s", err, strings.TrimSpace(string(output)))
	}
	versionCmd := exec.CommandContext(checkCtx, tmp, "-version")
	output, err := versionCmd.Output()
	if err != nil || strings.TrimSpace(string(output)) != inst.Version {
		return false, errors.New("downloaded Agent version does not match instruction")
	}
	current := filepath.Join(dir, "vm-agent")
	previous := filepath.Join(dir, "vm-agent.previous")
	if err := os.Remove(previous); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := os.Rename(current, previous); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, current); err != nil {
		if rollbackErr := os.Rename(previous, current); rollbackErr != nil {
			return false, fmt.Errorf("install failed: %v; rollback failed: %w", err, rollbackErr)
		}
		return false, err
	}
	return true, nil
}
