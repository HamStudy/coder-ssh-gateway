//go:build live

// Live example.test integration suite (§38.4 subset). These tests NEVER
// run in CI: they require the CODER_LIVE_TOKEN environment variable holding
// a real Coder session token. The token is read from the environment at
// runtime and passed to the gateway exclusively via stdin pipes — it is
// never written to a file, never placed in argv, and never logged.
//
// Run with:
//
//	CODER_LIVE_TOKEN=<token> go test -tags live -v ./test/e2e/ -run TestLive -count=1
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	liveCoderURL    = "https://example.test"
	liveCoderBinary = "/usr/local/bin/coder"
)

// liveToken reads the session token from the environment or skips. The
// value is NEVER persisted: enrollment pipes it to `admin credential set
// --stdin`, and API probes send it in an in-memory request header only.
func liveToken(t *testing.T) string {
	t.Helper()
	token := os.Getenv("CODER_LIVE_TOKEN")
	if token == "" {
		t.Skip("CODER_LIVE_TOKEN not set; skipping live example.test test")
	}
	return token
}

// liveFixture boots the real gateway against the real deployment: real
// coder_url, real coder binary, real target suffix. Enrollment happens
// through the real CLI with the env token piped to stdin.
func liveFixture(t *testing.T, token string) *gatewayFixture {
	t.Helper()
	if _, err := os.Stat(liveCoderBinary); err != nil {
		t.Skipf("coder binary not at %s: %v", liveCoderBinary, err)
	}

	f := &gatewayFixture{
		t:        t,
		bin:      buildGateway(t),
		stateDir: t.TempDir(),
		logBuf:   &lockedBuffer{},
	}

	f.runCLI(t, nil, "", "init")
	writeLiveConfig(t, f)

	out := f.runCLI(t, nil, "", "admin", "account", "add", "--label", "live e2e", "--bind-on-first-token")
	f.accountID = parseAccountID(t, out)

	f.keyPath, f.pubPath = writeClientKey(t, t.TempDir(), generateKey(t))
	f.runCLI(t, nil, "", "admin", "key", "add", "--account", f.accountID.String(), "--file", f.pubPath, "--label", "live e2e key")

	// Token to stdin ONLY, followed by the bind confirmation line.
	f.runCLI(t, nil, token+"\nyes\n", "admin", "credential", "set", "--account", f.accountID.String(), "--stdin")

	f.startServe(t)
	f.knownHosts = f.scanKnownHosts(t)
	t.Cleanup(f.stop)
	return f
}

// writeLiveConfig writes the live-deployment config over init's starter:
// production coder_url/binary/suffix, dynamic loopback listen address.
func writeLiveConfig(t *testing.T, f *gatewayFixture) {
	t.Helper()
	lnAddr := reserveAddr(t)
	f.host, f.port = splitAddr(t, lnAddr)
	f.addr = lnAddr

	cfg := fmt.Sprintf(`version: 1

listen:
  address: %q
  handshake_timeout: 15s
  renewal_auth_timeout: 5m

ssh:
  transport_user: coder
  maintenance_user: auth

state:
  dir: %s

deployment:
  id: primary
  coder_url: %s
  target_suffix: coder-gateway.example.com
  coder_binary: %s
  coder_global_config: %s
  working_directory: %s
  autostart: true
  wait: auto
  workspace_connect_timeout: 5m
  token_validation_timeout: 15s
  token_validation_cache: 5s

observability:
  log_format: text
  log_level: info
`, f.addr, f.stateDir, liveCoderURL, liveCoderBinary,
		filepath.Join(f.stateDir, "coder-config"), filepath.Join(f.stateDir, "run"))
	if err := os.WriteFile(filepath.Join(f.stateDir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write live config: %v", err)
	}
	for _, d := range []string{"coder-config", "run"} {
		if err := os.MkdirAll(filepath.Join(f.stateDir, d), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
}

// TestLiveProxyJumpStarted connects through the gateway to a workspace that
// is expected to be running (§38.4 "running" state, "exec" feature).
func TestLiveProxyJumpStarted(t *testing.T) {
	requireOpenSSH(t)
	token := liveToken(t)
	f := liveFixture(t, token)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	stdout, stderr, code := f.proxyJumpExec(t, ctx, "examtools-docs.coder-gateway.example.com", "printf hello")
	if code != 0 {
		t.Fatalf("live ProxyJump exit %d\nstdout: %q\nstderr: %q\ngateway logs:\n%s",
			code, stdout, stderr, f.logBuf.String())
	}
	if stdout != "hello" {
		t.Fatalf("stdout = %q, want exactly %q", stdout, "hello")
	}
	assertNoLeftoverChildren(t, f)
}

// TestLiveAutostartStopped connects to a workspace that starts out Stopped
// and lets the coder CLI autostart it (§38.4 "stopped with autostart";
// §39 "A stopped workspace can autostart when configured"). Afterwards the
// workspace is returned to its found state: if WE started it, we stop it.
func TestLiveAutostartStopped(t *testing.T) {
	requireOpenSSH(t)
	token := liveToken(t)
	f := liveFixture(t, token)

	wasRunning := liveWorkspaceRunning(t, token, "general")
	startedByUs := false
	if !wasRunning {
		startedByUs = true // conservative: stop it again unless it was clearly running
	}
	t.Cleanup(func() {
		if startedByUs {
			liveStopWorkspace(t, token, "general")
		}
	})

	// Autostart may take minutes: allow the full workspace_connect_timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	stdout, stderr, code := f.proxyJumpExec(t, ctx, "general.coder-gateway.example.com", "printf hello")
	if code != 0 {
		t.Fatalf("live autostart ProxyJump exit %d\nstdout: %q\nstderr: %q\ngateway logs:\n%s",
			code, stdout, stderr, f.logBuf.String())
	}
	if stdout != "hello" {
		t.Fatalf("stdout = %q, want exactly %q", stdout, "hello")
	}
	assertNoLeftoverChildren(t, f)
}

// assertNoLeftoverChildren verifies the gateway reaped every `coder ssh
// --stdio` child after the connections closed (§39).
func assertNoLeftoverChildren(t *testing.T, f *gatewayFixture) {
	t.Helper()
	f.waitNoChildren(t, 15*time.Second)
}

// liveWorkspaceRunning probes the real Coder API for the workspace's latest
// build status. The token lives only in the request header. Any probe
// failure conservatively reports "running" so cleanup never stops a
// workspace the test did not start.
func liveWorkspaceRunning(t *testing.T, token, workspace string) bool {
	t.Helper()
	me, err := liveAPIGet(t, token, "/api/v2/users/me")
	if err != nil {
		t.Logf("live probe /users/me failed (%v); assuming workspace running", err)
		return true
	}
	username, _ := me["username"].(string)
	if username == "" {
		t.Log("live probe: no username in /users/me; assuming workspace running")
		return true
	}
	ws, err := liveAPIGet(t, token, "/api/v2/users/"+username+"/workspace/"+workspace)
	if err != nil {
		t.Logf("live probe workspace %q failed (%v); assuming running", workspace, err)
		return true
	}
	build, _ := ws["latest_build"].(map[string]any)
	status, _ := build["status"].(string)
	t.Logf("workspace %q latest_build.status = %q", workspace, status)
	return status == "running"
}

// liveAPIGet performs one authenticated GET against example.test and
// returns the decoded JSON object.
func liveAPIGet(t *testing.T, token, path string) (map[string]any, error) {
	t.Helper()
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(liveCoderURL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Coder-Session-Token", token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// liveStopWorkspace returns a workspace to Stopped via the real coder CLI.
// The token is passed through the process environment of the child only —
// never argv (§18.3 parity) — and the child is the trusted official binary.
func liveStopWorkspace(t *testing.T, token, workspace string) {
	t.Helper()
	cmd := exec.Command(liveCoderBinary, "stop", "--yes", workspace)
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + t.TempDir(),
		"CODER_URL=" + liveCoderURL,
		"CODER_SESSION_TOKEN=" + token,
		"CODER_NO_VERSION_WARNING=true",
		"CODER_NO_FEATURE_WARNING=true",
		"CODER_DISABLE_NETWORK_TELEMETRY=true",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("cleanup: coder stop %s failed: %v\n%s", workspace, err, out)
		return
	}
	t.Logf("cleanup: stopped workspace %q (started by this test)", workspace)
}
