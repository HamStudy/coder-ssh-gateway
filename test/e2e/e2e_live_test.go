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
//
// Ordering is deliberate: the initial status is captured and the
// stop-if-we-started cleanup registered BEFORE any connect attempt, so a
// mid-test failure (e.g. banner timeout against a cold-starting agent)
// still restores the workspace.
func TestLiveAutostartStopped(t *testing.T) {
	requireOpenSSH(t)
	token := liveToken(t)

	// 1. Capture initial state FIRST.
	status, healthy := liveWorkspaceState(t, token, "general")
	startedByUs := status != "running" // conservative: anything not clearly running gets stopped again

	// 2. Register cleanup BEFORE the fixture and any connect attempt; it
	// must fire even when the test fails midway.
	t.Cleanup(func() {
		if startedByUs {
			liveStopWorkspace(t, token, "general")
		}
	})

	f := liveFixture(t, token)

	// 3. A workspace that is running but whose agent is still bootstrapping
	// (left over from a previous interrupted run, for example) is not
	// connectable yet: wait for agent health before touching ssh.
	if status == "running" && !healthy {
		liveWaitHealthy(t, token, "general", 3*time.Minute)
	}

	// 4. Autostart may take minutes. The ssh_config ConnectTimeout (10s)
	// also bounds the INNER banner exchange, and `coder ssh --wait=auto`
	// emits nothing on stdout while the agent boots — a tight timeout kills
	// the connection mid-start. Give this invocation a 5m banner budget and
	// a 6m overall context (>= workspace_connect_timeout).
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	stdout, stderr, code := f.proxyJumpExecOpts(t, ctx, "general.coder-gateway.example.com", "printf hello",
		"ConnectTimeout=300")
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

// liveWorkspaceState probes the real Coder API for the workspace's latest
// build status and agent health. The token lives only in the request
// header. Any probe failure conservatively reports "running"/healthy so
// cleanup never stops a workspace the test did not start.
func liveWorkspaceState(t *testing.T, token, workspace string) (status string, healthy bool) {
	t.Helper()
	ws, err := liveGetWorkspace(t, token, workspace)
	if err != nil {
		t.Logf("live probe workspace %q failed (%v); assuming running+healthy", workspace, err)
		return "running", true
	}
	return workspaceState(ws)
}

// workspaceState extracts (latest_build.status, agents-healthy) from a
// decoded Coder workspace object. Health is version-tolerant: an agent
// counts healthy when its health.healthy flag is true, or — on deployments
// without the health object — when it is connected and past the starting
// lifecycle state.
func workspaceState(ws map[string]any) (string, bool) {
	build, _ := ws["latest_build"].(map[string]any)
	status, _ := build["status"].(string)
	if status != "running" {
		return status, false
	}
	agents := collectAgents(build)
	if len(agents) == 0 {
		return status, false // running build with no agents yet: still bootstrapping
	}
	for _, a := range agents {
		if health, ok := a["health"].(map[string]any); ok {
			if h, _ := health["healthy"].(bool); !h {
				return status, false
			}
			continue
		}
		agentStatus, _ := a["status"].(string)
		lifecycle, _ := a["lifecycle_state"].(string)
		if agentStatus != "connected" || (lifecycle != "" && lifecycle != "ready") {
			return status, false
		}
	}
	return status, true
}

// collectAgents flattens latest_build.resources[].agents[] across resources.
func collectAgents(build map[string]any) []map[string]any {
	var out []map[string]any
	resources, _ := build["resources"].([]any)
	for _, r := range resources {
		res, _ := r.(map[string]any)
		agents, _ := res["agents"].([]any)
		for _, a := range agents {
			if agent, ok := a.(map[string]any); ok {
				out = append(out, agent)
			}
		}
	}
	return out
}

// liveWaitHealthy polls the workspace until its build is running and every
// agent reports healthy, bounded by timeout.
func liveWaitHealthy(t *testing.T, token, workspace string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ws, err := liveGetWorkspace(t, token, workspace)
		if err == nil {
			status, healthy := workspaceState(ws)
			if status == "running" && healthy {
				t.Logf("workspace %q running and healthy", workspace)
				return
			}
			t.Logf("workspace %q status=%q healthy=%t; waiting", workspace, status, healthy)
		} else {
			t.Logf("workspace %q probe error (retrying): %v", workspace, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("workspace %q not healthy within %v", workspace, timeout)
		}
		time.Sleep(5 * time.Second)
	}
}

// liveGetWorkspace resolves the caller's username, then fetches the named
// workspace object.
func liveGetWorkspace(t *testing.T, token, workspace string) (map[string]any, error) {
	t.Helper()
	me, err := liveAPIGet(t, token, "/api/v2/users/me")
	if err != nil {
		return nil, fmt.Errorf("users/me: %w", err)
	}
	username, _ := me["username"].(string)
	if username == "" {
		return nil, fmt.Errorf("users/me: no username in reply")
	}
	return liveAPIGet(t, token, "/api/v2/users/"+username+"/workspace/"+workspace)
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

// liveStopWorkspace returns a workspace to Stopped via the real coder CLI,
// then VERIFIES the end state through the API: a stop issued while the
// workspace is still autostarting can lose the race against the in-flight
// build, so the stop is retried until the latest build reports stopped
// (bounded). The token is passed through the process environment of the
// child only — never argv (§18.3 parity).
func liveStopWorkspace(t *testing.T, token, workspace string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	stopped := false
	for attempt := 1; ; attempt++ {
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
			t.Logf("cleanup: coder stop %s (attempt %d): %v\n%s", workspace, attempt, err, out)
		}
		if ws, err := liveGetWorkspace(t, token, workspace); err == nil {
			if status, _ := workspaceState(ws); status == "stopped" {
				stopped = true
				break
			} else {
				t.Logf("cleanup: workspace %q status=%q after stop attempt %d; waiting", workspace, status, attempt)
			}
		} else {
			t.Logf("cleanup: status probe after stop attempt %d failed: %v", attempt, err)
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if !stopped {
		t.Errorf("cleanup: workspace %q did not reach stopped within budget; manual `coder stop %s` required", workspace, workspace)
		return
	}
	t.Logf("cleanup: workspace %q confirmed stopped", workspace)
}
