// Package e2e holds the crown-jewel end-to-end tests (§38.3/§38.4): the
// REAL gateway binary, the REAL /usr/bin/ssh client, and either a fake
// Coder deployment + fake coder binary (CI-safe) or the live
// live deployment (build tag "live", requires CODER_LIVE_URL and CODER_LIVE_TOKEN).
//
// The fake path proves OpenSSH client compatibility: ProxyJump, the
// lower-level `ssh -W` stdio forward, the keyboard-interactive credential
// renewal cycle driven through a real PTY, and rapid preflight connection
// bursts within the configured limits (§39).
package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/testutil"
)

// testWorkspace is a strict bare Coder target used by the fake E2E path.
const testWorkspace = "dev"

// testCoderUserID is the Coder user UUID the fake control plane returns for
// every valid test token. The account binds to it on first token.
var testCoderUserID = uuid.MustParse("45454545-4545-4545-4545-454545454545")

var (
	gatewayBuildOnce sync.Once
	gatewayBuildPath string
	gatewayBuildErr  error
)

// buildGateway compiles the REAL gateway binary exactly once per test
// process into a shared temp dir, mirroring testutil.BuildFakeCoder.
// Maximal fidelity: the E2E exercises the shipped command surface, not an
// in-process approximation.
func buildGateway(t testing.TB) string {
	t.Helper()
	gatewayBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "coder-ssh-gateway-e2e")
		if err != nil {
			gatewayBuildErr = err
			return
		}
		out := filepath.Join(dir, "coder-ssh-gateway")
		_, src, _, ok := runtime.Caller(0)
		if !ok {
			gatewayBuildErr = errors.New("runtime.Caller failed")
			return
		}
		repoRoot := filepath.Clean(filepath.Join(filepath.Dir(src), "..", ".."))
		cmd := exec.Command("go", "build", "-o", out, "./cmd/coder-ssh-gateway/")
		cmd.Dir = repoRoot
		if combined, err := cmd.CombinedOutput(); err != nil {
			gatewayBuildErr = fmt.Errorf("go build gateway: %w\n%s", err, combined)
			return
		}
		gatewayBuildPath = out
	})
	if gatewayBuildErr != nil {
		t.Fatalf("buildGateway: %v", gatewayBuildErr)
	}
	return gatewayBuildPath
}

// requireOpenSSH skips the test when the real OpenSSH client is absent
// (§38.3: "run real OpenSSH in CI where practical" — where impractical, skip).
func requireOpenSSH(t testing.TB) string {
	t.Helper()
	path, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH client (ssh) not found on PATH; skipping E2E compatibility test")
	}
	return path
}

// fakeCoderAPI is a minimal Coder control-plane stub speaking HTTPS (config
// validation requires an HTTPS coder_url). Token -> response mapping is
// mutable so tests can expire a stored credential mid-run (renewal path).
type fakeCoderAPI struct {
	t      *testing.T
	srv    *httptest.Server
	caFile string
	mu     sync.Mutex
	tokens map[string]fakeTokenResponse // token -> canned /users/me reply
	calls  []string                     // tokens presented, in order (debugging)
}

type fakeTokenResponse struct {
	status   int
	id       uuid.UUID
	username string
}

func newFakeCoderAPI(t *testing.T) *fakeCoderAPI {
	t.Helper()
	f := &fakeCoderAPI{t: t, tokens: map[string]fakeTokenResponse{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.srv.Close)

	// Export the test server's CA as PEM so deployment.tls.ca_file can
	// trust it (the gateway builds its own RootCAs from this file).
	cert := f.srv.TLS.Certificates[0].Certificate[0]
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	f.caFile = filepath.Join(t.TempDir(), "coder-ca.pem")
	if err := os.WriteFile(f.caFile, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	return f
}

func (f *fakeCoderAPI) url() string { return f.srv.URL }

// setToken programs the /api/v2/users/me reply for a token. status 200
// carries the bound identity; anything else (401) carries no body identity.
func (f *fakeCoderAPI) setToken(token string, status int) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[token] = fakeTokenResponse{status: status, id: testCoderUserID, username: "e2e-user"}
}

func (f *fakeCoderAPI) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	token := r.Header.Get("Coder-Session-Token")
	f.calls = append(f.calls, fmt.Sprintf("%s %s token_len=%d", r.Method, r.URL.Path, len(token)))
	if r.URL.Path != "/api/v2/users/me" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	resp, ok := f.tokens[token]
	if !ok || resp.status != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"invalid session token"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":%q,"username":%q,"status":"active"}`, resp.id.String(), resp.username)
}

// callLog returns a redacted request log (token LENGTHS only) for evidence.
func (f *fakeCoderAPI) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// gatewayFixture boots the real gateway binary against the fake control
// plane with the fake coder binary as deployment.coder_binary.
type gatewayFixture struct {
	t        *testing.T
	bin      string
	stateDir string
	addr     string // 127.0.0.1:<port>
	host     string
	port     string
	coder    *fakeCoderAPI

	accountID uuid.UUID
	keyPath   string // private key, 0600
	pubPath   string

	cmd    *exec.Cmd
	logBuf *lockedBuffer

	knownHosts string
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newGatewayFixture runs the full operator enrollment flow through the real
// CLI: init -> (rewrite config) -> account add -> key add -> [credential set]
// -> serve. If initialToken is non-empty it must already be programmed into
// the fake API as valid; enrollment then exercises bind-on-first-token.
func newGatewayFixture(t *testing.T, initialToken string) *gatewayFixture {
	t.Helper()

	f := &gatewayFixture{
		t:        t,
		bin:      buildGateway(t),
		stateDir: t.TempDir(),
		coder:    newFakeCoderAPI(t),
		logBuf:   &lockedBuffer{},
	}

	// Pick a free port up front; serve binds it moments later.
	f.addr = reserveAddr(t)
	f.host, f.port = splitAddr(t, f.addr)

	if initialToken != "" {
		f.coder.setToken(initialToken, http.StatusOK)
	}

	// 1. init: state layout, host key, encryption key, starter config.
	f.runCLI(t, nil, "", "init", "coder.example.com")

	// 2. Rewrite the config: fake coder_url (HTTPS + custom CA), fake coder
	// binary, dynamic listen address, temp runtime dirs.
	f.writeConfig(t)

	// 3. Enroll the account (bind-on-first-token) and a test ed25519 key.
	out := f.runCLI(t, nil, "", "admin", "account", "add", "--label", "e2e test account", "--bind-on-first-token")
	f.accountID = parseAccountID(t, out)

	f.keyPath, f.pubPath = writeClientKey(t, t.TempDir(), generateKey(t))
	f.runCLI(t, nil, "", "admin", "key", "add", "--account", f.accountID.String(), "--file", f.pubPath, "--label", "e2e key")

	// 4. Optional: seed a credential through the real CLI path. The token
	// travels on stdin only — NEVER argv (§29).
	if initialToken != "" {
		f.runCLI(t, nil, initialToken+"\nyes\n", "admin", "credential", "set", "--account", f.accountID.String(), "--stdin")
	}

	// 5. Serve. Startup is async: poll the TCP port.
	f.startServe(t)

	// 6. Pre-populate known_hosts via ssh-keyscan so no host-key prompt can
	// ever block the client; accept-new remains as a fallback.
	f.knownHosts = f.scanKnownHosts(t)

	t.Cleanup(f.stop)
	return f
}

var accountIDRE = regexp.MustCompile(`account ([0-9a-f-]{36}) created`)

func parseAccountID(t *testing.T, cliOut string) uuid.UUID {
	t.Helper()
	m := accountIDRE.FindStringSubmatch(cliOut)
	if m == nil {
		t.Fatalf("could not parse account UUID from CLI output:\n%s", cliOut)
	}
	id, err := uuid.Parse(m[1])
	if err != nil {
		t.Fatalf("parse account UUID: %v", err)
	}
	return id
}

// generateKey returns a fresh ed25519 client key.
func generateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	return priv
}

// reserveAddr grabs a free loopback TCP address and releases it. The small
// bind race before serve starts is accepted; failure surfaces as a startup
// error with full gateway logs.
func reserveAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	return addr
}

func splitAddr(t *testing.T, addr string) (host, port string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr %q: %v", addr, err)
	}
	return host, port
}

// writeClientKey writes an OpenSSH private key (0600) and its .pub.
func writeClientKey(t *testing.T, dir string, priv ed25519.PrivateKey) (keyPath, pubPath string) {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(priv, "e2e client key")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	keyPath = filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	pubPath = keyPath + ".pub"
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return keyPath, pubPath
}

// runCLI invokes the gateway binary and requires exit 0. stdinData (may be
// "") is piped via a real pipe so tokens never appear in argv or the
// process environment.
func (f *gatewayFixture) runCLI(t *testing.T, env []string, stdinData string, args ...string) string {
	t.Helper()
	full := append([]string{"--state-dir", f.stateDir}, args...)
	cmd := exec.Command(f.bin, full...)
	if env != nil {
		cmd.Env = env
	}
	if stdinData != "" {
		cmd.Stdin = strings.NewReader(stdinData)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gateway %s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

// writeConfig replaces the init-generated starter config with the E2E
// fixture config. All paths absolute; secrets come from init's secrets/.
func (f *gatewayFixture) writeConfig(t *testing.T) {
	t.Helper()
	fakeBin := testutil.BuildFakeCoder(t)
	cfg := fmt.Sprintf(`version: 1

listen:
  address: %q
  handshake_timeout: 15s
  renewal_auth_timeout: 2m

ssh:
  transport_user: coder
  maintenance_user: auth

state:
  dir: %s

deployment:
  id: primary
  coder_url: %q
  coder_binary: %s
  coder_global_config: %s
  working_directory: %s
  autostart: true
  wait: auto
  workspace_connect_timeout: 30s
  token_validation_timeout: 10s
  token_validation_cache: 1s
  tls:
    ca_file: %s

observability:
  log_format: text
  log_level: debug
  metrics_address: "127.0.0.1:0"
  health_address: "127.0.0.1:0"
`, f.addr, f.stateDir, f.coder.url(), fakeBin,
		filepath.Join(f.stateDir, "coder-config"), filepath.Join(f.stateDir, "run"), f.coder.caFile)
	// Ephemeral observability ports only: the 9090/9091 defaults would
	// collide with any concurrently running gateway on this host.
	for _, fixed := range []string{"9090", "9091"} {
		if strings.Contains(cfg, fixed) {
			t.Fatalf("fixture config must not bind fixed observability port %s", fixed)
		}
	}
	if !strings.Contains(cfg, `metrics_address: "127.0.0.1:0"`) ||
		!strings.Contains(cfg, `health_address: "127.0.0.1:0"`) {
		t.Fatalf("fixture config must set ephemeral metrics/health addresses:\n%s", cfg)
	}
	if err := os.WriteFile(filepath.Join(f.stateDir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// init only created runtime dirs for the STARTER config paths; our
	// rewrite points at the same names under the state dir, which init did
	// create — but be defensive for future overrides.
	for _, d := range []string{"coder-config", "run"} {
		if err := os.MkdirAll(filepath.Join(f.stateDir, d), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
}

// startServe launches `gateway serve` in its own process group and waits
// for the SSH port to accept connections.
func (f *gatewayFixture) startServe(t *testing.T) {
	t.Helper()
	cmd := exec.Command(f.bin, "--state-dir", f.stateDir, "serve")
	cmd.Stdout = f.logBuf
	cmd.Stderr = f.logBuf
	// A minimal environment: the gateway must not depend on ambient HOME,
	// and the fake child asserts no poisoned variables pass through.
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + f.stateDir, "TMPDIR=" + os.TempDir()}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start serve: %v", err)
	}
	f.cmd = cmd

	deadline := time.Now().Add(15 * time.Second)
	for {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			t.Fatalf("gateway exited during startup:\n%s", f.logBuf.String())
		}
		conn, err := net.DialTimeout("tcp", f.addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway did not listen on %s within 15s:\n%s", f.addr, f.logBuf.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stop terminates the gateway (SIGTERM to the process group, then SIGKILL
// after a grace period) and waits for reaping. Registered via t.Cleanup.
func (f *gatewayFixture) stop() {
	t := f.t
	if f.cmd == nil || f.cmd.Process == nil {
		return
	}
	pgid := f.cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_ = f.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Errorf("gateway process %d did not exit after SIGKILL", pgid)
		}
	}
}

// pid returns the gateway process PID (also its process-group ID).
func (f *gatewayFixture) pid() int { return f.cmd.Process.Pid }

// childPIDs lists the gateway's direct children (pgrep -P). Used to assert
// no leftover `coder ssh --stdio` (or fake-coder) children survive closed
// connections (§39 "All child processes are reaped").
func (f *gatewayFixture) childPIDs() []string {
	out, err := exec.Command("pgrep", "-P", strconv.Itoa(f.pid())).Output()
	if err != nil { // pgrep exits 1 on no matches — the success case
		return nil
	}
	var pids []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			pids = append(pids, line)
		}
	}
	return pids
}

// waitNoChildren polls until the gateway has no direct children.
func (f *gatewayFixture) waitNoChildren(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		kids := f.childPIDs()
		if len(kids) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway still has children after %v: %v\nlogs:\n%s", d, kids, f.logBuf.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// scanKnownHosts runs ssh-keyscan against the gateway and writes the result
// to a temp known_hosts file. Falls back to an empty file (accept-new in
// sshCommonArgs covers first contact) when keyscan is unavailable.
func (f *gatewayFixture) scanKnownHosts(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	var out bytes.Buffer
	if keyscan, err := exec.LookPath("ssh-keyscan"); err == nil {
		cmd := exec.Command(keyscan, "-T", "5", "-p", f.port, f.host)
		cmd.Stdout = &out
		cmd.Stderr = io.Discard
		_ = cmd.Run() // best effort; empty file + accept-new still works
	}
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return path
}

// sshConfig writes a per-fixture ssh_config carrying every isolation
// option. -F is the one option OpenSSH's implicit ProxyJump command
// propagates to the jump subprocess (-o flags are NOT), so a config file
// is the only way to keep both hops out of ~/.ssh while using real -J.
//
// The gateway hop keeps strict accept-new host-key checking (the gateway
// host key IS an authentication boundary). The inner workspace target does
// not (§6.3: the inner host key is not an independent authentication
// boundary — the fake inner SSH generates an ephemeral key per connection,
// and real workspace identity is anchored by the Coder control plane).
func (f *gatewayFixture) sshConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh_config")
	// ssh_config keyword semantics are first-value-wins: the inner-target
	// block must precede Host * or its UserKnownHostsFile is never read.
	content := fmt.Sprintf(`Host *
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
  IdentitiesOnly yes
  IdentityFile %s
  LogLevel ERROR
  ConnectTimeout 10
`, f.keyPath)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}
	return path
}

// sshCommonArgs returns the config-file argument every OpenSSH invocation
// shares. Extra -o flags appended by callers apply to the main connection.
func (f *gatewayFixture) sshCommonArgs(t *testing.T) []string {
	t.Helper()
	return []string{"-F", f.sshConfig(t)}
}

// jumpSpec is the ProxyJump target: transport user at the gateway address.
func (f *gatewayFixture) jumpSpec() string {
	return "coder@" + f.host + ":" + f.port
}

// runSSH executes the real OpenSSH client and returns stdout, stderr, and
// the exit code. It never fails the test — assertions belong to callers.
// E2E_SSH_VERBOSE=1 in the environment adds -v for failure diagnosis.
func runSSH(ctx context.Context, args ...string) (stdout, stderr string, exitCode int) {
	if os.Getenv("E2E_SSH_VERBOSE") != "" {
		args = append([]string{"-v"}, args...)
	}
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	switch {
	case err == nil:
		exitCode = 0
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// proxyJumpExec runs `ssh -J <gateway> coder@<workspace> <command...>` and
// returns the captured streams.
func (f *gatewayFixture) proxyJumpExec(t *testing.T, ctx context.Context, workspace string, command string) (stdout, stderr string, exitCode int) {
	t.Helper()
	return f.proxyJumpExecOpts(t, ctx, workspace, command)
}

// proxyJumpExecOpts is proxyJumpExec with extra per-invocation -o options
// (command-line options win over the fixture ssh_config: first-value-wins).
func (f *gatewayFixture) proxyJumpExecOpts(t *testing.T, ctx context.Context, workspace string, command string, extraOpts ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	args := f.sshCommonArgs(t)
	for _, o := range extraOpts {
		args = append(args, "-o", o)
	}
	args = append(args,
		"-J", f.jumpSpec(),
		"coder@"+workspace,
		command,
	)
	return runSSH(ctx, args...)
}
