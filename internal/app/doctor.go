package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/coderapi"
	"github.com/HamStudy/coder-ssh-gateway/internal/config"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/route"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
	"github.com/HamStudy/coder-ssh-gateway/internal/server"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
	"github.com/HamStudy/coder-ssh-gateway/internal/tunnel"
)

const (
	statusPass = "PASS"
	statusWarn = "WARN"
	statusFail = "FAIL"
)

// doctorReport accumulates §29.1 check results. Local misconfiguration is a
// FAIL; unreachable remote services are WARN (fail-soft, §28.1 spirit) —
// WARN never affects the exit code.
type doctorReport struct {
	c        *cli
	failures int
}

func (r *doctorReport) emit(name, status, format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	fmt.Fprintf(r.c.stdout, "%-4s %s: %s\n", status, name, line)
	if status == statusFail {
		r.failures++
	}
}

// cmdDoctor runs every §29.1 check and prints PASS/WARN/FAIL lines plus a
// summary. Exit 1 when any check FAILs. Tokens are never printed.
func (c *cli) cmdDoctor(args []string) int {
	fs := c.newFlagSet("doctor")
	accountID := fs.String("account", "", "also validate the stored credential of this account UUID against Coder")
	probeWorkspace := fs.String("probe-workspace", "", "run a real 'coder ssh --stdio' probe to this workspace (live-only)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	r := &doctorReport{c: c}

	path := c.configPath
	if path == "" && c.stateDir != "" {
		path = config.DefaultConfigPath(c.stateDir)
	}
	cfg, err := config.Parse(path)
	if err != nil {
		r.emit("config-parse", statusFail, "%v", err)
		fmt.Fprintln(c.stdout, "summary: cannot continue without a parseable config")
		return exitError
	}
	config.ApplyStateDir(cfg, c.stateDir)
	r.emit("config-parse", statusPass, "%s", path)

	r.checkStateDir(cfg)
	r.checkEncryptionKey(cfg)
	r.checkHostKeys(cfg)
	serverVersion := r.checkCoderReachability(cfg)
	r.checkCoderBinary(cfg, serverVersion)
	r.checkWritableDirs(cfg)
	r.checkProcessLimits()

	var probeToken []byte
	if *accountID != "" {
		probeToken = r.checkAccountCredential(cfg, *accountID)
		defer secretbox.BestEffortWipe(probeToken)
	}
	if *probeWorkspace != "" {
		r.checkWorkspaceProbe(cfg, *probeWorkspace, *accountID, probeToken)
	}

	fmt.Fprintf(c.stdout, "summary: %d FAIL\n", r.failures)
	if r.failures > 0 {
		return exitError
	}
	return exitOK
}

// checkStateDir covers §29.1 "database access and migration state" adapted
// to the flat-file store: directory access, VERSION marker, flock
// acquirability.
func (r *doctorReport) checkStateDir(cfg *config.Config) {
	const name = "state-dir"
	dir := cfg.State.Dir
	if dir == "" {
		r.emit(name, statusFail, "no state directory (pass --state-dir or set state.dir)")
		return
	}
	fi, err := os.Stat(dir)
	switch {
	case err != nil:
		r.emit(name, statusFail, "%s: %v", dir, err)
		return
	case !fi.IsDir():
		r.emit(name, statusFail, "%s is not a directory", dir)
		return
	}
	verBytes, err := os.ReadFile(dir + "/VERSION")
	switch {
	case errors.Is(err, os.ErrNotExist):
		r.emit(name, statusWarn, "VERSION marker missing; run 'coder-ssh-gateway init'")
		return
	case err != nil:
		r.emit(name, statusFail, "reading VERSION: %v", err)
		return
	case strings.TrimSpace(string(verBytes)) != "1":
		r.emit(name, statusFail, "unsupported store version %q", strings.TrimSpace(string(verBytes)))
		return
	}
	st, err := store.Open(dir)
	if err != nil {
		if errors.Is(err, store.ErrStoreLocked) {
			r.emit(name, statusFail, "state directory is locked by another process (is 'serve' running?)")
			return
		}
		r.emit(name, statusFail, "opening store: %v", err)
		return
	}
	if err := st.Close(); err != nil {
		r.emit(name, statusWarn, "closing store: %v", err)
		return
	}
	r.emit(name, statusPass, "%s accessible, VERSION=1", dir)
}

// checkEncryptionKey covers §29.1 "encryption key availability" plus the
// decrypt/encrypt self-test (seal+open round-trip of a marker).
func (r *doctorReport) checkEncryptionKey(cfg *config.Config) {
	const name = "encryption-key"
	if len(cfg.Encryption.Keys) == 0 || cfg.Encryption.ActiveKeyID == "" {
		r.emit(name, statusFail, "no encryption keys configured")
		return
	}
	kp := KeyProviderFromConfig(cfg, nil)
	keyID, key, err := kp.ActiveKey(context.Background())
	if err != nil {
		r.emit(name, statusFail, "active key %q unavailable: %v", cfg.Encryption.ActiveKeyID, err)
		return
	}
	marker := []byte("coder-ssh-gateway doctor self-test marker")
	nonce, ct, err := secretbox.Seal(keyID, key, marker, nil)
	if err != nil {
		r.emit(name, statusFail, "seal self-test: %v", err)
		return
	}
	pt, err := secretbox.Open(keyID, key, nonce, ct, nil)
	if err != nil || string(pt) != string(marker) {
		r.emit(name, statusFail, "round-trip self-test failed: %v", err)
		return
	}
	r.emit(name, statusPass, "active key %q loads and round-trips", keyID)
}

// checkHostKeys covers §29.1 "host-key loading and fingerprints" (§30).
func (r *doctorReport) checkHostKeys(cfg *config.Config) {
	const name = "host-key"
	if len(cfg.SSH.HostKeys) == 0 {
		r.emit(name, statusFail, "no host keys configured")
		return
	}
	signers, fps, err := server.LoadHostSigners(cfg.SSH.HostKeys)
	if err != nil {
		r.emit(name, statusFail, "%v", err)
		return
	}
	r.emit(name, statusPass, "%d key(s) loaded: %s", len(signers), strings.Join(fps, ", "))
}

// checkCoderReachability covers §29.1 "Coder URL TLS validation" and
// "/api/v2/buildinfo reachability". Both are remote checks: failures are
// WARN, never FAIL. Returns the server version string when known.
func (r *doctorReport) checkCoderReachability(cfg *config.Config) (serverVersion string) {
	u, err := url.Parse(cfg.Deployment.CoderURL)
	if cfg.Deployment.CoderURL == "" || err != nil || u.Host == "" {
		r.emit("coder-tls", statusFail, "deployment.coder_url %q is not a valid URL", cfg.Deployment.CoderURL)
		return ""
	}
	vopts, err := VerifierOptionsFromConfig(cfg)
	if err != nil {
		r.emit("coder-tls", statusFail, "%v", err)
		return ""
	}

	if u.Scheme != "https" {
		r.emit("coder-tls", statusWarn, "coder_url scheme %q is not https; TLS validation skipped (https is required at startup)", u.Scheme)
	} else {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		tlsCfg := &tls.Config{RootCAs: vopts.RootCAs, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
		conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(u.Hostname(), port), tlsCfg)
		if err != nil {
			r.emit("coder-tls", statusWarn, "TLS dial %s: %v", u.Host, err)
		} else {
			_ = conn.Close()
			r.emit("coder-tls", statusPass, "TLS handshake with %s ok", u.Host)
		}
	}

	httpClient, err := coderapi.NewHTTPClient(vopts)
	if err != nil {
		r.emit("coder-buildinfo", statusWarn, "building HTTP client: %v", err)
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.JoinPath("/api/v2/buildinfo").String(), nil)
	if err != nil {
		r.emit("coder-buildinfo", statusWarn, "%v", err)
		return ""
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		r.emit("coder-buildinfo", statusWarn, "GET /api/v2/buildinfo: %v", err)
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, coderapi.MaxBodyBytes))
	if resp.StatusCode != 200 {
		r.emit("coder-buildinfo", statusWarn, "GET /api/v2/buildinfo returned HTTP %d", resp.StatusCode)
		return ""
	}
	var bi struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &bi); err != nil {
		r.emit("coder-buildinfo", statusWarn, "buildinfo reply not JSON: %v", err)
		return ""
	}
	r.emit("coder-buildinfo", statusPass, "deployment reachable (server version %s)", bi.Version)
	return bi.Version
}

// coderVersionRE extracts a semantic version from `coder version` output.
var coderVersionRE = regexp.MustCompile(`v?(\d+\.\d+\.\d+)`)

// checkCoderBinary covers §29.1 "Coder CLI executable and version" plus the
// CLI/server compatibility warning (fail-soft).
func (r *doctorReport) checkCoderBinary(cfg *config.Config, serverVersion string) {
	const name = "coder-binary"
	bin := cfg.Deployment.CoderBinary
	if bin == "" {
		r.emit(name, statusFail, "deployment.coder_binary is not set")
		return
	}
	fi, err := os.Stat(bin)
	switch {
	case err != nil:
		r.emit(name, statusFail, "%s: %v", bin, err)
		return
	case fi.IsDir() || fi.Mode().Perm()&0o111 == 0:
		r.emit(name, statusFail, "%s is not executable", bin)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "version")
	if cfg.Deployment.WorkingDirectory != "" {
		if fi, err := os.Stat(cfg.Deployment.WorkingDirectory); err == nil && fi.IsDir() {
			cmd.Dir = cfg.Deployment.WorkingDirectory
		}
	}
	out, err := cmd.Output()
	if err != nil {
		r.emit(name, statusFail, "executing %s version: %v", bin, err)
		return
	}
	m := coderVersionRE.FindSubmatch(out)
	if m == nil {
		r.emit(name, statusWarn, "could not parse a version from %q output", bin)
		return
	}
	cliVersion := string(m[1])
	if serverVersion != "" {
		if sm := coderVersionRE.FindStringSubmatch(serverVersion); sm != nil && !sameMajorMinor(cliVersion, sm[1]) {
			r.emit(name, statusWarn, "coder CLI v%s differs from server %s; upgrade/downgrade the CLI to match (compatibility warning)", cliVersion, serverVersion)
			return
		}
		r.emit(name, statusPass, "coder CLI v%s (matches server)", cliVersion)
		return
	}
	r.emit(name, statusPass, "coder CLI v%s (server version unknown; compatibility not checked)", cliVersion)
}

func sameMajorMinor(a, b string) bool {
	cut := func(v string) string {
		parts := strings.Split(v, ".")
		if len(parts) < 2 {
			return v
		}
		return parts[0] + "." + parts[1]
	}
	return cut(a) == cut(b)
}

func (r *doctorReport) checkWritableDirs(cfg *config.Config) {
	const name = "writable-dirs"
	for _, d := range []string{cfg.State.Dir, os.TempDir()} {
		if d == "" {
			continue
		}
		probe, err := os.CreateTemp(d, ".doctor-write-probe-*")
		if err != nil {
			r.emit(name, statusFail, "%s is not writable: %v", d, err)
			return
		}
		_ = probe.Close()
		_ = os.Remove(probe.Name())
	}
	r.emit(name, statusPass, "state dir and temp dir are writable")
}

func (r *doctorReport) checkProcessLimits() {
	const name = "process-limits"
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		r.emit(name, statusWarn, "cannot read RLIMIT_NOFILE: %v", err)
		return
	}
	if rl.Cur < 1024 {
		r.emit(name, statusWarn, "nofile soft limit is %d (hard %d); raise it for production (section 20)", rl.Cur, rl.Max)
		return
	}
	r.emit(name, statusPass, "nofile soft=%d hard=%d", rl.Cur, rl.Max)
}

// checkAccountCredential is the optional §29.1 "real credential validation
// for a selected account". Returns a copy of the decrypted token for the
// optional workspace probe; caller wipes. Never prints token bytes.
func (r *doctorReport) checkAccountCredential(cfg *config.Config, accountFlag string) []byte {
	const name = "account-credential"
	id, err := uuid.Parse(accountFlag)
	if err != nil {
		r.emit(name, statusFail, "--account: %v", err)
		return nil
	}
	st, err := store.Open(cfg.State.Dir)
	if err != nil {
		r.emit(name, statusFail, "opening store: %v", err)
		return nil
	}
	defer st.Close()
	st.SetKeyProvider(KeyProviderFromConfig(cfg, nil))
	acct, err := st.GetAccount(id)
	if err != nil {
		r.emit(name, statusFail, "%v", err)
		return nil
	}
	snap, err := st.LoadCredential(context.Background(), id)
	if err != nil {
		r.emit(name, statusFail, "loading credential: %v", err)
		return nil
	}
	defer secretbox.BestEffortWipe(snap.Token)
	if snap.State == core.CredentialStateMissing || len(snap.Token) == 0 {
		r.emit(name, statusWarn, "account %s (%q) has no stored credential (state=%s)", id, acct.Label, snap.State)
		return nil
	}
	dep, err := DeploymentFromConfig(cfg)
	if err != nil {
		r.emit(name, statusFail, "%v", err)
		return nil
	}
	vopts, err := VerifierOptionsFromConfig(cfg)
	if err != nil {
		r.emit(name, statusFail, "%v", err)
		return nil
	}
	verifier, err := coderapi.New(dep, vopts)
	if err != nil {
		r.emit(name, statusFail, "%v", err)
		return nil
	}
	ident, err := verifier.Verify(context.Background(), snap.Token)
	if err == nil {
		if acct.CoderUserID != nil && *acct.CoderUserID != ident.ID {
			r.emit(name, statusFail, "stored credential belongs to Coder user %s but account is bound to %s", ident.ID, *acct.CoderUserID)
			return nil
		}
		r.emit(name, statusPass, "stored credential is valid (Coder user %q, generation %d)", ident.Username, snap.Generation)
		return slices.Clone(snap.Token)
	}
	switch core.KindOf(err) {
	case core.CredentialInvalid:
		r.emit(name, statusFail, "stored credential was rejected by Coder (401); renew it")
	case core.CredentialForbidden:
		r.emit(name, statusFail, "stored credential is forbidden (403)")
	case core.ControlPlaneUnavailable:
		r.emit(name, statusWarn, "control plane unreachable; credential not revalidated")
	default:
		r.emit(name, statusWarn, "credential validation inconclusive: %v", err)
	}
	return nil
}

// checkWorkspaceProbe is the optional §29.1 live probe: spawn the real
// `coder ssh --stdio` with the account's stored credential and PASS when the
// workspace handshake produces output. Any missing prerequisite is a WARN
// skip — the probe is meaningful only against a live deployment.
func (r *doctorReport) checkWorkspaceProbe(cfg *config.Config, workspace, accountFlag string, token []byte) {
	const name = "probe-workspace"
	if accountFlag == "" {
		r.emit(name, statusWarn, "skipped: --probe-workspace requires --account to supply the credential")
		return
	}
	if len(token) == 0 {
		r.emit(name, statusWarn, "skipped: no valid stored credential for the probe")
		return
	}
	dep, err := DeploymentFromConfig(cfg)
	if err != nil {
		r.emit(name, statusFail, "%v", err)
		return
	}
	rt, err := route.ParseBareTarget(workspace)
	if err != nil {
		r.emit(name, statusFail, "workspace name %q is not a valid target: %v", workspace, err)
		return
	}
	argv := tunnel.BuildArgv(dep, rt)
	if argv == nil {
		r.emit(name, statusFail, "could not build coder argv for %q", rt.WorkspaceHost)
		return
	}
	if err := tunnel.EnsureGlobalConfigDir(dep.GlobalConfig); err != nil {
		r.emit(name, statusFail, "coder global config dir: %v", err)
		return
	}
	env := tunnel.BuildEnv(dep, token)

	timeout := cfg.Deployment.WorkspaceConnectTimeout.Std()
	if timeout <= 0 || timeout > 60*time.Second {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, dep.CoderBinary, argv...)
	cmd.Env = env
	if dep.WorkingDir != "" {
		cmd.Dir = dep.WorkingDir
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		r.emit(name, statusWarn, "probe setup: %v", err)
		return
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		r.emit(name, statusWarn, "probe start: %v", err)
		return
	}
	firstByte := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := stdout.Read(buf)
		firstByte <- err
	}()
	select {
	case err := <-firstByte:
		if err == nil {
			r.emit(name, statusPass, "coder ssh --stdio to %q produced output (handshake underway)", rt.WorkspaceHost)
		} else {
			r.emit(name, statusWarn, "probe ended before any workspace output: %v", err)
		}
	case <-ctx.Done():
		r.emit(name, statusWarn, "no workspace output within %s (workspace stopped or unreachable)", timeout)
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()
}
