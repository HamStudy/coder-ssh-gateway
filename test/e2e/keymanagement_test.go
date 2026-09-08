//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// Key-management UI end-to-end coverage: the real OpenSSH client drives the
// account-scoped, line-based key-management UI served by the real gateway
// binary on login-admin@ connections. Scenarios: PTY removal with dynamic
// (fingerprint-parsed) menu selection, the session-key guard, restricted
// dispatch (no tunnels, exec refused), the no-pty path over stdin/stdout
// pipes, and account deletion followed by full login@ re-enrollment.
//
// The km* strings below are the contractual UI/wire strings pinned in
// internal/keymgmt/ui.go and internal/server/keymanagement.go. They are
// duplicated verbatim (not imported) so a drift in the user-facing contract
// fails this suite — that is its purpose.

const (
	kmHeaderPrefix  = "Coder SSH Gateway -- key management for "
	kmMenu          = "Enter a key number to remove it, d to delete your account, r to refresh, q to quit:"
	kmGuard         = "This key authenticates your current session and cannot be removed."
	kmInvalidInput  = "Invalid input."
	kmCancelled     = "Cancelled."
	kmBye           = "Bye."
	kmDeletePrompt  = "Type DELETE to permanently delete your account, anything else to cancel:"
	kmDeleted       = "Account deleted. Reconnect with login@ to enroll again."
	kmEnrolled      = "Enrollment complete. This connection will now close;"
	kmChannelReason = "key management connections cannot open workspace channels"

	// keysUser is the default key_management.user; the fixture config keeps
	// defaults, so these tests exercise the shipped special username.
	keysUser = "login-admin"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sshConfigForKey writes an isolation ssh_config pinned to one identity file
// (mirrors gatewayFixture.sshConfig; needed for key B, which the fixture
// config does not know about).
func sshConfigForKey(t *testing.T, keyPath string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh_config")
	content := fmt.Sprintf(`Host *
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
  IdentitiesOnly yes
  IdentityFile %s
  ConnectTimeout 10
`, keyPath)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}
	return path
}

// publicKeyFingerprint computes the gateway's canonical key fingerprint
// (ssh.FingerprintSHA256 — the same formula the store uses for records).
func publicKeyFingerprint(t *testing.T, pubPath string) string {
	t.Helper()
	raw, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read public key %s: %v", pubPath, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		t.Fatalf("parse public key %s: %v", pubPath, err)
	}
	return ssh.FingerprintSHA256(pub)
}

var kmKeyAddRE = regexp.MustCompile(`key ([0-9a-f-]{36}) added for account`)

// addAccountKey registers a second client key on the fixture's account via
// the admin CLI and returns the new key's UUID.
func addAccountKey(t *testing.T, f *gatewayFixture, pubPath, label string) string {
	t.Helper()
	out := f.runCLI(t, nil, "", "admin", "key", "add",
		"--account", f.accountID.String(), "--file", pubPath, "--label", label)
	m := kmKeyAddRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not parse key UUID from admin key add output:\n%s", out)
	}
	return m[1]
}

var kmKeyListRE = regexp.MustCompile(`id=([0-9a-f-]{36}) fingerprint=(\S+)`)

// keyIDByFingerprint resolves a key UUID through `admin key list` (used for
// keys the fixture enrolled internally).
func keyIDByFingerprint(t *testing.T, f *gatewayFixture, fp string) string {
	t.Helper()
	out := f.runCLI(t, nil, "", "admin", "key", "list", "--account", f.accountID.String())
	for _, m := range kmKeyListRE.FindAllStringSubmatch(out, -1) {
		if m[2] == fp {
			return m[1]
		}
	}
	t.Fatalf("no key with fingerprint %s in admin key list:\n%s", fp, out)
	return ""
}

// kmListingRE matches rendered listing lines ("<n> <fingerprint> <algo> ").
// Menu numbers are dynamic — ListKeysForAccount sorts by the keys' random
// UUIDs — so every selection parses the transcript instead of hardcoding an
// index. The confirm line ("You selected key N: ...") never matches because
// it does not start with digits+space, and pty-echoed keystrokes prefix the
// FOLLOWING server line rather than a listing line.
var kmListingRE = regexp.MustCompile(`(?m)^([0-9]+) (SHA256:[A-Za-z0-9+/=]+) `)

func keyIndexByFingerprint(t *testing.T, transcript, wantFP string) int {
	t.Helper()
	for _, m := range kmListingRE.FindAllStringSubmatch(transcript, -1) {
		if m[2] == wantFP {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				t.Fatalf("listing index %q: %v", m[1], err)
			}
			return n
		}
	}
	t.Fatalf("no listing entry with fingerprint %s; transcript:\n%s", wantFP, transcript)
	return 0
}

// sshSession is one driven OpenSSH client: either under a real PTY (creack/pty
// + ptmx writes, server-side echo interleaves with UI output) or over
// stdin/stdout pipes (no pty, no echo).
type sshSession struct {
	cmd        *exec.Cmd
	ptmx       *os.File       // PTY sessions only
	stdin      io.WriteCloser // pipe sessions only
	stderr     *bytes.Buffer  // pipe sessions only
	transcript *lockedBuffer
	readDone   chan error // PTY sessions only
}

func (s *sshSession) write(t *testing.T, data string) {
	t.Helper()
	var err error
	if s.ptmx != nil {
		_, err = s.ptmx.Write([]byte(data))
	} else {
		_, err = s.stdin.Write([]byte(data))
	}
	if err != nil {
		t.Fatalf("write %q to ssh session: %v", data, err)
	}
}

// waitExit waits for the client to exit and returns its exit code.
func (s *sshSession) waitExit(t *testing.T, d time.Duration) int {
	t.Helper()
	type result struct{ code int }
	ch := make(chan result, 1)
	go func() {
		err := s.cmd.Wait()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			code = -1
		}
		ch <- result{code}
	}()
	select {
	case r := <-ch:
		if s.ptmx != nil {
			_ = s.ptmx.Close() // unblocks the transcript reader goroutine
			<-s.readDone
		}
		return r.code
	case <-time.After(d):
		msg := fmt.Sprintf("ssh did not exit within %v\ntranscript:\n%s", d, s.transcript.String())
		if s.stderr != nil {
			msg += "\nstderr:\n" + s.stderr.String()
		}
		t.Fatal(msg)
	}
	return -1
}

// startSSHPTY launches `ssh -tt <user>@<gateway>` under a real PTY, mirroring
// TestE2ECredentialRenewalPTY (TERM must be set: CI has none) and continuously
// recording the transcript. All synchronization is waitForTranscript — no
// sleeps.
func startSSHPTY(t *testing.T, f *gatewayFixture, keyPath, user string, extraArgs ...string) *sshSession {
	t.Helper()
	args := append([]string{"-F", sshConfigForKey(t, keyPath), "-tt"}, extraArgs...)
	args = append(args, "-p", f.port, user+"@"+f.host)
	cmd := exec.Command("ssh", args...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("start ssh under PTY: %v", err)
	}
	s := &sshSession{cmd: cmd, ptmx: ptmx, transcript: &lockedBuffer{}, readDone: make(chan error, 1)}
	go func() {
		_, err := io.Copy(s.transcript, ptmx)
		s.readDone <- err
	}()
	t.Cleanup(func() {
		_ = ptmx.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	return s
}

// startSSHPipes launches `ssh <user>@<gateway>` without a pty: stdin/stdout
// pipes drive the same line-based UI (the no-pty client path).
func startSSHPipes(t *testing.T, f *gatewayFixture, keyPath, user string) *sshSession {
	t.Helper()
	args := []string{"-F", sshConfigForKey(t, keyPath), "-p", f.port, user + "@" + f.host}
	cmd := exec.Command("ssh", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	s := &sshSession{cmd: cmd, stdin: stdin, stderr: &bytes.Buffer{}, transcript: &lockedBuffer{}}
	cmd.Stdout = s.transcript
	cmd.Stderr = s.stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ssh (pipes): %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	return s
}

// waitForTranscriptCount polls until want appears at least n times — needed
// because identical prompts (the menu) legitimately re-render.
func waitForTranscriptCount(t *testing.T, buf *lockedBuffer, want string, n int, d time.Duration, extra ...*lockedBuffer) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if strings.Count(buf.String(), want) >= n {
			return
		}
		if time.Now().After(deadline) {
			msg := fmt.Sprintf("transcript did not contain %q at least %d times within %v\ntranscript:\n%s", want, n, d, buf.String())
			for _, b := range extra {
				if b != nil {
					msg += "\ngateway logs:\n" + b.String()
				}
			}
			t.Fatal(msg)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// waitForLog polls the gateway log buffer for a refusal/teardown line.
func waitForLog(t *testing.T, buf *lockedBuffer, want string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if strings.Contains(buf.String(), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway log did not contain %q within %v\nlogs:\n%s", want, d, buf.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// auditEventJSON is the subset of the audit wire format these tests assert on.
type auditEventJSON struct {
	EventType  string `json:"event_type"`
	Result     string `json:"result"`
	SSHKeyID   string `json:"ssh_key_id,omitempty"`
	AccountID  string `json:"account_id,omitempty"`
	DetailCode string `json:"detail_code,omitempty"`
}

// readAuditEvents parses every audit-*.jsonl in the fixture's state dir (the
// file name carries a per-instance suffix in HA setups, so glob by prefix and
// suffix) and also returns the raw text for secret-leak scans.
func readAuditEvents(t *testing.T, f *gatewayFixture) ([]auditEventJSON, string) {
	t.Helper()
	dir := filepath.Join(f.stateDir, "audit")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read audit dir: %v", err)
	}
	var events []auditEventJSON
	var raw strings.Builder
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "audit-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read audit file %s: %v", name, err)
		}
		raw.Write(data)
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var ev auditEventJSON
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("audit line is not JSON: %q: %v", line, err)
			}
			events = append(events, ev)
		}
	}
	return events, raw.String()
}

func findAuditEvent(t *testing.T, events []auditEventJSON, eventType, result, sshKeyID string) auditEventJSON {
	t.Helper()
	for _, ev := range events {
		if ev.EventType != eventType || ev.Result != result {
			continue
		}
		if sshKeyID != "" && ev.SSHKeyID != sshKeyID {
			continue
		}
		return ev
	}
	t.Fatalf("no audit event type=%s result=%s ssh_key_id=%s; events: %+v", eventType, result, sshKeyID, events)
	return auditEventJSON{}
}

// assertUniformRejection proves a failed authentication shows the generic
// denial only: exit 255, the client's "Permission denied (publickey)", and no
// fingerprint, label, or key-management UI output anywhere.
func assertUniformRejection(t *testing.T, f *gatewayFixture, keyPath, user string, secrets ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := []string{"-F", sshConfigForKey(t, keyPath),
		"-o", "PreferredAuthentications=publickey",
		"-p", f.port, user + "@" + f.host, "true"}
	stdout, stderr, code := runSSH(ctx, args...)
	if code != 255 {
		t.Fatalf("ssh %s@ exit = %d, want 255 (denied)\nstdout: %q\nstderr: %q\ngateway logs:\n%s",
			user, code, stdout, stderr, f.logBuf.String())
	}
	if !strings.Contains(stderr, "Permission denied (publickey)") {
		t.Fatalf("stderr lacks the generic denial:\n%s", stderr)
	}
	combined := stdout + stderr
	for _, s := range secrets {
		if strings.Contains(combined, s) {
			t.Fatalf("SECURITY: rejection output leaks %q:\n%s", s, combined)
		}
	}
	if strings.Contains(combined, kmHeaderPrefix) {
		t.Fatalf("rejected connection reached the key-management UI:\n%s", combined)
	}
}

// ---------------------------------------------------------------------------
// (a)+(b)+(e): PTY happy-path removal, dynamic selection, audit trail
// ---------------------------------------------------------------------------

// TestE2EKeyManagementRemoveKeyPTY drives the full happy path through a real
// PTY: key A (fixture) + key B (admin CLI) are listed, key B is selected by
// parsing its SHA256 fingerprint out of the transcript (never a hardcoded
// index — the store sorts keys by random UUID), confirmed, removed, and
// re-listed without it. Then key B fails uniformly, key A still opens a
// workspace session, and the audit trail carries the removal with IDs only.
func TestE2EKeyManagementRemoveKeyPTY(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")

	fpA := publicKeyFingerprint(t, f.pubPath)
	keyBPath, keyBPub := writeClientKey(t, t.TempDir(), generateKey(t))
	fpB := publicKeyFingerprint(t, keyBPub)
	keyBID := addAccountKey(t, f, keyBPub, "tablet key")

	s := startSSHPTY(t, f, f.keyPath, keysUser)
	waitForTranscript(t, s.transcript, kmHeaderPrefix, 60*time.Second, f.logBuf)
	waitForTranscript(t, s.transcript, kmMenu, 60*time.Second, f.logBuf)

	// Both enrolled keys are visible before any action.
	text := s.transcript.String()
	if !strings.Contains(text, fpA) || !strings.Contains(text, fpB) {
		t.Fatalf("initial listing does not show both fingerprints:\n%s", text)
	}

	n := keyIndexByFingerprint(t, text, fpB)
	s.write(t, fmt.Sprintf("%d\r", n))
	waitForTranscript(t, s.transcript, fmt.Sprintf("You selected key %d: %s", n, fpB), 30*time.Second, f.logBuf)
	s.write(t, fmt.Sprintf("%d\r", n))
	waitForTranscript(t, s.transcript, fmt.Sprintf("Key %d removed.", n), 30*time.Second, f.logBuf)

	// The re-listed menu shows the survivor (A) and not the removed key (B).
	waitForTranscriptCount(t, s.transcript, kmMenu, 2, 30*time.Second, f.logBuf)
	text = s.transcript.String()
	tail := text[strings.Index(text, fmt.Sprintf("Key %d removed.", n)):]
	if !strings.Contains(tail, fpA) {
		t.Errorf("re-listing after removal is missing the surviving key:\n%s", tail)
	}
	if strings.Contains(tail, fpB) {
		t.Errorf("re-listing after removal still shows the removed key:\n%s", tail)
	}

	s.write(t, "q\r")
	waitForTranscript(t, s.transcript, kmBye, 30*time.Second, f.logBuf)
	if code := s.waitExit(t, 30*time.Second); code != 0 {
		t.Fatalf("ssh exit after quit = %d, want 0", code)
	}

	// (e) Audit: the removal is on record with IDs and result only — no
	// fingerprint or label substring anywhere in the audit files.
	events, raw := readAuditEvents(t, f)
	ev := findAuditEvent(t, events, "ssh_key_removed", "success", keyBID)
	if ev.AccountID != f.accountID.String() {
		t.Errorf("ssh_key_removed account = %s, want %s", ev.AccountID, f.accountID)
	}
	for _, secret := range []string{fpA, fpB, "e2e key", "tablet key"} {
		if strings.Contains(raw, secret) {
			t.Errorf("SECURITY: audit log leaks %q", secret)
		}
	}

	// The removed key fails uniformly (no UI, no fingerprint echo) — on the
	// keys username and on a workspace route alike (no existence oracle).
	assertUniformRejection(t, f, keyBPath, keysUser, fpA, fpB)
	assertUniformRejection(t, f, keyBPath, testWorkspace, fpA, fpB)

	// The survivor still opens a normal workspace session.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := []string{"-F", sshConfigForKey(t, f.keyPath), "-p", f.port, testWorkspace + "@" + f.host, "printf hello"}
	stdout, stderr, code := runSSH(ctx, args...)
	if code != 0 {
		t.Fatalf("workspace session with surviving key exit = %d\nstdout: %q\nstderr: %q\ngateway logs:\n%s",
			code, stdout, stderr, f.logBuf.String())
	}
	if stdout != "hello" {
		t.Fatalf("workspace stdout = %q, want hello", stdout)
	}

	f.waitNoChildren(t, 5*time.Second)
	t.Logf("removal transcript:\n%s", s.transcript.String())
}

// ---------------------------------------------------------------------------
// (c): the session-key guard
// ---------------------------------------------------------------------------

// TestE2EKeyManagementSessionKeyGuard selects the session's OWN key by
// fingerprint and proves the guard refusal leaves the key working. The client
// is then killed abruptly mid-session (adversarial disconnect): teardown must
// be clean and the gateway stays healthy for the next connection.
func TestE2EKeyManagementSessionKeyGuard(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")

	fpA := publicKeyFingerprint(t, f.pubPath)
	keyAID := keyIDByFingerprint(t, f, fpA)

	s := startSSHPTY(t, f, f.keyPath, keysUser)
	waitForTranscript(t, s.transcript, kmMenu, 60*time.Second, f.logBuf)

	n := keyIndexByFingerprint(t, s.transcript.String(), fpA)
	s.write(t, fmt.Sprintf("%d\r", n))
	waitForTranscript(t, s.transcript, kmGuard, 30*time.Second, f.logBuf)
	waitForLog(t, f.logBuf, "session-key removal refused", 15*time.Second)

	// Abrupt disconnect instead of a clean quit.
	_ = s.cmd.Process.Kill()
	_ = s.waitExit(t, 30*time.Second)

	if strings.Contains(f.logBuf.String(), "panic") {
		t.Fatalf("gateway panicked during abrupt keys-session teardown:\n%s", f.logBuf.String())
	}

	// The refusal is audited as a failed removal with the guard detail code.
	events, raw := readAuditEvents(t, f)
	ev := findAuditEvent(t, events, "ssh_key_removed", "failure", keyAID)
	if ev.DetailCode != "current_session_key" {
		t.Errorf("guard audit detail_code = %q, want current_session_key", ev.DetailCode)
	}
	for _, secret := range []string{fpA, "e2e key"} {
		if strings.Contains(raw, secret) {
			t.Errorf("SECURITY: audit log leaks %q", secret)
		}
	}

	// The store is unchanged: key A still authenticates a workspace session.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := []string{"-F", sshConfigForKey(t, f.keyPath), "-p", f.port, testWorkspace + "@" + f.host, "printf hello"}
	stdout, stderr, code := runSSH(ctx, args...)
	if code != 0 {
		t.Fatalf("workspace session after guard refusal exit = %d\nstdout: %q\nstderr: %q\ngateway logs:\n%s",
			code, stdout, stderr, f.logBuf.String())
	}
	if stdout != "hello" {
		t.Fatalf("workspace stdout = %q, want hello", stdout)
	}
	f.waitNoChildren(t, 5*time.Second)
}

// ---------------------------------------------------------------------------
// (d): restricted dispatch — no tunnels on a keys-mode connection
// ---------------------------------------------------------------------------

// TestE2EKeyManagementNoTunnel proves the keys-mode channel surface over the
// real wire: exec is refused with exit-status 1 and the pinned stderr
// message, and a -L local forward's direct-tcpip channel is refused with the
// policy reason logged (never silent). No coder child is ever spawned.
func TestE2EKeyManagementNoTunnel(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")

	// exec on a key-management connection: the request is refused (the
	// server sends exit-status 1 + a stderr line afterwards, but OpenSSH
	// tears the session down on the channel failure — the client-visible
	// contract is the 255 exit plus "exec request failed"). The WARN log
	// pins the server-side refusal reason.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := []string{"-F", sshConfigForKey(t, f.keyPath), "-p", f.port, keysUser + "@" + f.host, "true"}
	stdout, stderr, code := runSSH(ctx, args...)
	if code != 255 {
		t.Fatalf("exec on key-management connection exit = %d, want 255 (exec request refused)\nstdout: %q\nstderr: %q\ngateway logs:\n%s",
			code, stdout, stderr, f.logBuf.String())
	}
	if !strings.Contains(stderr, "exec request failed") {
		t.Fatalf("stderr missing the exec failure:\n%s", stderr)
	}
	waitForLog(t, f.logBuf, "exec refused on key-management connection", 15*time.Second)

	// -L local forward against the keys-mode connection: the direct-tcpip
	// channel open must be refused and no data may flow.
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve local port: %v", err)
	}
	localPort := reserve.Addr().(*net.TCPAddr).Port
	_ = reserve.Close()

	fwdCtx, fwdCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer fwdCancel()
	fwdArgs := []string{"-F", sshConfigForKey(t, f.keyPath), "-N",
		"-L", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:9", localPort),
		"-p", f.port, keysUser + "@" + f.host}
	fwd := exec.CommandContext(fwdCtx, "ssh", fwdArgs...)
	if err := fwd.Start(); err != nil {
		t.Fatalf("start ssh -L: %v", err)
	}
	defer func() { _ = fwd.Process.Kill() }()

	deadline := time.Now().Add(15 * time.Second)
	var conn net.Conn
	for conn == nil {
		if time.Now().After(deadline) {
			t.Fatalf("local forward listener never came up\ngateway logs:\n%s", f.logBuf.String())
		}
		conn, err = net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(localPort), time.Second)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	marker := "forward-must-not-relay"
	if _, err := io.WriteString(conn, marker); err != nil {
		t.Fatalf("write through local forward: %v", err)
	}
	buf := make([]byte, len(marker))
	if n, _ := conn.Read(buf); n > 0 && string(buf[:n]) == marker {
		t.Fatal("SECURITY: data relayed through a key-management connection")
	}

	waitForLog(t, f.logBuf, kmChannelReason, 15*time.Second)
	f.waitNoChildren(t, 5*time.Second)
}

// ---------------------------------------------------------------------------
// (f): the no-pty path over stdin/stdout pipes
// ---------------------------------------------------------------------------

// TestE2EKeyManagementNoPtyRemoval drives the same removal flow with ssh on
// pipes (no pty, no echo), including the adversarial input paths over the
// real wire: garbage menu input (Invalid input. + re-list) and a wrong
// confirmation (Cancelled., key intact) before the real removal.
func TestE2EKeyManagementNoPtyRemoval(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")

	fpA := publicKeyFingerprint(t, f.pubPath)
	_, keyBPub := writeClientKey(t, t.TempDir(), generateKey(t))
	fpB := publicKeyFingerprint(t, keyBPub)
	keyBID := addAccountKey(t, f, keyBPub, "tablet key")

	s := startSSHPipes(t, f, f.keyPath, keysUser)
	waitForTranscript(t, s.transcript, kmMenu, 60*time.Second, f.logBuf)

	// Garbage menu input: rejected, listing re-rendered.
	s.write(t, "garbage!\n")
	waitForTranscript(t, s.transcript, kmInvalidInput, 30*time.Second, f.logBuf)
	waitForTranscriptCount(t, s.transcript, kmMenu, 2, 30*time.Second, f.logBuf)

	n := keyIndexByFingerprint(t, s.transcript.String(), fpB)

	// Wrong confirmation cancels and leaves the key listed.
	s.write(t, fmt.Sprintf("%d\n", n))
	waitForTranscript(t, s.transcript, fmt.Sprintf("You selected key %d: %s", n, fpB), 30*time.Second, f.logBuf)
	s.write(t, "x\n")
	waitForTranscript(t, s.transcript, kmCancelled, 30*time.Second, f.logBuf)
	waitForTranscriptCount(t, s.transcript, kmMenu, 3, 30*time.Second, f.logBuf)

	// Second attempt confirms and removes.
	s.write(t, fmt.Sprintf("%d\n", n))
	waitForTranscriptCount(t, s.transcript, fmt.Sprintf("You selected key %d: %s", n, fpB), 2, 30*time.Second, f.logBuf)
	s.write(t, fmt.Sprintf("%d\n", n))
	waitForTranscript(t, s.transcript, fmt.Sprintf("Key %d removed.", n), 30*time.Second, f.logBuf)
	waitForTranscriptCount(t, s.transcript, kmMenu, 4, 30*time.Second, f.logBuf)

	text := s.transcript.String()
	tail := text[strings.Index(text, fmt.Sprintf("Key %d removed.", n)):]
	if !strings.Contains(tail, fpA) {
		t.Errorf("re-listing after removal is missing the surviving key:\n%s", tail)
	}
	if strings.Contains(tail, fpB) {
		t.Errorf("re-listing after removal still shows the removed key:\n%s", tail)
	}

	s.write(t, "q\n")
	_ = s.stdin.Close()
	waitForTranscript(t, s.transcript, kmBye, 30*time.Second, f.logBuf)
	if code := s.waitExit(t, 30*time.Second); code != 0 {
		t.Fatalf("ssh exit after quit = %d, want 0\nstderr:\n%s", code, s.stderr.String())
	}

	events, raw := readAuditEvents(t, f)
	findAuditEvent(t, events, "ssh_key_removed", "success", keyBID)
	for _, secret := range []string{fpA, fpB, "e2e key", "tablet key"} {
		if strings.Contains(raw, secret) {
			t.Errorf("SECURITY: audit log leaks %q", secret)
		}
	}
	f.waitNoChildren(t, 5*time.Second)
	t.Logf("no-pty transcript:\n%s", s.transcript.String())
}

// ---------------------------------------------------------------------------
// (g): account deletion + full login@ recovery
// ---------------------------------------------------------------------------

// TestE2EKeyManagementAccountDeletionAndRecovery runs the destructive full
// circle: a wrong DELETE confirmation cancels (account intact), the real
// DELETE removes the account with an audited per-key cascade, key A then
// fails uniformly, and the standard login@ flow with a fresh Coder token
// re-enrolls key A so workspace connections work again.
func TestE2EKeyManagementAccountDeletionAndRecovery(t *testing.T) {
	requireOpenSSH(t)
	const freshToken = "e2e-recovery-token"

	f := newGatewayFixture(t, "e2e-valid-token")
	fpA := publicKeyFingerprint(t, f.pubPath)
	keyBPath, keyBPub := writeClientKey(t, t.TempDir(), generateKey(t))
	fpB := publicKeyFingerprint(t, keyBPub)
	keyAID := keyIDByFingerprint(t, f, fpA)
	keyBID := addAccountKey(t, f, keyBPub, "tablet key")
	f.coder.setToken(freshToken, 200)

	s := startSSHPTY(t, f, f.keyPath, keysUser)
	waitForTranscript(t, s.transcript, kmMenu, 60*time.Second, f.logBuf)

	// Consequences screen; a wrong confirmation cancels and re-lists.
	s.write(t, "d\r")
	waitForTranscript(t, s.transcript, "This will permanently delete your account: 2 key(s)", 30*time.Second, f.logBuf)
	waitForTranscript(t, s.transcript, kmDeletePrompt, 30*time.Second, f.logBuf)
	s.write(t, "nope\r")
	waitForTranscript(t, s.transcript, kmCancelled, 30*time.Second, f.logBuf)
	waitForTranscriptCount(t, s.transcript, kmMenu, 2, 30*time.Second, f.logBuf)

	// The real deletion: typed DELETE, goodbye, connection closes.
	s.write(t, "d\r")
	waitForTranscriptCount(t, s.transcript, "This will permanently delete your account: 2 key(s)", 2, 30*time.Second, f.logBuf)
	s.write(t, "DELETE\r")
	waitForTranscript(t, s.transcript, kmDeleted, 30*time.Second, f.logBuf)
	waitForTranscript(t, s.transcript, kmBye, 30*time.Second, f.logBuf)
	if code := s.waitExit(t, 30*time.Second); code != 0 {
		t.Fatalf("ssh exit after account deletion = %d, want 0", code)
	}

	// Audit: account_deleted plus one ssh_key_removed per cascaded key,
	// IDs only.
	events, raw := readAuditEvents(t, f)
	if ev := findAuditEvent(t, events, "account_deleted", "success", ""); ev.AccountID != f.accountID.String() {
		t.Errorf("account_deleted account = %s, want %s", ev.AccountID, f.accountID)
	}
	findAuditEvent(t, events, "ssh_key_removed", "success", keyAID)
	findAuditEvent(t, events, "ssh_key_removed", "success", keyBID)
	cascaded := 0
	for _, ev := range events {
		if ev.EventType == "ssh_key_removed" && ev.Result == "success" {
			cascaded++
		}
	}
	if cascaded != 2 {
		t.Errorf("cascaded ssh_key_removed events = %d, want 2 (one per key)", cascaded)
	}
	for _, secret := range []string{fpA, fpB, "e2e key", "tablet key"} {
		if strings.Contains(raw, secret) {
			t.Errorf("SECURITY: audit log leaks %q", secret)
		}
	}

	// Every former key fails uniformly on both routes.
	assertUniformRejection(t, f, f.keyPath, keysUser, fpA, fpB)
	assertUniformRejection(t, f, f.keyPath, testWorkspace, fpA, fpB)
	assertUniformRejection(t, f, keyBPath, keysUser, fpA, fpB)

	// Re-enroll from scratch through the standard login@ flow: KI token
	// prompt (hidden — the token must never hit the transcript), banners,
	// and the forced reconnect.
	e := startSSHPTY(t, f, f.keyPath, "login",
		"-o", "PreferredAuthentications=publickey,keyboard-interactive,password",
		"-o", "KbdInteractiveAuthentication=yes",
		"-o", "PasswordAuthentication=yes",
		"-o", "NumberOfPasswordPrompts=1",
	)
	waitForTranscript(t, e.transcript, "Coder token:", 60*time.Second, f.logBuf)
	e.write(t, freshToken+"\r")
	waitForTranscript(t, e.transcript, "Device enrolled.", 60*time.Second, f.logBuf)
	if code := e.waitExit(t, 60*time.Second); code != 0 {
		t.Fatalf("ssh login@ exit after enrollment = %d, want 0", code)
	}
	// OpenSSH drops the auth-time banner and shows the KI confirmation
	// instead, so the client-visible enrollment contract is the pinned
	// confirmation line plus the goodbye below.
	if text := e.transcript.String(); !strings.Contains(text, kmEnrolled) {
		t.Errorf("enrollment transcript missing the completion confirmation:\n%s", text)
	}
	if strings.Contains(e.transcript.String(), freshToken) {
		t.Fatal("SECURITY: enrollment token echoed to the PTY transcript")
	}

	// The recovered account reaches a workspace again.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := []string{"-F", sshConfigForKey(t, f.keyPath), "-p", f.port, testWorkspace + "@" + f.host, "printf hello"}
	stdout, stderr, code := runSSH(ctx, args...)
	if code != 0 {
		t.Fatalf("workspace session after re-enrollment exit = %d\nstdout: %q\nstderr: %q\ngateway logs:\n%s",
			code, stdout, stderr, f.logBuf.String())
	}
	if stdout != "hello" {
		t.Fatalf("workspace stdout = %q, want hello", stdout)
	}
	f.waitNoChildren(t, 5*time.Second)
	t.Logf("account-deletion transcript:\n%s", s.transcript.String())
	t.Logf("re-enrollment transcript (token-free):\n%s", e.transcript.String())
}
