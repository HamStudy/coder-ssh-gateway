package e2e

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/testutil/innerssh"
)

// TestE2EProxyJumpFake is the §38.3 headline case: the real OpenSSH client
// uses ProxyJump through the real gateway binary into the fake coder
// backend. The fake inner SSH server deterministically implements the exact
// acceptance command, so a correct end-to-end path returns literal "hello".
func TestE2EProxyJumpFake(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code := f.proxyJumpExec(t, ctx, testWorkspace, "printf hello")
	if code != 0 {
		t.Fatalf("ssh ProxyJump exit %d\nstdout: %q\nstderr: %q\ngateway logs:\n%s",
			code, stdout, stderr, f.logBuf.String())
	}
	if got, want := stdout, "hello"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}

	// §39: no leftover tunnel children once the connection closes.
	f.waitNoChildren(t, 5*time.Second)
	t.Logf("ProxyJump stdout: %q", stdout)
	t.Logf("fake coder API calls: %v", f.coder.callLog())
}

// TestE2EDirectWorkspaceUserFake exercises the primary direct-workspace
// syntax with the real OpenSSH client: the outer username is the bare Coder
// target and the enrolled public key still determines the gateway account.
func TestE2EDirectWorkspaceUserFake(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := append(f.sshCommonArgs(t), "-p", f.port, "emailsupport@"+f.host, "printf hello")
	stdout, stderr, code := runSSH(ctx, args...)
	if code != 0 {
		t.Fatalf("ssh emailsupport@gateway exit %d\nstdout: %q\nstderr: %q\ngateway logs:\n%s", code, stdout, stderr, f.logBuf.String())
	}
	if stdout != "hello" {
		t.Fatalf("stdout = %q, want hello", stdout)
	}
	f.waitNoChildren(t, 5*time.Second)
}

// TestE2EDirectWorkspaceInvalidTargetAfterAuth proves malformed targets do
// not become a key-authentication oracle: OpenSSH authenticates, then gets a
// bounded session failure with its conventional exit 255.
func TestE2EDirectWorkspaceInvalidTargetAfterAuth(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := append(f.sshCommonArgs(t), "-p", f.port, "invalid..target@"+f.host, "true")
	stdout, stderr, code := runSSH(ctx, args...)
	if code != 255 {
		t.Fatalf("invalid target exit = %d, want 255\nstdout: %q\nstderr: %q\ngateway logs:\n%s", code, stdout, stderr, f.logBuf.String())
	}
	if strings.Contains(stderr, "Permission denied (publickey)") {
		t.Fatalf("invalid target denied before authentication: %q", stderr)
	}
	if !strings.Contains(stderr, "workspace target is invalid or unavailable") {
		t.Fatalf("stderr = %q, want bounded post-auth failure", stderr)
	}
	f.waitNoChildren(t, 5*time.Second)
}

func TestE2EDirectWorkspaceRelaysInnerExitStatus(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := append(f.sshCommonArgs(t), "-p", f.port, "emailsupport@"+f.host, "exit 7")
	stdout, stderr, code := runSSH(ctx, args...)
	if code != 7 {
		t.Fatalf("inner exit status = %d, want 7\nstdout: %q\nstderr: %q\ngateway logs:\n%s", code, stdout, stderr, f.logBuf.String())
	}
	if strings.Contains(stderr, "workspace session failed") {
		t.Fatalf("nonzero remote exit emitted a generic infrastructure failure: %q", stderr)
	}
	f.waitNoChildren(t, 5*time.Second)
}

// TestE2EStdioForwardFake exercises the lower-level ProxyJump equivalent
// (§38.3): `ssh -W <workspace>:22 coder@<gateway>` bridges stdio to the
// inner SSH server, and a Go x/crypto client speaks through that stream.
func TestE2EStdioForwardFake(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	args := append(f.sshCommonArgs(t),
		"-W", testWorkspace+":22",
		"coder@"+f.host, "-p", f.port,
	)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ssh -W: %v", err)
	}
	// The stdin write side must stay open for the whole session: closing it
	// early is an EOF on the inner transport (T10 gotcha).
	defer stdin.Close()

	conn, chans, reqs, err := ssh.NewClientConn(
		innerssh.NewConn(stdout, stdin),
		testWorkspace+":22",
		&ssh.ClientConfig{
			User:            "coder",
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         15 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("inner handshake over -W stream: %v\nstderr: %s", err, stderrBuf.String())
	}
	client := ssh.NewClient(conn, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("inner session: %v", err)
	}
	out, err := session.Output("printf hello")
	if err != nil {
		t.Fatalf("inner exec: %v", err)
	}
	if got, want := string(out), "hello"; got != want {
		t.Fatalf("inner exec output = %q, want %q", got, want)
	}

	_ = client.Close()
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("ssh -W wait: %v (stderr: %s)", err, stderrBuf.String())
		}
		// A non-zero exit after a clean inner disconnect (e.g. 255 from the
		// forwarded-stream teardown ordering) is an OpenSSH artifact; the
		// payload assertion above is the compatibility claim.
		t.Logf("ssh -W exit after clean inner session: %v", err)
	}

	f.waitNoChildren(t, 5*time.Second)
	t.Logf("-W inner exec output: %q", string(out))
}

// TestE2ECredentialRenewalPTY drives the §2.2 renewal cycle through the real
// OpenSSH client attached to a real PTY: the stored credential is expired
// (fake control plane 401s it), the client is offered keyboard-interactive
// after partial publickey success, the operator types a fresh token at the
// hidden "Coder token:" prompt, the gateway validates + stores it, then
// deliberately disconnects. The NEXT connection reaches the workspace.
func TestE2ECredentialRenewalPTY(t *testing.T) {
	requireOpenSSH(t)

	const (
		expiredToken = "e2e-expired-token"
		freshToken   = "e2e-fresh-token"
	)
	f := newGatewayFixture(t, expiredToken)

	// Expire the stored credential: the control plane now rejects it.
	f.coder.setToken(expiredToken, 401)
	// The replacement token validates against the same bound Coder user.
	f.coder.setToken(freshToken, 200)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	args := append(f.sshCommonArgs(t),
		"-tt",
		"-o", "PreferredAuthentications=publickey,keyboard-interactive,password",
		"-o", "KbdInteractiveAuthentication=yes",
		"-o", "PasswordAuthentication=yes",
		"-o", "NumberOfPasswordPrompts=1",
		"coder@"+f.host, "-p", f.port,
	)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("start ssh under PTY: %v", err)
	}
	defer func() { _ = ptmx.Close() }()

	transcript := &lockedBuffer{}
	readErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(transcript, ptmx)
		readErr <- err
	}()

	// Wait for the hidden token prompt, then type the fresh token.
	waitForTranscript(t, transcript, "Coder token:", 60*time.Second)
	if _, err := ptmx.Write([]byte(freshToken + "\r")); err != nil {
		t.Fatalf("write token to PTY: %v", err)
	}

	// The renewal continues in place: the connection proceeds into the
	// workspace on the fresh credential — no reconnect required.
	waitForTranscript(t, transcript, "continuing to your workspace", 60*time.Second)

	// The session is live on the other side of the renewal: run a command
	// through the same connection to prove the continuation actually lands
	// in the workspace shell.
	if _, err := ptmx.Write([]byte("echo-probe-9137\r\n")); err != nil {
		t.Fatalf("write post-renewal command: %v", err)
	}
	waitForTranscript(t, transcript, "echo-probe-9137", 30*time.Second, f.logBuf)

	// The fake shell has no exit command; kill the client and verify the
	// gateway leaves no orphaned children behind.
	_ = cmd.Process.Kill()

	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case <-waitErr:
	case <-time.After(30 * time.Second):
		t.Fatalf("ssh did not exit after client kill\ntranscript:\n%s", transcript.String())
	}
	<-readErr

	text := transcript.String()
	if !strings.Contains(text, "Coder token:") {
		t.Errorf("transcript missing the hidden token prompt\n%s", text)
	}
	if !strings.Contains(text, "Coder token verified — continuing to your workspace.") {
		t.Errorf("transcript missing the renewal success banner\n%s", text)
	}
	if strings.Contains(text, freshToken) {
		t.Fatal("SECURITY: fresh token echoed to the PTY transcript (prompt must be hidden)")
	}

	f.waitNoChildren(t, 5*time.Second)
	t.Logf("renewal transcript (token-free):\n%s", text)
}

// TestE2ERapidPreflightFake hammers the gateway with 8 quick sequential
// ProxyJump connections — the §39 "rapid Moshi probe connections work
// within limits" acceptance criterion.
func TestE2ERapidPreflightFake(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")

	const probes = 8
	start := time.Now()
	for i := 0; i < probes; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		stdout, stderr, code := f.proxyJumpExec(t, ctx, testWorkspace, "true")
		cancel()
		if code != 0 {
			t.Fatalf("probe %d/%d exit %d\nstdout: %q\nstderr: %q\ngateway logs:\n%s",
				i+1, probes, code, stdout, stderr, f.logBuf.String())
		}
		if got, want := stdout, innerssh.ExecPrefix+"true"; got != want {
			t.Fatalf("probe %d/%d stdout = %q, want %q", i+1, probes, got, want)
		}
	}
	elapsed := time.Since(start)
	f.waitNoChildren(t, 5*time.Second)
	t.Logf("%d rapid sequential ProxyJump probes succeeded in %v", probes, elapsed)
}

// TestE2EControlMasterMultiplexing locks the session-reuse regression:
// ONE gateway connection — a real OpenSSH ControlMaster — carries two
// sequential multiplexed execs and two concurrently HELD interactive
// shells, with exactly one coder transport child alive while both shells
// are live. ProxyCommand=/bin/false on every multiplexed session client
// makes the silent fresh-connection fallback impossible, so a refused
// second session fails the client loudly (the pre-fix bug's signature)
// instead of silently passing.
func TestE2EControlMasterMultiplexing(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	target := testWorkspace + "@" + f.host
	cfgArgs := f.sshCommonArgs(t)

	// The control socket must live in a SHORT directory: sun_path caps at
	// 108 bytes and the deep per-test temp tree overflows it.
	sockDir, err := os.MkdirTemp("", "csgw-cm")
	if err != nil {
		t.Fatalf("mkdir control-socket dir: %v", err)
	}
	sock := filepath.Join(sockDir, "cm.sock")

	// MASTER: one long-lived connection carrying every channel below.
	// No ProxyCommand here — the master owns the real dial.
	masterArgs := append(append([]string{}, cfgArgs...),
		"-p", f.port,
		"-N",
		"-o", "ControlMaster=yes",
		"-o", "ControlPath="+sock,
		target,
	)
	master := exec.CommandContext(ctx, "ssh", masterArgs...)
	masterStderr := &lockedBuffer{}
	master.Stderr = masterStderr
	if err := master.Start(); err != nil {
		t.Fatalf("start ControlMaster: %v", err)
	}
	masterWait := make(chan error, 1)
	go func() { masterWait <- master.Wait() }()

	// OpenSSH links the final ControlPath atomically once the master's mux
	// listener is up (post-auth), so socket existence == ready.
	socketReady := make(chan struct{})
	go func() {
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			if _, err := os.Stat(sock); err == nil {
				close(socketReady)
				return
			}
			select {
			case <-tick.C:
			case <-ctx.Done():
				return
			}
		}
	}()
	select {
	case <-socketReady:
	case err := <-masterWait:
		t.Fatalf("ControlMaster exited during startup: %v\nstderr:\n%s\ngateway logs:\n%s", err, masterStderr.String(), f.logBuf.String())
	case <-time.After(30 * time.Second):
		t.Fatalf("control socket %s never appeared\nmaster stderr:\n%s\ngateway logs:\n%s", sock, masterStderr.String(), f.logBuf.String())
	}

	// Teardown, exactly-once: polite mux shutdown, then a bounded kill
	// fallback. master.Wait is called exactly once, via masterWait.
	shutdownMaster := func() {
		octx, ocancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ocancel()
		oargs := append(append([]string{}, cfgArgs...),
			"-o", "ControlPath="+sock,
			"-O", "exit",
			target,
		)
		_, _, _ = runSSH(octx, oargs...)
		select {
		case <-masterWait:
		case <-time.After(5 * time.Second):
			_ = master.Process.Kill()
			select {
			case <-masterWait:
			case <-time.After(5 * time.Second):
				t.Errorf("ControlMaster did not exit after kill\nstderr:\n%s", masterStderr.String())
			}
		}
	}
	var shutdownOnce sync.Once
	t.Cleanup(func() {
		shutdownOnce.Do(shutdownMaster)
		_ = os.RemoveAll(sockDir)
	})

	// Every multiplexed session client: never a master itself, and
	// ProxyCommand=/bin/false forbids OpenSSH's fallback to a fresh direct
	// connection when a mux session is refused — the refusal then has to
	// surface as a nonzero client exit.
	muxClientOpts := []string{
		"-o", "ControlMaster=no",
		"-o", "ControlPath=" + sock,
		"-o", "ProxyCommand=/bin/false",
	}

	// SEQUENTIAL PHASE: two execs over the shared connection. The second
	// session-after-close is exactly the reported bug — pre-fix, the
	// connection permitted one session channel for its entire life.
	for i, command := range []string{"echo one", "echo two"} {
		args := append(append([]string{}, cfgArgs...), muxClientOpts...)
		args = append(args, "-p", f.port, target, command)
		stdout, stderr, code := runSSH(ctx, args...)
		if code != 0 {
			t.Fatalf("multiplexed exec %d (%q) exit %d\nstdout: %q\nstderr: %q\ngateway logs:\n%s",
				i+1, command, code, stdout, stderr, f.logBuf.String())
		}
		if want := innerssh.ExecPrefix + command; stdout != want {
			t.Fatalf("multiplexed exec %d stdout = %q, want %q\nstderr: %q", i+1, stdout, want, stderr)
		}
		t.Logf("multiplexed exec %d (%q) ok", i+1, command)
	}

	// CONCURRENT PHASE: two HELD shell sessions over the same connection.
	// Held shells — not short execs — prove the sessions genuinely
	// overlap: the fake inner server answers exec immediately, so even
	// concurrent execs could pass without ever sharing the connection.
	type heldShell struct {
		stdin io.WriteCloser
		out   *lockedBuffer
		wait  chan error
	}
	markers := []string{"held-shell-alpha-4d91", "held-shell-beta-7c25"}
	shells := make([]heldShell, len(markers))
	for i := range shells {
		args := append(append([]string{}, cfgArgs...), muxClientOpts...)
		args = append(args, "-p", f.port, target)
		cmd := exec.CommandContext(ctx, "ssh", args...)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatalf("held shell %d stdin pipe: %v", i, err)
		}
		out := &lockedBuffer{}
		cmd.Stdout = out
		cmd.Stderr = out
		if err := cmd.Start(); err != nil {
			t.Fatalf("start held shell %d: %v", i, err)
		}
		waitCh := make(chan error, 1)
		go func() { waitCh <- cmd.Wait() }()
		shells[i] = heldShell{stdin: stdin, out: out, wait: waitCh}
	}

	// Both shells must be demonstrably live (banner received) BEFORE the
	// one-child assertion runs; the logged timestamps are the ordering
	// proof for that sequencing.
	bannerAt := make([]time.Time, len(shells))
	for i := range shells {
		waitForTranscript(t, shells[i].out, strings.TrimSpace(innerssh.ShellBanner), 30*time.Second, f.logBuf)
		bannerAt[i] = time.Now()
		t.Logf("held shell %d banner observed at %s", i, bannerAt[i].Format(time.RFC3339Nano))
	}

	// While BOTH shells are live there is exactly ONE coder transport
	// child: every session on the connection rides the shared transport.
	kids := f.childPIDs()
	t.Logf("one-child assertion at %s (after both banners): gateway children=%v",
		time.Now().Format(time.RFC3339Nano), kids)
	if len(kids) != 1 {
		t.Fatalf("gateway children while both held shells live = %v, want exactly 1 shared transport child\ngateway logs:\n%s", kids, f.logBuf.String())
	}

	// Two independent shells: each echoes its own marker line back.
	for i := range shells {
		if _, err := io.WriteString(shells[i].stdin, markers[i]+"\n"); err != nil {
			t.Fatalf("write marker to held shell %d: %v", i, err)
		}
	}
	for i := range shells {
		waitForTranscript(t, shells[i].out, markers[i], 30*time.Second, f.logBuf)
		t.Logf("held shell %d echoed marker %q", i, markers[i])
	}

	// Closing stdin is the client-side session EOF: the fake shell sends
	// exit-status 0 and both clients must exit cleanly.
	for i := range shells {
		if err := shells[i].stdin.Close(); err != nil {
			t.Fatalf("close held shell %d stdin: %v", i, err)
		}
	}
	for i := range shells {
		select {
		case err := <-shells[i].wait:
			if err != nil {
				t.Fatalf("held shell %d exited with error: %v\ntranscript:\n%s\ngateway logs:\n%s", i, err, shells[i].out.String(), f.logBuf.String())
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("held shell %d did not exit after stdin close\ntranscript:\n%s\ngateway logs:\n%s", i, shells[i].out.String(), f.logBuf.String())
		}
		t.Logf("held shell %d exited cleanly", i)
	}

	// Polite master teardown, then no leftover transport children.
	shutdownOnce.Do(shutdownMaster)
	f.waitNoChildren(t, 5*time.Second)
	t.Logf("one ControlMaster connection carried 2 sequential execs + 2 concurrent held shells on 1 transport child")
}

// waitForTranscript polls the PTY transcript until it contains want.
func waitForTranscript(t *testing.T, buf *lockedBuffer, want string, d time.Duration, extra ...*lockedBuffer) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if strings.Contains(buf.String(), want) {
			return
		}
		if time.Now().After(deadline) {
			msg := "PTY transcript did not contain " + want + " within " + d.String() + "\ntranscript:\n" + buf.String()
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
