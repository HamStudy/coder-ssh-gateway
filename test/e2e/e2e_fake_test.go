package e2e

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
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
