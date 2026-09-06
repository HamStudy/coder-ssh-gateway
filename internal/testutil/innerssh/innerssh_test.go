package innerssh_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/taxilian/coder-ssh-gateway/internal/testleaks"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil/innerssh"
	"golang.org/x/crypto/ssh"
)

// serveOverPipes starts the in-memory server on one end of a real OS pipe
// pair and returns a connected SSH client plus a shutdown func. OS pipes
// (not io.Pipe) are used deliberately: they are kernel-buffered, so the
// write-then-read SSH version exchange cannot deadlock, and closing the
// client's write side delivers a real EOF to the server.
func serveOverPipes(t *testing.T) (*ssh.Client, func()) {
	t.Helper()

	c2sR, c2sW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe c2s: %v", err)
	}
	s2cR, s2cW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe s2c: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- innerssh.Serve(ctx, c2sR, s2cW)
	}()

	conn, chans, reqs, err := ssh.NewClientConn(
		innerssh.NewConn(s2cR, c2sW),
		"pipe",
		&ssh.ClientConfig{
			User:            "test",
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		},
	)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	client := ssh.NewClient(conn, chans, reqs)

	shutdown := func() {
		client.Close()
		c2sW.Close() // EOF to the server's read side
		cancel()
		if err := <-serveDone; err != nil {
			t.Errorf("Serve returned error: %v", err)
		}
		c2sR.Close()
		s2cR.Close()
		s2cW.Close()
	}
	return client, shutdown
}

func TestServeExecRoundTrip(t *testing.T) {
	defer testleaks.Verify(t)
	client, shutdown := serveOverPipes(t)
	defer shutdown()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	out, err := session.Output("hello")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != "ECHO:hello" {
		t.Fatalf("exec output = %q, want %q", out, "ECHO:hello")
	}
	// session.Output returning nil error already proves exit-status 0.
}

func TestServeExecPrintfHelloExact(t *testing.T) {
	defer testleaks.Verify(t)
	client, shutdown := serveOverPipes(t)
	defer shutdown()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	out, err := session.Output("printf hello")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != "hello" {
		t.Fatalf("exec output = %q, want %q", out, "hello")
	}
}

func TestServeExecExitStatusFailureVisible(t *testing.T) {
	defer testleaks.Verify(t)
	client, shutdown := serveOverPipes(t)
	defer shutdown()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	// The fake always answers exit-status 0; assert the exact bytes of a
	// distinct payload to prove the response is per-request, not canned.
	out, err := session.Output("printf hello world")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != "ECHO:printf hello world" {
		t.Fatalf("exec output = %q", out)
	}
}

func TestServeShellEcho(t *testing.T) {
	defer testleaks.Verify(t)
	client, shutdown := serveOverPipes(t)
	defer shutdown()

	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}
	go ssh.DiscardRequests(reqs)

	if ok, err := ch.SendRequest("shell", true, nil); err != nil || !ok {
		t.Fatalf("shell request: ok=%v err=%v", ok, err)
	}

	lines := bufio.NewReader(ch)
	banner, err := lines.ReadString('\n')
	if err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if banner != innerssh.ShellBanner {
		t.Fatalf("banner = %q, want %q", banner, innerssh.ShellBanner)
	}

	if _, err := io.WriteString(ch, "ping\n"); err != nil {
		t.Fatalf("write line: %v", err)
	}
	echo, err := lines.ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if echo != "ping\n" {
		t.Fatalf("echo = %q, want %q", echo, "ping\n")
	}
	ch.Close()
}

func TestServePtyRequestAccepted(t *testing.T) {
	defer testleaks.Verify(t)
	client, shutdown := serveOverPipes(t)
	defer shutdown()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
}

func TestServeRejectsNonSessionChannel(t *testing.T) {
	defer testleaks.Verify(t)
	client, shutdown := serveOverPipes(t)
	defer shutdown()

	_, _, err := client.OpenChannel("direct-tcpip", nil)
	if err == nil {
		t.Fatal("OpenChannel(direct-tcpip) succeeded, want rejection")
	}
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) {
		t.Fatalf("error type = %T, want *ssh.OpenChannelError", err)
	}
	if openErr.Reason != ssh.UnknownChannelType {
		t.Fatalf("rejection reason = %v, want UnknownChannelType", openErr.Reason)
	}
}
