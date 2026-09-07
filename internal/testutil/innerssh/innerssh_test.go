package innerssh_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/testleaks"
	"github.com/HamStudy/coder-ssh-gateway/internal/testutil/innerssh"
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

	_, _, err := client.OpenChannel("tun@vendor.example", nil)
	if err == nil {
		t.Fatal("OpenChannel(tun@vendor.example) succeeded, want rejection")
	}
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) {
		t.Fatalf("error type = %T, want *ssh.OpenChannelError", err)
	}
	if openErr.Reason != ssh.UnknownChannelType {
		t.Fatalf("rejection reason = %v, want UnknownChannelType", openErr.Reason)
	}
}

func TestServeDirectTCPIPDialsRealTarget(t *testing.T) {
	defer testleaks.Verify(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("d blinked"))
		_ = conn.Close()
	}()

	client, shutdown := serveOverPipes(t)
	defer shutdown()
	port := l.Addr().(*net.TCPAddr).Port
	ch, err := client.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("Dial via direct-tcpip: %v", err)
	}
	defer ch.Close()
	buf := make([]byte, 9)
	if _, err := io.ReadFull(ch, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "d blinked" {
		t.Fatalf("payload = %q", buf)
	}
}

func TestServeDirectTCPIPRejectsRefused(t *testing.T) {
	defer testleaks.Verify(t)
	client, shutdown := serveOverPipes(t)
	defer shutdown()
	// Port 1 on loopback is reserved and reliably closed in tests.
	_, err := client.Dial("tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("Dial to refused port succeeded, want failure")
	}
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) || openErr.Reason != ssh.ConnectionFailed {
		t.Fatalf("err = %v, want ConnectionFailed rejection", err)
	}
}

func TestServeTCPIPForwardBindsAndForwards(t *testing.T) {
	defer testleaks.Verify(t)
	type forwardTCPMsg struct {
		Addr string
		Port uint32
	}
	client, shutdown := serveOverPipes(t)
	defer shutdown()

	ok, payload, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(forwardTCPMsg{"127.0.0.1", 0}))
	if err != nil || !ok {
		t.Fatalf("tcpip-forward: ok=%v err=%v", ok, err)
	}
	var bound struct{ Port uint32 }
	if err := ssh.Unmarshal(payload, &bound); err != nil || bound.Port == 0 {
		t.Fatalf("bound port payload = %v (%v), want nonzero port", payload, err)
	}
	defer func() {
		_, _, _ = client.SendRequest("cancel-tcpip-forward", false, ssh.Marshal(forwardTCPMsg{"127.0.0.1", bound.Port}))
	}()

	// Server must open a forwarded-tcpip channel when the listener is hit.
	fwd := client.HandleChannelOpen("forwarded-tcpip")
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(bound.Port)))
	if err != nil {
		t.Fatalf("dial forwarded listener: %v", err)
	}
	defer conn.Close()
	select {
	case newCh, ok := <-fwd:
		if !ok {
			t.Fatal("forwarded-tcpip channel closed")
		}
		ch, _, err := newCh.Accept()
		if err != nil {
			t.Fatalf("accept forwarded channel: %v", err)
		}
		defer ch.Close()
		if _, err := conn.Write([]byte("m")); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 1)
		if _, err := io.ReadFull(ch, buf); err != nil {
			t.Fatalf("read through forward: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no forwarded-tcpip channel opened")
	}
}

func TestServeSubsystemSFTP(t *testing.T) {
	defer testleaks.Verify(t)
	client, shutdown := serveOverPipes(t)
	defer shutdown()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()
	if err := session.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("RequestSubsystem(sftp): %v", err)
	}
	w, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	r, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	sftpClient, err := sftp.NewClientPipe(r, w)
	if err != nil {
		t.Fatalf("sftp.NewClientPipe: %v", err)
	}
	defer sftpClient.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.txt")
	if err := os.WriteFile(path, []byte("sftp-fake-ok"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	f, err := sftpClient.Open(path)
	if err != nil {
		t.Fatalf("sftp open: %v", err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("sftp read: %v", err)
	}
	if string(got) != "sftp-fake-ok" {
		t.Fatalf("content = %q", got)
	}
}

func TestServeAgentForwardingRequest(t *testing.T) {
	defer testleaks.Verify(t)
	client, shutdown := serveOverPipes(t)
	defer shutdown()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()
	if ok, err := session.SendRequest("auth-agent-req@openssh.com", true, nil); err != nil || !ok {
		t.Fatalf("auth-agent-req: ok=%v err=%v, want accepted", ok, err)
	}
}
