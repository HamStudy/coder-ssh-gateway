package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Relay-surface e2e tests: SFTP/scp subsystems, agent forwarding, and port
// forwarding (-L/-R) through the session bridge, using the real OpenSSH
// client against the fake workspace endpoint.

func TestE2ESFTPSubsystemFake(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")
	defer f.stop()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	local := filepath.Join(dir, "local.txt")
	remote := filepath.Join(dir, "remote.txt")
	content := "sftp round trip " + t.Name()
	if err := os.WriteFile(local, []byte(content), 0o600); err != nil {
		t.Fatalf("write local: %v", err)
	}
	batch := fmt.Sprintf("put %s %s\nget %s %s\n", local, remote, remote, filepath.Join(dir, "back.txt"))
	batchFile := filepath.Join(dir, "batch")
	if err := os.WriteFile(batchFile, []byte(batch), 0o600); err != nil {
		t.Fatalf("write batch: %v", err)
	}

	args := append(f.sshCommonArgs(t), "-b", batchFile, "-P", f.port, "emailsupport@"+f.host)
	cmd := exec.CommandContext(ctx, "sftp", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sftp: %v\nstderr: %s", err, stderr.String())
	}
	back, err := os.ReadFile(filepath.Join(dir, "back.txt"))
	if err != nil {
		t.Fatalf("round trip file missing: %v", err)
	}
	if string(back) != content {
		t.Fatalf("round trip content = %q, want %q", back, content)
	}
	f.waitNoChildren(t, 5*time.Second)
}

func TestE2ESCPFake(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")
	defer f.stop()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	remote := filepath.Join(dir, "scp-remote.txt")
	local := filepath.Join(dir, "scp-local.txt")
	content := "scp round trip " + t.Name()
	if err := os.WriteFile(remote, []byte(content), 0o600); err != nil {
		t.Fatalf("write remote fixture: %v", err)
	}

	args := append(f.sshCommonArgs(t), "-P", f.port, "emailsupport@"+f.host+":"+remote, local)
	cmd := exec.CommandContext(ctx, "scp", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scp: %v\nstderr: %s", err, stderr.String())
	}
	got, err := os.ReadFile(local)
	if err != nil {
		t.Fatalf("scp output missing: %v", err)
	}
	if string(got) != content {
		t.Fatalf("scp content = %q, want %q", got, content)
	}
	f.waitNoChildren(t, 5*time.Second)
}

// TestE2EAgentForwardingFake drives the full agent chain: the fake
// workspace's agent-ping exec opens an auth-agent channel that must surface
// at the real local agent started for the test.
func TestE2EAgentForwardingFake(t *testing.T) {
	requireOpenSSH(t)
	agentBin, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Skip("ssh-agent not available")
	}
	f := newGatewayFixture(t, "e2e-valid-token")
	defer f.stop()

	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	agent := exec.Command(agentBin, "-a", sock)
	out, err := agent.StdoutPipe()
	if err != nil {
		t.Fatalf("agent stdout pipe: %v", err)
	}
	if err := agent.Start(); err != nil {
		t.Fatalf("start ssh-agent: %v", err)
	}
	defer func() {
		_ = agent.Process.Kill()
		_, _ = agent.Process.Wait()
	}()
	envData, err := io.ReadAll(out)
	if err != nil {
		t.Fatalf("read agent env: %v", err)
	}
	if !strings.Contains(string(envData), "SSH_AUTH_SOCK=") {
		t.Fatalf("agent env = %q", envData)
	}
	// The agent keeps running; give the socket a moment to appear.
	sockOK := false
	for i := 0; i < 50 && !sockOK; i++ {
		if _, err := os.Stat(sock); err == nil {
			sockOK = true
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sockOK {
		t.Fatal("agent socket never appeared")
	}

	// Load the fixture client key into the test agent.
	add := exec.Command("ssh-add", f.keyPath)
	add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v\n%s", err, output)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	env := append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	args := append(f.sshCommonArgs(t), "-A", "-p", f.port, "emailsupport@"+f.host, "agent-ping")
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Env = env
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("agent-ping: %v\nstderr: %s\ngateway logs:\n%s", err, stderr.String(), f.logBuf.String())
	}
	if !strings.Contains(stdout.String(), "agent-keys=") {
		t.Fatalf("agent-ping stdout = %q, want agent-keys=N", stdout.String())
	}

	// Without -A the relayed channel open must be refused by the client.
	args = append(f.sshCommonArgs(t), "-p", f.port, "emailsupport@"+f.host, "agent-ping")
	cmd = exec.CommandContext(ctx, "ssh", args...)
	cmd.Env = env
	stdout.Reset()
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("agent-ping without -A: %v\nstderr: %s", err, stderr.String())
	}
	// Without -A the client refuses (or drops) the agent channel; the
	// invariant is that no identities ever surface.
	if strings.Contains(stdout.String(), "agent-keys=") {
		t.Fatalf("no -A stdout = %q, want no agent access", stdout.String())
	}
	f.waitNoChildren(t, 5*time.Second)
}

// TestE2ELocalForwardFake proves ssh -L resolves inside the workspace
// network through the gateway's direct-tcpip relay.
func TestE2ELocalForwardFake(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")
	defer f.stop()

	// Echo endpoint standing in for a workspace service.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(conn, conn)
				_ = conn.Close()
			}()
		}
	}()
	echoPort := echo.Addr().(*net.TCPAddr).Port

	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local reserve: %v", err)
	}
	localPort := local.Addr().(*net.TCPAddr).Port
	_ = local.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := append(f.sshCommonArgs(t), "-N",
		"-L", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", localPort, echoPort),
		"-p", f.port, "emailsupport@"+f.host)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ssh -L: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	deadline := time.Now().Add(15 * time.Second)
	var conn net.Conn
	for conn == nil {
		if time.Now().After(deadline) {
			t.Fatal("local forward never came up")
		}
		conn, err = net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(localPort), time.Second)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	marker := "local-fwd-marker"
	if _, err := io.WriteString(conn, marker); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(marker))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != marker {
		t.Fatalf("echo = %q, want %q", buf, marker)
	}
}

// TestE2ERemoteForwardFake proves ssh -R: the fake workspace binds the
// listener, and workspace-side connections tunnel back to the test's echo
// endpoint through the gateway's forwarded-tcpip relay.
func TestE2ERemoteForwardFake(t *testing.T) {
	requireOpenSSH(t)
	f := newGatewayFixture(t, "e2e-valid-token")
	defer f.stop()

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echo.Close()
	marker := "remote-fwd-marker"
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte(marker))
			_ = conn.Close()
		}
	}()
	echoPort := echo.Addr().(*net.TCPAddr).Port

	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind reserve: %v", err)
	}
	bindPort := reserve.Addr().(*net.TCPAddr).Port
	_ = reserve.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := append(f.sshCommonArgs(t), "-N",
		"-R", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", bindPort, echoPort),
		"-p", f.port, "emailsupport@"+f.host)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start ssh -R: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	deadline := time.Now().Add(15 * time.Second)
	var conn net.Conn
	for conn == nil {
		if time.Now().After(deadline) {
			t.Fatal("remote forward never came up")
		}
		conn, err = net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(bindPort), time.Second)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, len(marker))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read through remote forward: %v", err)
	}
	if string(buf) != marker {
		t.Fatalf("payload = %q, want %q", buf, marker)
	}
}
