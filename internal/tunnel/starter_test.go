package tunnel_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/testleaks"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil"
	"github.com/taxilian/coder-ssh-gateway/internal/tunnel"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func testDeploymentStarter(t *testing.T) core.Deployment {
	t.Helper()
	u, err := url.Parse("https://coder.example.com")
	if err != nil {
		t.Fatalf("parse coder URL: %v", err)
	}
	workDir := t.TempDir()
	return core.Deployment{
		ID:           uuid.New(),
		CoderURL:     u,
		TargetSuffix: "coder-gateway.example.com",
		CoderBinary:  testutil.BuildFakeCoder(t),
		GlobalConfig: "/var/lib/coder-ssh-gateway/coder-config",
		WorkingDir:   workDir,
		Autostart:    true,
		WaitMode:     "auto",
	}
}

func testRouteStarter(host string) core.Route {
	return core.Route{
		RequestedHost: host,
		RequestedPort: 22,
		WorkspaceHost: host,
		DisplayTarget: host + ":22",
	}
}

func TestLauncherLaunchHappy(t *testing.T) {
	defer testleaks.Verify(t)

	bin := testutil.BuildFakeCoder(t)
	dep := testDeploymentStarter(t)
	dep.CoderBinary = bin

	route := testRouteStarter("examtools-docs.coder-gateway.example.com")
	cred := core.CredentialSnapshot{
		AccountID:  uuid.New(),
		Generation: 1,
		State:      core.CredentialStateValid,
		Token:      []byte("valid-token-abc123"),
	}

	launcher := &tunnel.Launcher{Dep: dep, Log: discardLogger()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := launcher.Launch(ctx, route, cred)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-proc.PID, syscall.SIGKILL)
	})

	stdoutFile, ok := proc.Stdout.(*os.File)
	if !ok {
		t.Fatal("Stdout is not an *os.File")
	}
	buf := make([]byte, 1)
	byteCh := make(chan byte, 1)
	go func() {
		n, err := stdoutFile.Read(buf)
		if n == 1 && err == nil {
			byteCh <- buf[0]
		}
	}()

	select {
	case b := <-byteCh:
		if b != 'S' {
			t.Fatalf("first byte: got %q, want 'S'", string(b))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first byte not received within 5s")
	}

	proc.Stdin.Close()
	// No Supervise here: signal both pipe consumers done so Wait may run.
	proc.StdoutDrained()
	proc.StderrDrained()
	select {
	case <-proc.Wait():
	case <-time.After(2 * time.Second):
		t.Log("Wait did not return within 2s after stdin close")
	}
}

func TestLauncherLaunchMissingBinary(t *testing.T) {
	defer testleaks.Verify(t)

	u, _ := url.Parse("https://coder.example.com")
	dep := core.Deployment{
		ID:           uuid.New(),
		CoderURL:     u,
		TargetSuffix: "coder-gateway.example.com",
		CoderBinary:  "/nonexistent/binary/coder",
		GlobalConfig: "/var/lib/coder-ssh-gateway/coder-config",
		WorkingDir:   "/var/empty/coder-ssh-gateway",
		Autostart:    true,
		WaitMode:     "auto",
	}

	route := testRouteStarter("w.coder-gateway.example.com")
	cred := core.CredentialSnapshot{
		AccountID:  uuid.New(),
		Generation: 1,
		State:      core.CredentialStateValid,
		Token:      []byte("test-token"),
	}

	launcher := &tunnel.Launcher{Dep: dep, Log: discardLogger()}

	ctx := context.Background()
	_, err := launcher.Launch(ctx, route, cred)
	if err == nil {
		t.Fatal("Launch: expected error for missing binary, got nil")
	}
	if !strings.Contains(err.Error(), core.TUNNEL_PROCESS_START_FAILED) {
		t.Errorf("Launch error: got %q, want to contain %q", err.Error(), core.TUNNEL_PROCESS_START_FAILED)
	}
}

func TestLauncherTokenNeverInArgv(t *testing.T) {
	defer testleaks.Verify(t)

	bin := testutil.BuildFakeCoder(t)
	dep := testDeploymentStarter(t)
	dep.CoderBinary = bin

	const marker = "MARKERTOKEN1234567890ABCDEFGH"
	route := testRouteStarter("w.coder-gateway.example.com")
	cred := core.CredentialSnapshot{
		AccountID:  uuid.New(),
		Generation: 1,
		State:      core.CredentialStateValid,
		Token:      []byte(marker),
	}

	launcher := &tunnel.Launcher{Dep: dep, Log: discardLogger()}

	ctx := context.Background()
	proc, err := launcher.Launch(ctx, route, cred)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-proc.PID, syscall.SIGKILL)
	})

	time.Sleep(200 * time.Millisecond)

	cmdlineData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", proc.PID))
	if err != nil {
		t.Fatalf("ReadFile /proc/%d/cmdline: %v", proc.PID, err)
	}
	cmdline := string(cmdlineData)
	if strings.Contains(cmdline, marker) {
		t.Errorf("marker token found in /proc/%d/cmdline: %q", proc.PID, cmdline)
	}

	proc.Stdin.Close()
	proc.StdoutDrained()
	proc.StderrDrained()
	select {
	case <-proc.Wait():
	case <-time.After(2 * time.Second):
		t.Log("Wait did not return within 2s after stdin close")
	}
}

func TestLauncherWaitReturnsExactlyOnce(t *testing.T) {
	defer testleaks.Verify(t)

	bin := testutil.BuildFakeCoder(t)
	dep := testDeploymentStarter(t)
	dep.CoderBinary = bin

	route := testRouteStarter("examtools-docs.coder-gateway.example.com")
	cred := core.CredentialSnapshot{
		AccountID:  uuid.New(),
		Generation: 1,
		State:      core.CredentialStateValid,
		Token:      []byte("wait-test-token"),
	}

	launcher := &tunnel.Launcher{Dep: dep, Log: discardLogger()}

	ctx := context.Background()
	proc, err := launcher.Launch(ctx, route, cred)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-proc.PID, syscall.SIGKILL)
	})

	ch1 := proc.Wait()
	ch2 := proc.Wait()
	if ch1 != ch2 {
		t.Fatal("Wait() returned different channels on subsequent calls")
	}

	proc.Stdin.Close()
	proc.StdoutDrained()
	proc.StderrDrained()

	select {
	case <-ch1:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait() channel did not fire within 5s")
	}

	select {
	case <-ch1:
		t.Fatal("Wait() channel fired a second time")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestLauncherProcessGroupKill(t *testing.T) {
	defer testleaks.Verify(t)

	bin := testutil.BuildFakeCoder(t)
	dep := testDeploymentStarter(t)
	dep.CoderBinary = bin

	route := testRouteStarter("examtools-docs.coder-gateway.example.com")
	cred := core.CredentialSnapshot{
		AccountID:  uuid.New(),
		Generation: 1,
		State:      core.CredentialStateValid,
		Token:      []byte("pgroup-test-token"),
	}

	launcher := &tunnel.Launcher{Dep: dep, Log: discardLogger()}

	ctx := context.Background()
	proc, err := launcher.Launch(ctx, route, cred)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(-proc.PID, syscall.SIGKILL); err != nil {
		t.Logf("SIGKILL to process group: %v (may already be dead)", err)
	}
	proc.StdoutDrained()
	proc.StderrDrained()

	select {
	case <-proc.Wait():
	case <-time.After(5 * time.Second):
		t.Fatal("process did not exit after SIGKILL")
	}
}
