package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/testleaks"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil/innerssh"
)

func TestWorkspaceSessionStarterStopsStartupWatchdogAfterHandshake(t *testing.T) {
	defer testleaks.Verify(t)

	timerC := make(chan time.Time)
	registry := NewRegistry()
	credential := testCredential()
	starter := &WorkspaceSessionStarter{
		Launcher:        &Launcher{Dep: testDeployment(t, testutil.BuildFakeCoder(t)), Log: slog.New(slog.DiscardHandler)},
		StartupTimeout:  time.Millisecond,
		ShutdownGrace:   time.Second,
		Registry:        registry,
		NewStartupTimer: func(time.Duration) (<-chan time.Time, func()) { return timerC, func() {} },
	}

	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()
	client, startDone := startWorkspaceSession(t, ch, clientR, clientW, starter, credential)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	// Start has synchronously stopped its watchdog before NewClientConn returns.
	// A send would be received only if the timer were still armed.
	select {
	case timerC <- time.Now():
		t.Fatal("startup watchdog remained armed after successful handshake")
	default:
	}

	out, err := session.Output("ping")
	if err != nil {
		t.Fatalf("exec after startup timeout elapsed: %v", err)
	}
	if string(out) != "ECHO:ping" {
		t.Fatalf("output = %q, want %q", out, "ECHO:ping")
	}
	_ = session.Close()
	_ = client.Close()
	_ = clientW.Close()
	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not finish")
	}
	if got := len(registry.List()); got != 0 {
		t.Fatalf("registry entries after session = %d, want 0", got)
	}
}

func TestWorkspaceSessionStarterStartupFailureTerminatesChild(t *testing.T) {
	defer testleaks.Verify(t)

	bin := filepath.Join(t.TempDir(), "blocked-coder")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n"), 0o700); err != nil {
		t.Fatalf("write blocked coder: %v", err)
	}
	timerC := make(chan time.Time, 1)
	timerC <- time.Now()
	starter := &WorkspaceSessionStarter{
		Launcher:        &Launcher{Dep: testDeployment(t, bin), Log: slog.New(slog.DiscardHandler)},
		StartupTimeout:  time.Hour,
		ShutdownGrace:   time.Second,
		NewStartupTimer: func(time.Duration) (<-chan time.Time, func()) { return timerC, func() {} },
	}
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()
	done := make(chan error, 1)
	go func() { done <- starter.Start(context.Background(), ch, nil, "workspace", testCredential()) }()
	select {
	case err := <-done:
		var startErr *StartError
		if !errors.As(err, &startErr) || startErr.Code != core.TUNNEL_START_TIMEOUT {
			t.Fatalf("Start error = %v, want startup timeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup failure did not reap child promptly")
	}
}

func TestWorkspaceSessionStarterRelaysNonzeroExitWithoutFailure(t *testing.T) {
	defer testleaks.Verify(t)

	starter := &WorkspaceSessionStarter{Launcher: &Launcher{Dep: testDeployment(t, testutil.BuildFakeCoder(t)), Log: slog.New(slog.DiscardHandler)}}
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()
	client, done := startWorkspaceSession(t, ch, clientR, clientW, starter, testCredential())
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	out, err := session.Output("exit 7")
	if len(out) != 0 {
		t.Fatalf("nonzero output = %q, want empty", out)
	}
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 7 {
		t.Fatalf("exec error = %v, want exit status 7", err)
	}
	_ = client.Close()
	_ = clientW.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned infrastructure error for remote exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not finish")
	}
}

func TestWorkspaceSessionStarterReapsOnOuterClose(t *testing.T) {
	defer testleaks.Verify(t)

	starter := &WorkspaceSessionStarter{Launcher: &Launcher{Dep: testDeployment(t, testutil.BuildFakeCoder(t)), Log: slog.New(slog.DiscardHandler)}}
	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()
	client, done := startWorkspaceSession(t, ch, clientR, clientW, starter, testCredential())
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	_ = client.Close()
	_ = clientW.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not reap the inner session after outer close")
	}
}

func workspaceTestClient(t *testing.T, reader, writer *os.File) *ssh.Client {
	t.Helper()
	conn, chans, requests, err := ssh.NewClientConn(innerssh.NewConn(reader, writer), "pipe", &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("outer handshake: %v", err)
	}
	return ssh.NewClient(conn, chans, requests)
}

func startWorkspaceSession(t *testing.T, transport ssh.Channel, reader, writer *os.File, starter *WorkspaceSessionStarter, credential core.CredentialSnapshot) (*ssh.Client, <-chan error) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		config := &ssh.ServerConfig{NoClientAuth: true}
		config.AddHostKey(signer)
		conn, channels, requests, err := ssh.NewServerConn(innerssh.NewConn(transport, transport), config)
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		go ssh.DiscardRequests(requests)
		newChannel, ok := <-channels
		if !ok {
			done <- errors.New("outer client closed without session")
			return
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- starter.Start(context.Background(), channel, requests, "workspace", credential)
	}()
	return workspaceTestClient(t, reader, writer), done
}
