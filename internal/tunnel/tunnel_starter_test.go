package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/audit"
	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/server"
	"github.com/taxilian/coder-ssh-gateway/internal/testleaks"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil/innerssh"
)

var _ server.TunnelStarter = (*TunnelStarter)(nil)

func testDeployment(t *testing.T, bin string) core.Deployment {
	t.Helper()
	u, err := url.Parse("https://coder.example.com")
	if err != nil {
		t.Fatalf("parse coder URL: %v", err)
	}
	return core.Deployment{
		ID:           uuid.New(),
		CoderURL:     u,
		TargetSuffix: "coder-gateway.example.com",
		CoderBinary:  bin,
		GlobalConfig: t.TempDir(),
		WorkingDir:   t.TempDir(),
		Autostart:    true,
		WaitMode:     "auto",
	}
}

func testCredential() core.CredentialSnapshot {
	return core.CredentialSnapshot{
		AccountID:  uuid.New(),
		Generation: 1,
		State:      core.CredentialStateValid,
		Token:      []byte("starter-test-token"),
	}
}

func testRoute() core.Route {
	return core.Route{
		RequestedHost: "w.coder-gateway.example.com",
		RequestedPort: 22,
		WorkspaceHost: "w.coder-gateway.example.com",
		DisplayTarget: "w.coder-gateway.example.com:22",
	}
}

// §38.1: start failure — missing binary yields a typed
// TUNNEL_PROCESS_START_FAILED error, the accepted channel is closed (§8.5),
// and a failure audit event is recorded.
func TestTunnelStarterStartFailure(t *testing.T) {
	defer testleaks.Verify(t)

	dep := testDeployment(t, "/nonexistent/binary/coder")
	aud := audit.NewInMemoryLogger()
	ts := &TunnelStarter{
		Launcher: &Launcher{Dep: dep, Log: slog.New(slog.DiscardHandler)},
		Audit:    aud,
		Log:      slog.New(slog.DiscardHandler),
	}

	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()

	err := ts.Start(context.Background(), ch, testRoute(), testCredential())
	if err == nil {
		t.Fatal("Start: expected error for missing binary, got nil")
	}
	var se *StartError
	if !errors.As(err, &se) {
		t.Fatalf("Start error type = %T, want *StartError", err)
	}
	if se.Code != core.TUNNEL_PROCESS_START_FAILED {
		t.Errorf("StartError.Code = %q, want %q", se.Code, core.TUNNEL_PROCESS_START_FAILED)
	}
	if !ch.IsClosed() {
		t.Error("accepted channel not closed after Start failure (§8.5)")
	}

	events := aud.Events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.EventType != EventTypeTunnelStart || ev.Result != "failure" || ev.DetailCode != core.TUNNEL_PROCESS_START_FAILED {
		t.Errorf("audit event = %+v, want tunnel_start/failure/%s", ev, core.TUNNEL_PROCESS_START_FAILED)
	}
	if ev.AccountID == "" || ev.DeploymentID == "" || ev.Target == "" {
		t.Errorf("audit event missing account/deployment/target: %+v", ev)
	}
}

// Full adapter happy path: Start blocks until the tunnel ends, a real inner
// SSH client round-trips through it, and success records no failure audit.
func TestTunnelStarterHappyRoundTrip(t *testing.T) {
	defer testleaks.Verify(t)

	bin := testutil.BuildFakeCoder(t)
	dep := testDeployment(t, bin)
	aud := audit.NewInMemoryLogger()
	ts := &TunnelStarter{
		Launcher:        &Launcher{Dep: dep, Log: slog.New(slog.DiscardHandler)},
		StartupTimeout:  5 * time.Second,
		ShutdownGrace:   500 * time.Millisecond,
		StderrRingBytes: 1024,
		Audit:           aud,
		Log:             slog.New(slog.DiscardHandler),
	}

	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()

	done := make(chan error, 1)
	go func() {
		done <- ts.Start(context.Background(), ch, testRoute(), testCredential())
	}()

	conn, chans, reqs, err := ssh.NewClientConn(
		innerssh.NewConn(clientR, clientW),
		"pipe",
		&ssh.ClientConfig{
			User:            "test",
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("inner handshake through TunnelStarter: %v", err)
	}
	client := ssh.NewClient(conn, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	out, err := session.Output("ping")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != "ECHO:ping" {
		t.Fatalf("exec output = %q, want %q", out, "ECHO:ping")
	}
	_ = session.Close()
	_ = client.Close()
	_ = clientW.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error after clean tunnel end: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after client disconnect")
	}

	for _, ev := range aud.Events() {
		if ev.EventType == EventTypeTunnelStart && ev.Result == "failure" {
			t.Errorf("unexpected failure audit event on successful tunnel: %+v", ev)
		}
	}
}

// A global-config path that violates the §18.4 rule is a typed start failure
// before any process is spawned.
func TestTunnelStarterGlobalConfigRejected(t *testing.T) {
	defer testleaks.Verify(t)

	dep := testDeployment(t, "/nonexistent/binary/coder")
	dep.GlobalConfig = "/home/user/.config/coderv2"
	ts := &TunnelStarter{
		Launcher: &Launcher{Dep: dep, Log: slog.New(slog.DiscardHandler)},
		Log:      slog.New(slog.DiscardHandler),
	}

	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()
	defer clientW.Close()

	err := ts.Start(context.Background(), ch, testRoute(), testCredential())
	var se *StartError
	if !errors.As(err, &se) || se.Code != core.TUNNEL_PROCESS_START_FAILED {
		t.Fatalf("Start error = %v, want *StartError with %q", err, core.TUNNEL_PROCESS_START_FAILED)
	}
	if !ch.IsClosed() {
		t.Error("accepted channel not closed after Start failure")
	}
}
