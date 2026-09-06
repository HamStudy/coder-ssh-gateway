package tunnel

import (
	"context"
	"log/slog"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/audit"
	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/testleaks"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil"
	"github.com/taxilian/coder-ssh-gateway/internal/testutil/innerssh"
)

type recordingObserver struct {
	mu           sync.Mutex
	started      int
	exited       []string
	bytesUp      int
	bytesDown    int
	activeGauges []int
}

func (o *recordingObserver) ProcessStarted() {
	o.mu.Lock()
	o.started++
	o.mu.Unlock()
}

func (o *recordingObserver) ProcessExited(class string) {
	o.mu.Lock()
	o.exited = append(o.exited, class)
	o.mu.Unlock()
}

func (o *recordingObserver) TunnelBytes(dir string, n int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if dir == "up" {
		o.bytesUp += n
	} else {
		o.bytesDown += n
	}
}

func (o *recordingObserver) ActiveGauge(n int) {
	o.mu.Lock()
	o.activeGauges = append(o.activeGauges, n)
	o.mu.Unlock()
}

func testDeploymentObs(t *testing.T, bin string) core.Deployment {
	t.Helper()
	u, err := url.Parse("https://coder.example.com")
	if err != nil {
		t.Fatalf("parse coder URL: %v", err)
	}
	return core.Deployment{
		ID:           uuid.New(),
		CoderURL:     u,
		CoderBinary:  bin,
		GlobalConfig: t.TempDir(),
		WorkingDir:   t.TempDir(),
		Autostart:    true,
		WaitMode:     "auto",
	}
}

func TestObserverNoopSafe(t *testing.T) {
	defer testleaks.Verify(t)
	obs := NoopObserver{}
	obs.ProcessStarted()
	obs.ProcessExited("TUNNEL_CODER_EXITED")
	obs.TunnelBytes("up", 1024)
	obs.TunnelBytes("down", 2048)
	obs.ActiveGauge(5)
}

func TestObserverHappyPath(t *testing.T) {
	defer testleaks.Verify(t)

	bin := testutil.BuildFakeCoder(t)
	dep := testDeploymentObs(t, bin)
	obs := &recordingObserver{}
	registry := NewRegistry()

	ts := &TunnelStarter{
		Launcher:        &Launcher{Dep: dep, Log: slog.New(slog.DiscardHandler)},
		StartupTimeout:  5 * time.Second,
		ShutdownGrace:   500 * time.Millisecond,
		StderrRingBytes: 1024,
		Audit:           audit.NewInMemoryLogger(),
		Log:             slog.New(slog.DiscardHandler),
		Observer:        obs,
		Registry:        registry,
	}

	ch, clientR, clientW := newFakeChannel(t)
	defer clientR.Close()

	done := make(chan error, 1)
	go func() {
		done <- ts.Start(context.Background(), ch, core.Route{
			RequestedHost: "w",
			RequestedPort: 22,
			WorkspaceHost: "w",
			DisplayTarget: "w",
		}, core.CredentialSnapshot{
			AccountID:  uuid.New(),
			Generation: 1,
			State:      core.CredentialStateValid,
			Token:      []byte("test-token"),
		})
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

	obs.mu.Lock()
	started := obs.started
	exited := append([]string(nil), obs.exited...)
	bytesUp := obs.bytesUp
	bytesDown := obs.bytesDown
	activeGauges := append([]int(nil), obs.activeGauges...)
	obs.mu.Unlock()

	if started != 1 {
		t.Errorf("ProcessStarted count = %d, want 1", started)
	}
	if len(exited) != 1 {
		t.Errorf("ProcessExited calls = %d, want 1", len(exited))
	}
	if len(exited) > 0 && exited[0] != "" {
		t.Errorf("ProcessExited class = %q, want empty (success)", exited[0])
	}
	if bytesUp == 0 {
		t.Error("bytesUp = 0, want > 0")
	}
	if bytesDown == 0 {
		t.Error("bytesDown = 0, want > 0")
	}
	if len(activeGauges) == 0 {
		t.Error("no ActiveGauge calls recorded")
	}
	if len(activeGauges) > 0 && activeGauges[len(activeGauges)-1] != 0 {
		t.Errorf("last ActiveGauge = %d, want 0 (tunnel ended)", activeGauges[len(activeGauges)-1])
	}

	if len(registry.List()) != 0 {
		t.Errorf("registry not empty after tunnel end: %d entries", len(registry.List()))
	}
}
