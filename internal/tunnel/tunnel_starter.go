package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/audit"
	"github.com/taxilian/coder-ssh-gateway/internal/core"
)

// EventTypeTunnelStart is the audit event recorded when a tunnel fails after
// the channel was accepted (§8.5 connect-failure visibility). The channel
// open itself is audited by the server (§34.3).
const EventTypeTunnelStart = "tunnel_start"

// TunnelStarter adapts the launcher + supervisor to the server's
// TunnelStarter interface: Start blocks for the tunnel's lifetime. On any
// failure the already-accepted channel is closed and a tunnel_start failure
// audit event is recorded with the core.TUNNEL_* detail code.
type TunnelStarter struct {
	Launcher        *Launcher
	StartupTimeout  time.Duration // <=0 -> DefaultStartupTimeout
	PolicyTimeout   time.Duration // 0 -> none
	ShutdownGrace   time.Duration // <=0 -> DefaultShutdownGrace
	StderrRingBytes int64         // <=0 -> DefaultStderrRingBytes
	Audit           audit.Logger  // nil -> no failure audit
	Log             *slog.Logger  // nil -> discard
}

func (ts *TunnelStarter) Start(ctx context.Context, channel ssh.Channel, route core.Route, credential core.CredentialSnapshot) error {
	log := ts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if ts.Launcher == nil {
		_ = channel.Close()
		return &StartError{Code: core.TUNNEL_PROCESS_START_FAILED, Err: fmt.Errorf("nil launcher")}
	}
	if err := EnsureGlobalConfigDir(ts.Launcher.Dep.GlobalConfig); err != nil {
		_ = channel.Close()
		ts.auditFailure(ctx, route, credential, core.TUNNEL_PROCESS_START_FAILED, 0)
		return &StartError{Code: core.TUNNEL_PROCESS_START_FAILED, Err: fmt.Errorf("global config dir: %w", err)}
	}
	proc, err := ts.Launcher.Launch(ctx, route, credential)
	if err != nil {
		_ = channel.Close()
		ts.auditFailure(ctx, route, credential, core.TUNNEL_PROCESS_START_FAILED, 0)
		return err
	}

	ring := NewStderrRing(ts.StderrRingBytes)
	res := Supervise(ctx, proc, channel, SuperviseOpts{
		Ring:           ring,
		StartupTimeout: ts.StartupTimeout,
		PolicyTimeout:  ts.PolicyTimeout,
		Grace:          ts.ShutdownGrace,
		Log:            log,
	})
	if res.Code == "" {
		return nil
	}

	_ = channel.Close()
	log.Debug("tunnel ended with failure",
		slog.String("code", res.Code),
		slog.String("target", route.DisplayTarget),
		slog.String("stderr_tail", string(res.StderrTail)),
	)
	ts.auditFailure(ctx, route, credential, res.Code, res.Duration)
	return &StartError{Code: res.Code, Err: supervisionError(res)}
}

func supervisionError(res SupervisionResult) error {
	if res.WaitErr != nil {
		return fmt.Errorf("%s: %w", res.Code, res.WaitErr)
	}
	return fmt.Errorf("%s", res.Code)
}

func (ts *TunnelStarter) auditFailure(ctx context.Context, route core.Route, credential core.CredentialSnapshot, code string, dur time.Duration) {
	if ts.Audit == nil {
		return
	}
	gen := credential.Generation
	ev := audit.Event{
		ID:                   uuid.NewString(),
		OccurredAtMs:         time.Now().UnixMilli(),
		DeploymentID:         ts.Launcher.Dep.ID.String(),
		AccountID:            credential.AccountID.String(),
		EventType:            EventTypeTunnelStart,
		Result:               "failure",
		Target:               route.DisplayTarget,
		CredentialGeneration: &gen,
		DetailCode:           code,
	}
	if dur > 0 {
		ms := dur.Milliseconds()
		ev.DurationMs = &ms
	}
	if err := ts.Audit.Record(ctx, ev); err != nil {
		if ts.Log != nil {
			ts.Log.Debug("audit record failed", slog.String("detail", err.Error()))
		}
	}
}
