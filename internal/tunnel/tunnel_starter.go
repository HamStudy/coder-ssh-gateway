package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

// EventTypeTunnelStart is the audit event recorded when a tunnel fails after
// the channel was accepted (§8.5 connect-failure visibility). The channel
// open itself is audited by the server (§34.3).
const EventTypeTunnelStart = "tunnel_start"

type TunnelStarter struct {
	Launcher        *Launcher
	StartupTimeout  time.Duration
	PolicyTimeout   time.Duration
	ShutdownGrace   time.Duration
	StderrRingBytes int64
	Audit           audit.Logger
	Log             *slog.Logger
	Observer        Observer
	Rechecker       *Rechecker
	Registry        *Registry
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

	var tunnelID uuid.UUID
	if ts.Registry != nil {
		tunnelID = uuid.New()
		ts.Registry.Add(TunnelInfo{
			ID:           tunnelID,
			AccountID:    credential.AccountID,
			DeploymentID: ts.Launcher.Dep.ID,
			Generation:   credential.Generation,
			Route:        route,
			StartedAt:    time.Now(),
			ConnectionID: credential.AccountID.String(),
		})
	}

	ring := NewStderrRing(ts.StderrRingBytes)
	res := Supervise(ctx, proc, channel, SuperviseOpts{
		Ring:           ring,
		StartupTimeout: ts.StartupTimeout,
		PolicyTimeout:  ts.PolicyTimeout,
		Grace:          ts.ShutdownGrace,
		Log:            log,
		Observer:       ts.Observer,
	})

	if ts.Registry != nil && tunnelID != uuid.Nil {
		ts.Registry.Remove(tunnelID)
	}

	if res.Code == "" {
		return nil
	}

	if ts.Rechecker != nil && (res.Code == core.TUNNEL_CODER_EXITED || res.Code == core.TUNNEL_START_TIMEOUT) {
		ts.Rechecker.RecheckAfterFailure(ctx, credential.AccountID, credential.Generation)
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
