package server

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
)

// credentialValidationError is the classified result of loading and
// revalidating a credential outside the channel-open paths.
type credentialValidationError struct {
	detail string
	err    error
}

func (e *credentialValidationError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return e.detail
}

// loadValidatedCredential reloads the newest credential generation and
// revalidates stale entries. The returned error classifies the failure so
// callers can apply their own transport-level consequences.
func (s *Server) loadValidatedCredential(ctx context.Context, state *sshauth.ConnState, perms sshauth.FinalPerms) (core.CredentialSnapshot, error) {
	snap, err := s.cfg.Auth.Store.LoadCredential(ctx, perms.AccountID)
	if err != nil {
		return core.CredentialSnapshot{}, &credentialValidationError{detail: core.STORE_UNAVAILABLE, err: err}
	}
	if snap.State == core.CredentialStateInvalid || snap.State == core.CredentialStateMissing || len(snap.Token) == 0 {
		secretbox.BestEffortWipe(snap.Token) // §21.5: token not passed onward
		detail := core.AUTH_CREDENTIAL_UNAUTHORIZED
		if snap.State == core.CredentialStateMissing {
			detail = core.AUTH_CREDENTIAL_MISSING
		}
		return core.CredentialSnapshot{}, &credentialValidationError{detail: detail}
	}
	if time.Since(snap.LastValidatedAt) > s.cfg.CacheTTL {
		if _, err := s.cfg.Auth.Verifier.VerifyCached(ctx, perms.AccountID, snap.Generation, snap.Token); err != nil {
			secretbox.BestEffortWipe(snap.Token) // §21.5: token not passed onward
			detail := core.AUTH_CREDENTIAL_UNAUTHORIZED
			var ce *core.CredentialError
			if errors.As(err, &ce) && ce.DetailCode != "" {
				detail = ce.DetailCode
			}
			if core.KindOf(err) == core.ControlPlaneUnavailable {
				detail = core.AUTH_CODER_UNAVAILABLE
			}
			return core.CredentialSnapshot{}, &credentialValidationError{detail: detail, err: err}
		}
		snap.LastValidatedAt = time.Now()
	}
	return snap, nil
}

// handleGlobalRequests drains the connection's global-request channel (§8.4,
// §19.10: never leave requests unread — WantReply callers would block).
// keepalive@openssh.com is answered true; tcpip-forward/cancel-tcpip-forward
// (ssh -R) relay to the workspace transport when one is available; every
// other request is answered false. wc is nil for non-workspace connections.
func (s *Server) handleGlobalRequests(ctx context.Context, state *sshauth.ConnState, wc *workspaceContext, requests <-chan *ssh.Request) {
	log := s.log.With(
		slog.String("connection_id", state.ID()),
		slog.String("peer", state.PeerAddr()),
	)
	for req := range requests {
		switch {
		case req.Type == "keepalive@openssh.com":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case req.Type == "tcpip-forward" || req.Type == "cancel-tcpip-forward":
			s.relayForwardRequest(ctx, wc, req, log)
		default:
			log.Debug("global request rejected", slog.String("request_type", req.Type))
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// relayForwardRequest forwards an ssh -R bind/cancel to the workspace
// transport. Payloads (bind addresses) are client-supplied and never logged
// (§34.1); the workspace side decides what may bind.
func (s *Server) relayForwardRequest(ctx context.Context, wc *workspaceContext, req *ssh.Request, log *slog.Logger) {
	if s.cfg.WorkspaceTransports == nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	if s.draining.Load() || wc.perms.MustReconnect {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	var tr = wc.existing()
	if tr == nil && req.Type == "tcpip-forward" {
		created, err := wc.transport(ctx)
		if err != nil {
			log.Debug("forward transport creation failed", slog.String("request_type", req.Type), slog.String("detail", err.Error()))
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			return
		}
		tr = created
	}
	if tr == nil {
		// cancel-tcpip-forward with nothing ever bound: idempotent success.
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
		return
	}
	ok, payload := tr.RelayGlobalRequest(req.Type, req.WantReply, req.Payload)
	if req.WantReply {
		_ = req.Reply(ok, payload)
	}
}
