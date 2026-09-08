package server

import (
	"log/slog"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/keymgmt"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
	"github.com/HamStudy/coder-ssh-gateway/internal/tunnel"
)

// This file owns the restricted channel dispatch for keymanagement-mode
// connections (login-admin@ by default): exactly one session channel
// running the account-scoped key-management UI, nothing else. This mode
// owns no workspaceContext and never creates a workspace transport — a
// credential load or coder child spawn on this path would violate the
// mode's hard rule — so every workspace channel type and every forwarding
// request is refused with a logged reason (never-silent).

// Wire reasons for keymanagement-mode refusals; stable for log grepping.
const (
	keyMgmtChannelReason = "key management connections cannot open workspace channels"
	keyMgmtGlobalReason  = "no workspace transport on key management connections"
	keyMgmtExecMessage   = "exec is not available on key management connections\r\n"
)

// dispatchKeyManagement serves one keymanagement-mode connection. Channel
// and request handlers run in their own goroutines so a slow UI never
// blocks sibling refusals; every handler terminates when the connection
// closes and tears down its channels.
func (s *Server) dispatchKeyManagement(channels <-chan ssh.NewChannel, requests <-chan *ssh.Request, state *sshauth.ConnState, perms sshauth.FinalPerms, log *slog.Logger) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handleKeyManagementGlobalRequests(state, requests)
	}()

	served := false
	var wg sync.WaitGroup
	for newCh := range channels {
		// Mirrors the workspace dispatch: a client that closes pre-session
		// (or never opens one) is invisible without this line.
		log.Debug("channel open request",
			slog.String("channel_type", newCh.ChannelType()),
		)
		switch newCh.ChannelType() {
		case "session":
			if served {
				s.rejectKeyManagementChannel(log, newCh)
				continue
			}
			if s.draining.Load() {
				s.rec.ChannelRejected()
				log.Info("session channel rejected", "reason", "draining")
				_ = newCh.Reject(ssh.Prohibited, "server is shutting down")
				continue
			}
			served = true
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.serveKeyManagementSession(newCh, state, perms, log)
			}()
		case "direct-tcpip", "forwarded-tcpip", "x11":
			// Known workspace channel types, deliberately prohibited.
			s.rejectKeyManagementChannel(log, newCh)
		default:
			s.rejectUnsupportedChannel(log, newCh)
		}
	}
	wg.Wait()
}

// rejectKeyManagementChannel refuses a known workspace channel type with
// the policy reason, logged at DEBUG (deliberate policy refusal).
func (s *Server) rejectKeyManagementChannel(log *slog.Logger, newCh ssh.NewChannel) {
	s.rec.ChannelRejected()
	log.Debug("key management channel rejected",
		slog.String("channel_type", newCh.ChannelType()),
		slog.String("reason", keyMgmtChannelReason),
	)
	_ = newCh.Reject(ssh.Prohibited, keyMgmtChannelReason)
}

// handleKeyManagementGlobalRequests answers the connection's global
// requests: keepalive stays true (clients ping through it); everything
// else — tcpip-forward included — is refused, because there is no
// workspace transport to relay to and creating one is forbidden here.
func (s *Server) handleKeyManagementGlobalRequests(state *sshauth.ConnState, requests <-chan *ssh.Request) {
	log := s.log.With(
		slog.String("connection_id", state.ID()),
		slog.String("peer", state.PeerAddr()),
	)
	for req := range requests {
		if req == nil {
			continue
		}
		if req.Type == "keepalive@openssh.com" {
			log.Debug("global request",
				slog.String("request_type", req.Type),
				slog.Bool("want_reply", req.WantReply),
			)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			continue
		}
		log.Debug("key management global request rejected",
			slog.String("request_type", req.Type),
			slog.String("reason", keyMgmtGlobalReason),
		)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

// serveKeyManagementSession owns the FIRST session channel and runs the
// key-management UI on it. Request policy:
//
//   - pty-req: validated by tunnel.ParsePtyRequest (the same parser and
//     mobile-quirk tolerance as the workspace bridge); valid requests are
//     acked and the pty flag is remembered for the UI's line editing.
//   - shell: starts the UI; when it returns (quit, client EOF, or account
//     deletion) the channel gets exit-status 0 and closes.
//   - exec: refused with a stderr message and exit-status 1.
//   - env: acked and discarded (the UI reads no environment).
//   - window-change / signal: acked as no-ops — the UI is line-based and
//     re-renders after every action, so it is inherently resize-safe and
//     has no child process to signal.
//   - subsystem and unknown request types: refused, logged at DEBUG with
//     the request type and reason.
func (s *Server) serveKeyManagementSession(newCh ssh.NewChannel, state *sshauth.ConnState, perms sshauth.FinalPerms, log *slog.Logger) {
	ch, requests, err := newCh.Accept()
	if err != nil {
		log.Debug("key management session accept failed", slog.String("detail", err.Error()))
		return
	}
	s.rec.ChannelAccepted()
	s.activeChannels.Add(1)
	defer s.activeChannels.Add(-1)
	defer s.rec.ChannelClosed()
	defer ch.Close()

	ptySeen := false
	started := false
	for req := range requests {
		if req == nil {
			continue
		}
		switch req.Type {
		case "pty-req":
			if _, _, err := tunnel.ParsePtyRequest(req.Payload); err != nil {
				log.Warn("key management pty-req rejected", slog.String("reason", err.Error()))
				replyRequest(req, false)
				continue
			}
			ptySeen = true
			replyRequest(req, true)
		case "env":
			replyRequest(req, true)
		case "window-change", "signal":
			replyRequest(req, true)
		case "shell":
			if started {
				s.refuseSessionRequest(log, req, "session already started")
				continue
			}
			started = true
			replyRequest(req, true)
			go s.runKeyManagementUI(ch, state, perms, log, ptySeen)
		case "exec":
			if started {
				s.refuseSessionRequest(log, req, "session already started")
				continue
			}
			log.Warn("exec refused on key-management connection")
			replyRequest(req, false)
			_, _ = ch.Stderr().Write([]byte(keyMgmtExecMessage))
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))
			_ = ch.CloseWrite()
			_ = ch.Close()
			return
		default:
			s.refuseSessionRequest(log, req, "request type not available on key management connections")
		}
	}
}

// refuseSessionRequest refuses a session request with a DEBUG log line
// naming the type and reason (never-silent policy refusals).
func (s *Server) refuseSessionRequest(log *slog.Logger, req *ssh.Request, reason string) {
	log.Debug("key management session request refused",
		slog.String("request_type", req.Type),
		slog.String("reason", reason),
	)
	replyRequest(req, false)
}

func replyRequest(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

// runKeyManagementUI bridges the session channel to the key-management
// service and closes the channel cleanly once it returns. Run always
// returns nil (quit, EOF, and account deletion are all clean exits).
func (s *Server) runKeyManagementUI(ch ssh.Channel, state *sshauth.ConnState, perms sshauth.FinalPerms, log *slog.Logger, pty bool) {
	account, _, _, verified := state.VerifiedIdentity()
	store, storeOK := s.cfg.Auth.Store.(keymgmt.Store)
	if !verified || !storeOK {
		// Unreachable over the wire (keys-mode finals are granted only
		// after the verified-key callback records the identity, and the
		// real auth store always satisfies keymgmt.Store) — fail loudly
		// rather than serve a half-initialized UI.
		log.Error("key management UI unavailable: identity or store missing",
			slog.Bool("verified", verified),
			slog.Bool("store", storeOK),
		)
		_, _ = ch.Stderr().Write([]byte("key management is unavailable\r\n"))
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 255}))
		_ = ch.CloseWrite()
		_ = ch.Close()
		return
	}
	svc := (&keymgmt.Service{
		Store:          store,
		Audit:          s.cfg.Audit,
		Log:            log,
		SessionKeyID:   perms.SSHKeyID,
		Account:        account,
		EnrollmentUser: s.cfg.EnrollmentUser,
		PeerAddress:    state.PeerAddr(),
		ConnectionID:   state.ID(),
	}).WithPty(pty)
	_ = svc.Run(ch, ch)
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
	_ = ch.CloseWrite()
	_ = ch.Close()
}
