package server

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/audit"
	"github.com/taxilian/coder-ssh-gateway/internal/sshauth"
)

// EventTypeHandshakeFailed is audited when ssh.NewServerConn fails — the
// rejection may have happened before any auth callback ran (§34.3).
const EventTypeHandshakeFailed = "ssh_handshake_failed"

// DetailHandshakeFailed is the stable detail code for handshake failures;
// the wire error text is never audited because it may embed client input.
const DetailHandshakeFailed = "SSH_HANDSHAKE_FAILED"

// handleConn runs one accepted TCP connection through admission, the SSH
// handshake with phase-aware deadlines (§13.5), and the §8.3 channel
// dispatch. It follows the §26 pseudocode.
func (s *Server) handleConn(raw net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic in connection handler; closing connection",
				slog.String("peer", peerIP(raw.RemoteAddr())),
				slog.Any("panic", r),
			)
			_ = raw.Close()
		}
	}()

	ip := peerIP(raw.RemoteAddr())
	if s.cfg.PreAuthGate != nil && !s.cfg.PreAuthGate(ip) {
		s.log.Debug("pre-auth rate gate refused connection", slog.String("peer", ip))
		_ = raw.Close()
		return
	}

	releaseGlobal, ok := s.cfg.Counters.AcquireGlobal()
	if !ok {
		s.log.Debug("global unauthenticated connection limit reached", slog.String("peer", ip))
		_ = raw.Close()
		return
	}
	globalHeld := true
	defer func() {
		if globalHeld {
			releaseGlobal()
		}
	}()

	releaseIP, ok := s.cfg.Counters.AcquireIP(ip)
	if !ok {
		s.log.Debug("per-IP connection limit reached", slog.String("peer", ip))
		_ = raw.Close()
		return
	}
	defer releaseIP()

	releaseHandshake, ok := s.cfg.Counters.AcquireHandshake()
	if !ok {
		s.log.Debug("handshake concurrency limit reached", slog.String("peer", ip))
		_ = raw.Close()
		return
	}
	handshakeHeld := true
	defer func() {
		if handshakeHeld {
			releaseHandshake()
		}
	}()

	conn := net.Conn(raw)
	if s.cfg.ProxyProtocol {
		asserted, err := parseProxyV1(raw, s.cfg.ProxyHeaderTimeout)
		if err != nil {
			s.log.Debug("invalid PROXY header; closing",
				slog.String("peer", ip),
				slog.String("detail", err.Error()),
			)
			_ = raw.Close()
			return
		}
		if asserted != nil {
			s.log.Debug("PROXY header accepted",
				slog.String("real_peer", ip),
				slog.String("asserted_peer", asserted.String()),
			)
			conn = &proxiedConn{Conn: raw, asserted: asserted}
		}
	}

	// ConnState is created before the handshake so the random connection ID
	// exists even for connections that never authenticate (§34.4).
	state := sshauth.NewConnState(conn)
	s.track(state)
	defer s.untrack(state.ID())
	defer state.Close()

	log := s.log.With(
		slog.String("connection_id", state.ID()),
		slog.String("peer", state.PeerAddr()),
	)

	// §13.5: single deadline covering key exchange + ordinary pubkey auth;
	// cleared after successful authentication.
	if err := conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout)); err != nil {
		log.Debug("cannot set handshake deadline", slog.String("detail", err.Error()))
		return
	}

	// §9.4: shallow copy of the immutable base config; per-connection
	// callbacks close over this connection's state. The base config's slices
	// and maps are never mutated.
	connCfg := *s.base
	pubKeyCb, verifiedKeyCb := sshauth.BuildCallbacks(s.cfg.Auth, state)
	connCfg.PublicKeyCallback = pubKeyCb
	connCfg.VerifiedPublicKeyCallback = verifiedKeyCb
	connCfg.PreAuthConnCallback = state.SetPreAuthConn
	connCfg.AuthLogCallback = func(meta ssh.ConnMetadata, method string, err error) {
		log.Debug("auth attempt",
			slog.String("method", method),
			slog.String("user", meta.User()),
			slog.Bool("ok", err == nil),
		)
	}

	serverConn, channels, requests, err := ssh.NewServerConn(conn, &connCfg)
	if err != nil {
		log.Debug("handshake failed", slog.String("detail", err.Error()))
		s.auditHandshakeFailure(state)
		return
	}
	defer serverConn.Close()

	if err := conn.SetDeadline(time.Time{}); err != nil {
		log.Debug("cannot clear handshake deadline", slog.String("detail", err.Error()))
		return
	}
	releaseHandshake()
	handshakeHeld = false
	releaseGlobal()
	globalHeld = false

	perms, err := sshauth.ParseFinalPermissions(serverConn.Permissions)
	if err != nil {
		// Permissions are server-generated; unparseable means tampering or
		// a bug — close without serving (§26).
		log.Warn("final permissions unparseable; closing", slog.String("detail", err.Error()))
		return
	}

	if perms.MustReconnect {
		// §13.6: renewal completed — close immediately, no dispatcher.
		log.Info("closing connection for forced reconnect after renewal")
		return
	}

	connCtx, cancel := context.WithCancel(state.Context())
	defer cancel()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handleGlobalRequests(connCtx, state, requests)
	}()

	// §8.3 dispatch: transport mode admits only direct-tcpip (T16);
	// maintenance mode admits one session channel via the §14 handler (T21),
	// or rejects everything when no handler is wired.
	switch perms.Mode {
	case sshauth.ModeTransport:
		s.dispatchTransportChannels(connCtx, state, perms, channels)
	case sshauth.ModeMaintenance:
		if s.cfg.MaintenanceHandler == nil {
			rejectChannelAll(channels)
			return
		}
		s.dispatchMaintenanceChannels(connCtx, state, perms, channels)
	default:
		log.Warn("unknown permission mode; closing", slog.String("mode", perms.Mode))
		rejectChannelAll(channels)
	}
}

// rejectChannelAll drains the channels channel with a Prohibited rejection
// per open so ssh.NewServerConn bookkeeping unwinds cleanly on close.
// Used by maintenance mode when no MaintenanceHandler is wired and by the
// unknown-mode guard.
func rejectChannelAll(channels <-chan ssh.NewChannel) {
	for ch := range channels {
		_ = ch.Reject(ssh.Prohibited, "channel type not permitted")
	}
}

func (s *Server) auditHandshakeFailure(state *sshauth.ConnState) {
	if s.cfg.Audit == nil {
		return
	}
	ev := audit.Event{
		ID:           uuid.NewString(),
		OccurredAtMs: time.Now().UnixMilli(),
		ConnectionID: state.ID(),
		EventType:    EventTypeHandshakeFailed,
		Result:       "failure",
		PeerAddress:  state.PeerAddr(),
		DetailCode:   DetailHandshakeFailed,
	}
	if s.cfg.Auth.DeploymentID != uuid.Nil {
		ev.DeploymentID = s.cfg.Auth.DeploymentID.String()
	}
	if err := s.cfg.Audit.Record(state.Context(), ev); err != nil {
		s.log.Debug("audit record failed",
			slog.String("connection_id", state.ID()),
			slog.String("detail", err.Error()),
		)
	}
}
