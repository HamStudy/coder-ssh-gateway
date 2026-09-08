package server

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/limits"
	"github.com/HamStudy/coder-ssh-gateway/internal/metrics"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
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
		s.log.Warn("pre-auth rate gate refused connection", slog.String("peer", ip))
		s.rec.LimitRejection(string(limits.ReasonPreAuthIP))
		s.rec.ConnectionOpened()
		s.rec.ConnectionClosed(metrics.ResultRejected)
		_ = raw.Close()
		return
	}

	s.rec.ConnectionOpened()
	connResult := metrics.ResultFailure
	defer func() { s.rec.ConnectionClosed(connResult) }()

	releaseGlobal, ok := s.cfg.Counters.AcquireGlobal()
	if !ok {
		s.log.Debug("global unauthenticated connection limit reached", slog.String("peer", ip))
		s.rec.LimitRejection(string(limits.ReasonGlobalConn))
		connResult = metrics.ResultRejected
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
		s.rec.LimitRejection(string(limits.ReasonIPConn))
		connResult = metrics.ResultRejected
		_ = raw.Close()
		return
	}
	defer releaseIP()

	releaseHandshake, ok := s.cfg.Counters.AcquireHandshake()
	if !ok {
		s.log.Debug("handshake concurrency limit reached", slog.String("peer", ip))
		s.rec.LimitRejection(string(limits.ReasonHandshake))
		connResult = metrics.ResultRejected
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
		authResult := metrics.ResultFailure
		if err == nil {
			authResult = metrics.ResultSuccess
		}
		s.rec.AuthAttempt(method, authResult)
		log.Debug("auth attempt",
			slog.String("method", method),
			slog.String("user", meta.User()),
			slog.Bool("ok", err == nil),
		)
	}

	handshakeStart := time.Now()
	serverConn, channels, requests, err := ssh.NewServerConn(conn, &connCfg)
	handshakeDur := time.Since(handshakeStart)
	if err != nil {
		s.rec.AuthDuration(metrics.ResultFailure, handshakeDur)
		log.Warn("connection handshake failed", slog.String("detail", err.Error()))
		s.auditHandshakeFailure(state)
		return
	}
	s.rec.AuthDuration(metrics.ResultSuccess, handshakeDur)
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

	// §20: per-key and per-account connection limits apply to authenticated
	// connections and are held for the connection lifetime (the pre-auth
	// global/per-IP slots are released above).
	releaseKey, ok := s.cfg.Counters.AcquireKey(perms.SSHKeyID)
	if !ok {
		log.Info("per-key connection limit reached", slog.String("ssh_key_id", perms.SSHKeyID.String()))
		s.rec.LimitRejection(string(limits.ReasonKeyConn))
		connResult = metrics.ResultRejected
		return
	}
	defer releaseKey()
	releaseAccount, ok := s.cfg.Counters.AcquireAccount(perms.AccountID)
	if !ok {
		log.Info("per-account connection limit reached", slog.String("account_id", perms.AccountID.String()))
		s.rec.LimitRejection(string(limits.ReasonAccountConn))
		connResult = metrics.ResultRejected
		return
	}
	defer releaseAccount()

	connResult = metrics.ResultSuccess

	if perms.MustReconnect {
		// §13.6: enrollment completed — this connection must never open a
		// workspace. Close it gracefully: clients open a session right
		// after auth, and a raw TCP close reads as "connection error: end
		// of file" on clients like Moshi.
		log.Info("enrollment complete; closing connection for reconnect")
		s.enrollmentGoodbye(serverConn, channels, log)
		return
	}

	connCtx, cancel := context.WithCancel(state.Context())
	defer cancel()

	// §8.3 dispatch by permission mode. The workspaceContext and the
	// workspace-backed global-request handler exist ONLY in workspace mode:
	// a keymanagement connection must never reach a workspace transport
	// (credential load + coder child spawn), so its global requests are
	// answered by the refusing handler inside dispatchKeyManagement.
	switch perms.Mode {
	case sshauth.ModeWorkspace:
		// Workspace connections admit session channels (target =
		// username) and direct-tcpip relays/jumps, in any order.
		wc := &workspaceContext{srv: s, state: state, perms: perms, target: serverConn.User(), out: serverConn}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleGlobalRequests(connCtx, state, wc, requests)
		}()
		s.dispatchWorkspaceChannels(connCtx, wc, channels)
	case sshauth.ModeKeyManagement:
		s.dispatchKeyManagement(channels, requests, state, perms, log)
	default:
		log.Warn("unknown permission mode; closing", slog.String("mode", perms.Mode))
		rejectChannelAll(log, channels)
	}
}

// enrollmentGoodbye ends an enrollment connection politely. The first
// session channel a client opens receives the reconnect confirmation on its
// stderr and exit-status 0 before the transport closes, so the client sees a
// clean "connection closed" instead of an EOF error. Clients that never open
// a session (or open other channel types) are handled within a short bound.
func (s *Server) enrollmentGoodbye(conn ssh.Conn, channels <-chan ssh.NewChannel, log *slog.Logger) {
	const goodbye = "Device enrolled.\r\n" +
		"This connection cannot open workspaces.\r\n" +
		"Reconnect with your workspace connection (<workspace>@<this-host>).\r\n"
	// 3s bound: a real client either opens its session immediately (goodbye
	// delivered) or disconnects (channels stream closes, early return). The
	// deadline only bounds silent clients.
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case newCh, ok := <-channels:
			if !ok {
				return
			}
			if newCh.ChannelType() != "session" {
				log.Warn("rejecting non-session channel on enrollment connection",
					slog.String("channel_type", newCh.ChannelType()),
				)
				_ = newCh.Reject(ssh.Prohibited, "enrollment connections cannot open channels")
				continue
			}
			ch, requests, err := newCh.Accept()
			if err != nil {
				return
			}
			go drainChannelRequests(log, requests)
			_, _ = ch.Stderr().Write([]byte(goodbye))
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			_ = ch.CloseWrite()
			_ = ch.Close()
			return
		case <-deadline.C:
			// The client never opened a session channel: the goodbye is
			// undeliverable and the client sees a raw close. Termius (iOS)
			// behaves this way; OpenSSH and Moshi open a session immediately.
			log.Info("enrollment client opened no session; closing without goodbye")
			return
		}
	}
}

// rejectChannelAll drains the channels channel with a Prohibited rejection
// per open so ssh.NewServerConn bookkeeping unwinds cleanly on close.
// Used by the unknown-permission-mode guard.
func rejectChannelAll(log *slog.Logger, channels <-chan ssh.NewChannel) {
	for ch := range channels {
		log.Debug("rejecting channel",
			slog.String("channel_type", ch.ChannelType()),
			slog.String("reason", "channel type not permitted"),
		)
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
