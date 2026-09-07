package server

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/limits"
	"github.com/HamStudy/coder-ssh-gateway/internal/route"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
	"github.com/HamStudy/coder-ssh-gateway/internal/tunnel"
)

// EventTypeChannelOpen audits channel target acceptance/rejection (§34.3).
const EventTypeChannelOpen = "ssh_channel_open"

// TunnelStarter starts a workspace tunnel on an accepted direct-tcpip
// channel (§24.1 adapted: the channel is accepted by the server, the starter
// owns its lifecycle from that point). T17 provides the real implementation.
type TunnelStarter interface {
	Start(ctx context.Context, channel ssh.Channel, route core.Route, credential core.CredentialSnapshot) error
}

// WorkspaceTransportFactory creates the per-connection workspace transport
// (one `coder ssh --stdio` child + inner SSH client) shared by the session
// bridge, direct-tcpip relays, and tcpip-forward global requests.
type WorkspaceTransportFactory interface {
	NewTransport(ctx context.Context, target string, credential core.CredentialSnapshot, out ssh.Conn) (tunnel.WorkspaceTransport, error)
}

// directTCPIPRequest is the RFC 4254 §7.2 direct-tcpip open payload (§19.2).
type directTCPIPRequest struct {
	DestinationAddress string
	DestinationPort    uint32
	OriginatorAddress  string
	OriginatorPort     uint32
}

// dispatchTransportChannels implements §8.3 for transport mode: only
// direct-tcpip is admitted; every other channel type is rejected per the
// §8.5 reason matrix. direct-tcpip admission runs in its own goroutine so a
// slow credential revalidation never blocks sibling channel opens (§19.9
// multiplexing).
// rejectUnsupportedChannel maps §8.3 rejections to §8.5 reason codes.
// `session` is a known type rejected by policy → Prohibited; every other
// type is unsupported by this server → UnknownChannelType.
func (s *Server) rejectUnsupportedChannel(log *slog.Logger, newCh ssh.NewChannel) {
	s.rec.ChannelRejected()
	chType := newCh.ChannelType()
	// Reaching dispatch requires authentication, so an unknown channel type
	// is a client/gateway incompatibility signal, not scanner noise.
	log.Warn("rejecting unsupported channel type", slog.String("channel_type", chType))
	_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
}

// workspaceContext is the per-connection lazily-created workspace transport
// plus the context every admission path shares. The transport spawns on
// first need: the session channel, an arbitrary direct-tcpip target
// (ssh -L/-D), or a tcpip-forward global request (ssh -R).
type workspaceContext struct {
	srv    *Server
	state  *sshauth.ConnState
	perms  sshauth.FinalPerms
	target string
	out    ssh.Conn

	mu          sync.Mutex
	tr          tunnel.WorkspaceTransport
	releaseProc func()
}

// transport returns the connection transport, creating it (with full
// credential validation) on first use.
func (w *workspaceContext) transport(ctx context.Context) (tunnel.WorkspaceTransport, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.tr != nil {
		return w.tr, nil
	}
	snap, verr := w.srv.loadValidatedCredential(ctx, w.state, w.perms)
	if verr != nil {
		return nil, verr
	}
	return w.createLocked(ctx, snap)
}

// bindTransport creates-or-returns the transport using an already-validated
// credential snapshot (the session channel path).
func (w *workspaceContext) bindTransport(ctx context.Context, snap core.CredentialSnapshot) (tunnel.WorkspaceTransport, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.tr != nil {
		return w.tr, nil
	}
	return w.createLocked(ctx, snap)
}

func (w *workspaceContext) createLocked(ctx context.Context, snap core.CredentialSnapshot) (tunnel.WorkspaceTransport, error) {
	relProc, ok := w.srv.cfg.Counters.AcquireCoderProcess()
	if !ok {
		w.srv.rec.LimitRejection(string(limits.ReasonCoderProcess))
		return nil, &transportError{detail: core.TUNNEL_LIMIT_REACHED}
	}
	tr, err := w.srv.cfg.WorkspaceTransports.NewTransport(ctx, w.target, snap, w.out)
	if err != nil {
		relProc()
		return nil, &transportError{detail: startErrorCode(err), err: err}
	}
	w.tr = tr
	w.releaseProc = relProc
	return tr, nil
}

// existing returns the transport without creating one.
func (w *workspaceContext) existing() tunnel.WorkspaceTransport {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tr
}

// close tears the transport down and waits for the session bridge and
// inbound relays to unwind. Called after the dispatch loop ends.
func (w *workspaceContext) close() {
	w.mu.Lock()
	tr := w.tr
	w.tr = nil
	release := w.releaseProc
	w.releaseProc = nil
	w.mu.Unlock()
	if tr != nil {
		tr.Close()
	}
	if release != nil {
		release()
	}
}

// transportError carries a failure reason for lazy transport creation.
type transportError struct {
	detail string
	err    error
}

func (e *transportError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return e.detail
}

func startErrorCode(err error) string {
	var se *tunnel.StartError
	if errors.As(err, &se) {
		return se.Code
	}
	return core.TUNNEL_PROCESS_START_FAILED
}

// dispatchWorkspaceChannels implements §8.3 for workspace connections. The
// username is the workspace target for session channels. direct-tcpip
// channels with a workspace target (:22) get a dedicated jump tunnel;
// everything else relays through the connection transport (ssh -L/-D).
// Session channels: exactly one (first wins). Channel handlers run in their
// own goroutines so multiplexing never blocks on a slow channel (§19.9).
func (s *Server) dispatchWorkspaceChannels(ctx context.Context, wc *workspaceContext, channels <-chan ssh.NewChannel) {
	served := false
	defer wc.close()
	var wg sync.WaitGroup
	for newCh := range channels {
		// Debug-log every open: a client that closes pre-session (or never
		// opens) is invisible otherwise, and the missing open is the datum.
		s.log.Debug("channel open request",
			slog.String("connection_id", wc.state.ID()),
			slog.String("channel_type", newCh.ChannelType()),
		)
		switch newCh.ChannelType() {
		case "session":
			if served || s.cfg.WorkspaceTransports == nil {
				s.rec.ChannelRejected()
				s.log.Info("session channel rejected", "reason", "already served or no factory", "served", served)
				_ = newCh.Reject(ssh.Prohibited, "workspace connections permit one session channel")
				continue
			}
			if s.draining.Load() {
				s.rec.ChannelRejected()
				s.log.Info("session channel rejected", "reason", "draining")
				_ = newCh.Reject(ssh.Prohibited, "server is shutting down")
				continue
			}
			served = true
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.admitWorkspaceSession(ctx, wc, newCh)
			}()
		case "direct-tcpip":
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.admitDirectTCPIP(ctx, wc, newCh)
			}()
		default:
			s.rejectUnsupportedChannel(s.log.With(slog.String("connection_id", wc.state.ID())), newCh)
		}
	}
	wg.Wait()
}

func (s *Server) admitWorkspaceSession(ctx context.Context, wc *workspaceContext, newCh ssh.NewChannel) {
	state, perms, target := wc.state, wc.perms, wc.target
	// Parsing happens here, after the enrolled key has been authenticated.
	if perms.MustReconnect {
		s.rec.ChannelRejected()
		_ = newCh.Reject(ssh.Prohibited, "reconnect required")
		return
	}
	rt, err := route.ParseBareTarget(target)
	if err != nil {
		ch, requests, acceptErr := newCh.Accept()
		if acceptErr == nil {
			go drainChannelRequests(s.log, requests)
			_, _ = ch.Stderr().Write([]byte("workspace target is invalid or unavailable\r\n"))
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 255}))
			_ = ch.CloseWrite()
			_ = ch.Close()
		}
		s.rec.ChannelRejected()
		s.auditChannelOpen(state, perms, "", false, route.CodeOf(err))
		s.log.Warn("session target rejected",
			slog.String("connection_id", state.ID()),
			slog.String("user", target),
			slog.String("detail_code", route.CodeOf(err)),
		)
		return
	}
	relChan, ok := s.cfg.Counters.AcquireChannel(state.ID())
	if !ok {
		s.rejectChannelLimit(state, perms, newCh, string(limits.ReasonChannelConn))
		return
	}
	defer relChan()
	relAcct, ok := s.cfg.Counters.AcquireChannelAccount(perms.AccountID)
	if !ok {
		s.rejectChannelLimit(state, perms, newCh, string(limits.ReasonChannelAccount))
		return
	}
	defer relAcct()

	snap, err := s.cfg.Auth.Store.LoadCredential(ctx, perms.AccountID)
	if err != nil {
		s.rec.ChannelRejected()
		s.auditChannelOpen(state, perms, rt.DisplayTarget, false, core.STORE_UNAVAILABLE)
		s.log.Warn("credential store unavailable at session open",
			slog.String("connection_id", state.ID()),
			slog.String("account_id", perms.AccountID.String()),
			slog.String("detail", err.Error()),
		)
		_ = newCh.Reject(ssh.ConnectionFailed, "credential store unavailable")
		return
	}
	defer secretbox.BestEffortWipe(snap.Token)
	if snap.State == core.CredentialStateInvalid || snap.State == core.CredentialStateMissing || len(snap.Token) == 0 {
		detail := core.AUTH_CREDENTIAL_UNAUTHORIZED
		if snap.State == core.CredentialStateMissing {
			detail = core.AUTH_CREDENTIAL_MISSING
		}
		_ = state.Close()
		s.rec.ChannelRejected()
		s.auditChannelOpen(state, perms, rt.DisplayTarget, false, detail)
		_ = newCh.Reject(ssh.Prohibited, "credential no longer valid; reconnect")
		return
	}
	if time.Since(snap.LastValidatedAt) > s.cfg.CacheTTL {
		if _, err := s.cfg.Auth.Verifier.VerifyCached(ctx, perms.AccountID, snap.Generation, snap.Token); err != nil {
			s.rejectOnRevalidationFailure(ctx, state, perms, rt, newCh, err)
			return
		}
		snap.LastValidatedAt = time.Now()
	}
	ch, requests, err := newCh.Accept()
	if err != nil {
		return
	}
	s.rec.ChannelAccepted()
	s.activeChannels.Add(1)
	defer s.activeChannels.Add(-1)
	defer s.rec.ChannelClosed()
	s.auditChannelOpen(state, perms, rt.DisplayTarget, true, "")

	// §19.9: the transport starts concurrently while BridgePendingSession
	// answers the client's early session requests — mobile clients time out
	// on replies that wait for the child spawn + inner handshake, and the
	// deferred bridge acknowledges and replays those requests instead.
	pending := make(chan tunnel.PendingTransport, 1)
	go func() {
		tr, err := wc.bindTransport(ctx, snap)
		pending <- tunnel.PendingTransport{Tr: tr, Err: err}
	}()
	if err := tunnel.BridgePendingSession(ctx, ch, requests, pending, s.log); err != nil {
		var te *transportError
		if errors.As(err, &te) {
			s.log.Warn("workspace transport creation failed", slog.String("code", te.detail), slog.String("detail", err.Error()))
		}
		_ = ch.Close()
	}
}

// admitDirectTCPIP routes one direct-tcpip open (§19.1 admission order).
// Workspace targets on port 22 get a dedicated jump tunnel (ProxyJump);
// every other target relays through the connection transport so ssh -L/-D
// resolves inside the workspace network.
func (s *Server) admitDirectTCPIP(ctx context.Context, wc *workspaceContext, newCh ssh.NewChannel) {
	state, perms := wc.state, wc.perms
	log := s.log.With(
		slog.String("connection_id", state.ID()),
		slog.String("account_id", perms.AccountID.String()),
	)

	// §32 step 3: reject new channel opens once shutdown drain has begun.
	if s.draining.Load() {
		s.rec.ChannelRejected()
		_ = newCh.Reject(ssh.Prohibited, "server is shutting down")
		return
	}

	// §19.1(2): defense in depth — a must_reconnect connection should have
	// been closed right after the handshake (§13.6).
	if perms.MustReconnect {
		s.rec.ChannelRejected()
		_ = newCh.Reject(ssh.Prohibited, "reconnect required")
		return
	}

	// §19.1(3): decode the RFC 4254 payload.
	var req directTCPIPRequest
	if err := ssh.Unmarshal(newCh.ExtraData(), &req); err != nil {
		s.rec.ChannelRejected()
		s.auditChannelOpen(state, perms, "", false, core.ROUTE_INVALID_PAYLOAD)
		_ = newCh.Reject(ssh.Prohibited, "invalid direct-tcpip payload")
		return
	}

	// §19.1(5): the originator fields are client-supplied and never used
	// for authorization or audit attribution (§5.1) — debug logging only.
	log.Debug("direct-tcpip open request",
		slog.String("originator", req.OriginatorAddress),
		slog.Uint64("originator_port", uint64(req.OriginatorPort)),
	)

	// §19.1(4): workspace targets (§17.4/§17.5) take the jump path.
	rt, err := s.cfg.RouteCodec.ParseDirectTCPIP(req.DestinationAddress, req.DestinationPort)
	if err == nil {
		s.startJumpTunnel(ctx, wc, newCh, rt, log)
		return
	}
	s.relayDirectTCPIP(ctx, wc, newCh, log)
}

// startJumpTunnel is the §19.1 dedicated-child path for workspace:22
// targets: full per-channel validation, then a TunnelStarter child.
func (s *Server) startJumpTunnel(ctx context.Context, wc *workspaceContext, newCh ssh.NewChannel, rt core.Route, log *slog.Logger) {
	state, perms := wc.state, wc.perms
	// §19.1(6): channel + process admission semaphores. Released when the
	// tunnel ends (§19.1 step 15); released immediately on later failure.
	relChan, ok := s.cfg.Counters.AcquireChannel(state.ID())
	if !ok {
		s.rec.LimitRejection(string(limits.ReasonChannelConn))
		s.rejectChannelLimit(state, perms, newCh, string(limits.ReasonChannelConn))
		return
	}
	relAcct, ok := s.cfg.Counters.AcquireChannelAccount(perms.AccountID)
	if !ok {
		s.rec.LimitRejection(string(limits.ReasonChannelAccount))
		relChan()
		s.rejectChannelLimit(state, perms, newCh, string(limits.ReasonChannelAccount))
		return
	}
	relProc, ok := s.cfg.Counters.AcquireCoderProcess()
	if !ok {
		s.rec.LimitRejection(string(limits.ReasonCoderProcess))
		relAcct()
		relChan()
		s.rejectChannelLimit(state, perms, newCh, string(limits.ReasonCoderProcess))
		return
	}
	defer relProc()
	defer relAcct()
	defer relChan()

	// §19.1(7) + §19.9: reload the newest credential generation; the
	// permissions snapshot taken at auth time may be stale.
	snap, err := s.cfg.Auth.Store.LoadCredential(ctx, perms.AccountID)
	if err != nil {
		log.Warn("credential store unavailable at channel open", slog.String("detail", err.Error()))
		s.rec.ChannelRejected()
		s.auditChannelOpen(state, perms, rt.DisplayTarget, false, core.STORE_UNAVAILABLE)
		_ = newCh.Reject(ssh.ConnectionFailed, "credential store unavailable")
		return
	}
	if snap.State == core.CredentialStateInvalid || snap.State == core.CredentialStateMissing {
		// §19.9: reject the channel AND close the entire outer transport;
		// the next connection enters partial-auth renewal.
		detail := core.AUTH_CREDENTIAL_UNAUTHORIZED
		if snap.State == core.CredentialStateMissing {
			detail = core.AUTH_CREDENTIAL_MISSING
		}
		log.Info("credential no longer valid at channel open; closing transport",
			slog.String("state", snap.State.String()),
		)
		secretbox.BestEffortWipe(snap.Token) // §21.5: token not passed onward
		s.rec.ChannelRejected()
		s.auditChannelOpen(state, perms, rt.DisplayTarget, false, detail)
		_ = newCh.Reject(ssh.Prohibited, "credential no longer valid; reconnect")
		_ = state.Close()
		return
	}
	if snap.Generation != perms.CredentialGeneration {
		// Newer VALID generation: the auth-time permissions were stale in
		// the good direction — proceed with the newer snapshot (§19.9).
		log.Debug("credential generation advanced since auth; using newer snapshot",
			slog.Int64("auth_generation", perms.CredentialGeneration),
			slog.Int64("current_generation", snap.Generation),
		)
	}

	// §19.1(8) + §11.5: revalidate when the cached validation is stale.
	if time.Since(snap.LastValidatedAt) > s.cfg.CacheTTL {
		if _, err := s.cfg.Auth.Verifier.VerifyCached(ctx, perms.AccountID, snap.Generation, snap.Token); err != nil {
			secretbox.BestEffortWipe(snap.Token) // §21.5: token not passed onward
			s.rejectOnRevalidationFailure(ctx, state, perms, rt, newCh, err)
			return
		}
		snap.LastValidatedAt = time.Now()
	}

	// §19.1(10): accept before any slow work (workspace autostart can take
	// minutes; a pending channel open would hit client timeouts).
	ch, requests, err := newCh.Accept()
	if err != nil {
		secretbox.BestEffortWipe(snap.Token) // §21.5: token not passed onward
		log.Debug("channel accept failed", slog.String("detail", err.Error()))
		return
	}
	s.rec.ChannelAccepted()
	s.activeChannels.Add(1)
	defer s.activeChannels.Add(-1)
	defer s.rec.ChannelClosed()

	// §19.10: a direct-tcpip channel ordinarily carries no requests, but
	// the request channel must still be drained.
	go drainChannelRequests(log, requests)

	s.auditChannelOpen(state, perms, rt.DisplayTarget, true, "")

	// §19.1(11+): the starter owns the channel from here (T17).
	if err := s.cfg.TunnelStarter.Start(ctx, ch, rt, snap); err != nil {
		log.Debug("tunnel start failed", slog.String("detail", err.Error()))
		_ = ch.Close()
	}
}

// relayDirectTCPIP relays a non-workspace direct-tcpip open through the
// connection transport. The transport dial happens inside RelayChannel
// before acceptance, so in-workspace connect failures surface to the client
// as native SSH_OPEN_CONNECT_FAILED rejections. Relay targets are
// client-supplied free-form host:port and are never audited (§34.1).
func (s *Server) relayDirectTCPIP(ctx context.Context, wc *workspaceContext, newCh ssh.NewChannel, log *slog.Logger) {
	state, perms := wc.state, wc.perms
	if s.cfg.WorkspaceTransports == nil {
		s.rec.ChannelRejected()
		s.auditChannelOpen(state, perms, "", false, core.TUNNEL_PROCESS_START_FAILED)
		log.Warn("relay rejected: no transport factory configured")
		_ = newCh.Reject(ssh.Prohibited, "port forwarding unavailable")
		return
	}
	relChan, ok := s.cfg.Counters.AcquireChannel(state.ID())
	if !ok {
		s.rec.LimitRejection(string(limits.ReasonChannelConn))
		s.rejectChannelLimit(state, perms, newCh, string(limits.ReasonChannelConn))
		return
	}
	defer relChan()
	relAcct, ok := s.cfg.Counters.AcquireChannelAccount(perms.AccountID)
	if !ok {
		s.rec.LimitRejection(string(limits.ReasonChannelAccount))
		s.rejectChannelLimit(state, perms, newCh, string(limits.ReasonChannelAccount))
		return
	}
	defer relAcct()

	tr, err := wc.transport(ctx)
	if err != nil {
		s.rejectTransportFailure(ctx, state, perms, newCh, err)
		return
	}
	s.rec.ChannelAccepted()
	s.activeChannels.Add(1)
	defer s.activeChannels.Add(-1)
	defer s.rec.ChannelClosed()
	s.auditChannelOpen(state, perms, "", true, "")
	tr.RelayChannel(newCh)
}

// rejectTransportFailure maps a lazy transport creation failure to channel
// rejections with the same consequences as channel-open revalidation.
func (s *Server) rejectTransportFailure(ctx context.Context, state *sshauth.ConnState, perms sshauth.FinalPerms, newCh ssh.NewChannel, err error) {
	var te *transportError
	if !errors.As(err, &te) {
		s.rec.ChannelRejected()
		s.log.Warn("relay rejected: workspace is unavailable", slog.String("connection_id", state.ID()), slog.String("detail", err.Error()))
		_ = newCh.Reject(ssh.ConnectionFailed, "workspace is unavailable")
		return
	}
	log := s.log.With(slog.String("connection_id", state.ID()), slog.String("account_id", perms.AccountID.String()), slog.String("detail_code", te.detail))
	switch {
	case te.detail == core.STORE_UNAVAILABLE:
		s.rec.ChannelRejected()
		s.auditChannelOpen(state, perms, "", false, core.STORE_UNAVAILABLE)
		log.Warn("relay rejected: credential store unavailable")
		_ = newCh.Reject(ssh.ConnectionFailed, "credential store unavailable")
	case te.detail == core.AUTH_CODER_UNAVAILABLE:
		s.rec.ChannelRejected()
		s.auditChannelOpen(state, perms, "", false, core.AUTH_CODER_UNAVAILABLE)
		log.Warn("relay rejected: coder control plane unavailable")
		_ = newCh.Reject(ssh.ConnectionFailed, "coder control plane unavailable")
	default:
		s.rec.ChannelRejected()
		s.auditChannelOpen(state, perms, "", false, te.detail)
		log.Warn("relay rejected: credential no longer valid")
		_ = newCh.Reject(ssh.Prohibited, "credential no longer valid; reconnect")
		_ = state.Close()
	}
}

// rejectOnRevalidationFailure maps a failed channel-open revalidation to
// §8.5 reasons and the §19.9/§11.4 transport-level consequences.
func (s *Server) rejectOnRevalidationFailure(ctx context.Context, state *sshauth.ConnState, perms sshauth.FinalPerms, rt core.Route, newCh ssh.NewChannel, err error) {
	s.log.Warn("channel-open revalidation failed",
		slog.String("connection_id", state.ID()),
		slog.String("account_id", perms.AccountID.String()),
		slog.String("detail", err.Error()))
	detail := core.AUTH_CREDENTIAL_UNAUTHORIZED
	var ce *core.CredentialError
	if errors.As(err, &ce) && ce.DetailCode != "" {
		detail = ce.DetailCode
	}

	if core.KindOf(err) == core.ControlPlaneUnavailable {
		// §11.4: unavailability is NOT a credential failure — reject the
		// channel, never mark the credential invalid, keep the transport.
		s.rec.ChannelRejected()
		s.auditChannelOpen(state, perms, rt.DisplayTarget, false, core.AUTH_CODER_UNAVAILABLE)
		_ = newCh.Reject(ssh.ConnectionFailed, "coder control plane unavailable")
		return
	}

	// Missing/invalid (and non-renewable rejection kinds): §19.9 — reject
	// the channel and close the entire outer transport so the next
	// connection enters renewal.
	s.rec.ChannelRejected()
	s.auditChannelOpen(state, perms, rt.DisplayTarget, false, detail)
	_ = newCh.Reject(ssh.Prohibited, "credential no longer valid; reconnect")
	_ = state.Close()
}

func (s *Server) rejectChannelLimit(state *sshauth.ConnState, perms sshauth.FinalPerms, newCh ssh.NewChannel, reason string) {
	s.rec.ChannelRejected()
	s.auditChannelOpen(state, perms, "", false, core.TUNNEL_LIMIT_REACHED)
	s.log.Warn("channel rejected at limit",
		slog.String("connection_id", state.ID()),
		slog.String("account_id", perms.AccountID.String()),
		slog.String("reason", reason),
	)
	_ = newCh.Reject(ssh.ResourceShortage, "channel limit reached")
}

// drainChannelRequests answers every channel request false until the
// channel closes (§19.10). Never leaves the request channel unread, and
// never refuses silently: relays deliberately carry no session requests,
// so any request here is a client/gateway mismatch worth seeing.
func drainChannelRequests(log *slog.Logger, requests <-chan *ssh.Request) {
	for req := range requests {
		if req == nil {
			continue
		}
		log.Debug("relay channel request refused",
			slog.String("request_type", req.Type),
			slog.Bool("want_reply", req.WantReply),
		)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

// auditChannelOpen records one §34.3 channel target accepted/rejected
// event. target is emitted only when it is the strict-grammar DisplayTarget
// (log-safe); untrusted request bytes are never audited.
func (s *Server) auditChannelOpen(state *sshauth.ConnState, perms sshauth.FinalPerms, target string, success bool, detail string) {
	if s.cfg.Audit == nil {
		return
	}
	result := sshauth.ResultFailure
	if success {
		result = sshauth.ResultSuccess
	}
	gen := perms.CredentialGeneration
	ev := audit.Event{
		ID:                   uuid.NewString(),
		OccurredAtMs:         time.Now().UnixMilli(),
		ConnectionID:         state.ID(),
		AccountID:            perms.AccountID.String(),
		SSHKeyID:             perms.SSHKeyID.String(),
		EventType:            EventTypeChannelOpen,
		Result:               result,
		PeerAddress:          state.PeerAddr(),
		Target:               target,
		CredentialGeneration: &gen,
		DetailCode:           detail,
	}
	if perms.DeploymentID != uuid.Nil {
		ev.DeploymentID = perms.DeploymentID.String()
	}
	if err := s.cfg.Audit.Record(state.Context(), ev); err != nil {
		s.log.Debug("audit record failed",
			slog.String("connection_id", state.ID()),
			slog.String("detail", err.Error()),
		)
	}
}
