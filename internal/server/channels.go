package server

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/audit"
	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/route"
	"github.com/taxilian/coder-ssh-gateway/internal/sshauth"
)

// EventTypeChannelOpen audits channel target acceptance/rejection (§34.3).
const EventTypeChannelOpen = "ssh_channel_open"

// TunnelStarter starts a workspace tunnel on an accepted direct-tcpip
// channel (§24.1 adapted: the channel is accepted by the server, the starter
// owns its lifecycle from that point). T17 provides the real implementation.
type TunnelStarter interface {
	Start(ctx context.Context, channel ssh.Channel, route core.Route, credential core.CredentialSnapshot) error
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
func (s *Server) dispatchTransportChannels(ctx context.Context, state *sshauth.ConnState, perms sshauth.FinalPerms, channels <-chan ssh.NewChannel) {
	log := s.log.With(slog.String("connection_id", state.ID()))
	var wg sync.WaitGroup
	for newCh := range channels {
		if newCh.ChannelType() != "direct-tcpip" {
			s.rejectUnsupportedChannel(log, newCh)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.admitDirectTCPIP(ctx, state, perms, newCh)
		}()
	}
	wg.Wait()
}

// rejectUnsupportedChannel maps §8.3 rejections to §8.5 reason codes.
// `session` is a known type rejected by policy → Prohibited; every other
// type is unsupported by this server → UnknownChannelType.
func (s *Server) rejectUnsupportedChannel(log *slog.Logger, newCh ssh.NewChannel) {
	chType := newCh.ChannelType()
	if chType == "session" {
		log.Debug("rejecting session channel in transport mode (§8.3)")
		_ = newCh.Reject(ssh.Prohibited, "session channels are not permitted in transport mode")
		return
	}
	log.Debug("rejecting unsupported channel type", slog.String("channel_type", chType))
	_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
}

// admitDirectTCPIP runs the §19.1 admission order for one direct-tcpip
// channel open: cheap validation first, channel accepted only after every
// admission check passes, then handed to the TunnelStarter.
func (s *Server) admitDirectTCPIP(ctx context.Context, state *sshauth.ConnState, perms sshauth.FinalPerms, newCh ssh.NewChannel) {
	log := s.log.With(
		slog.String("connection_id", state.ID()),
		slog.String("account_id", perms.AccountID.String()),
	)

	// §19.1(2): defense in depth — a must_reconnect connection should have
	// been closed right after the handshake (§13.6).
	if perms.MustReconnect {
		_ = newCh.Reject(ssh.Prohibited, "reconnect required")
		return
	}

	// §19.1(3): decode the RFC 4254 payload.
	var req directTCPIPRequest
	if err := ssh.Unmarshal(newCh.ExtraData(), &req); err != nil {
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

	// §19.1(4): strict target validation (§17.4/§17.5).
	rt, err := s.cfg.RouteCodec.ParseDirectTCPIP(req.DestinationAddress, req.DestinationPort)
	if err != nil {
		s.auditChannelOpen(state, perms, "", false, route.CodeOf(err))
		_ = newCh.Reject(ssh.Prohibited, "target not permitted")
		return
	}

	// §19.1(6): channel + process admission semaphores. Released when the
	// tunnel ends (§19.1 step 15); released immediately on later failure.
	relChan, ok := s.cfg.Counters.AcquireChannel(state.ID())
	if !ok {
		s.rejectChannelLimit(state, perms, newCh)
		return
	}
	relAcct, ok := s.cfg.Counters.AcquireChannelAccount(perms.AccountID)
	if !ok {
		relChan()
		s.rejectChannelLimit(state, perms, newCh)
		return
	}
	relProc, ok := s.cfg.Counters.AcquireCoderProcess()
	if !ok {
		relAcct()
		relChan()
		s.rejectChannelLimit(state, perms, newCh)
		return
	}
	defer relProc()
	defer relAcct()
	defer relChan()

	// §19.1(7) + §19.9: reload the newest credential generation; the
	// permissions snapshot taken at auth time may be stale.
	snap, err := s.cfg.Auth.Store.LoadCredential(ctx, perms.AccountID)
	if err != nil {
		log.Debug("credential load failed at channel open", slog.String("detail", err.Error()))
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
			s.rejectOnRevalidationFailure(ctx, state, perms, rt, newCh, err)
			return
		}
		snap.LastValidatedAt = time.Now()
	}

	// §19.1(10): accept before any slow work (workspace autostart can take
	// minutes; a pending channel open would hit client timeouts).
	ch, requests, err := newCh.Accept()
	if err != nil {
		log.Debug("channel accept failed", slog.String("detail", err.Error()))
		return
	}

	// §19.10: a direct-tcpip channel ordinarily carries no requests, but
	// the request channel must still be drained.
	go drainChannelRequests(requests)

	s.auditChannelOpen(state, perms, rt.DisplayTarget, true, "")

	// §19.1(11+): the starter owns the channel from here (T17).
	if err := s.cfg.TunnelStarter.Start(ctx, ch, rt, snap); err != nil {
		log.Debug("tunnel start failed", slog.String("detail", err.Error()))
		_ = ch.Close()
	}
}

// rejectOnRevalidationFailure maps a failed channel-open revalidation to
// §8.5 reasons and the §19.9/§11.4 transport-level consequences.
func (s *Server) rejectOnRevalidationFailure(ctx context.Context, state *sshauth.ConnState, perms sshauth.FinalPerms, rt core.Route, newCh ssh.NewChannel, err error) {
	detail := core.AUTH_CREDENTIAL_UNAUTHORIZED
	var ce *core.CredentialError
	if errors.As(err, &ce) && ce.DetailCode != "" {
		detail = ce.DetailCode
	}

	if core.KindOf(err) == core.ControlPlaneUnavailable {
		// §11.4: unavailability is NOT a credential failure — reject the
		// channel, never mark the credential invalid, keep the transport.
		s.auditChannelOpen(state, perms, rt.DisplayTarget, false, core.AUTH_CODER_UNAVAILABLE)
		_ = newCh.Reject(ssh.ConnectionFailed, "coder control plane unavailable")
		return
	}

	// Missing/invalid (and non-renewable rejection kinds): §19.9 — reject
	// the channel and close the entire outer transport so the next
	// connection enters renewal.
	s.auditChannelOpen(state, perms, rt.DisplayTarget, false, detail)
	_ = newCh.Reject(ssh.Prohibited, "credential no longer valid; reconnect")
	_ = state.Close()
}

func (s *Server) rejectChannelLimit(state *sshauth.ConnState, perms sshauth.FinalPerms, newCh ssh.NewChannel) {
	s.auditChannelOpen(state, perms, "", false, core.TUNNEL_LIMIT_REACHED)
	_ = newCh.Reject(ssh.ResourceShortage, "channel limit reached")
}

// drainChannelRequests answers every channel request false until the
// channel closes (§19.10). Never leaves the request channel unread.
func drainChannelRequests(requests <-chan *ssh.Request) {
	for req := range requests {
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
