package server

import (
	"context"
	"log/slog"

	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
)

// handleGlobalRequests drains the connection's global-request channel (§8.4,
// §19.10: never leave requests unread — WantReply callers would block). Only
// keepalive@openssh.com is answered true; reverse-forwarding and every other
// request are answered false.
func (s *Server) handleGlobalRequests(ctx context.Context, state *sshauth.ConnState, requests <-chan *ssh.Request) {
	log := s.log.With(
		slog.String("connection_id", state.ID()),
		slog.String("peer", state.PeerAddr()),
	)
	for req := range requests {
		allow := req.Type == "keepalive@openssh.com"
		switch {
		case allow:
			log.Debug("global keepalive answered")
		case req.Type == "tcpip-forward" || req.Type == "cancel-tcpip-forward":
			// §8.4: the outer server is not a general bastion; reverse
			// forwarding is never available. Payload is never logged (§34.1).
			log.Debug("reverse forwarding rejected", slog.String("request_type", req.Type))
		default:
			log.Debug("global request rejected", slog.String("request_type", req.Type))
		}
		if req.WantReply {
			_ = req.Reply(allow, nil)
		}
	}
}
