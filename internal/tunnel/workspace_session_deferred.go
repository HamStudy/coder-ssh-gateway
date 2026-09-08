package tunnel

import (
	"context"
	"errors"
	"log/slog"

	"golang.org/x/crypto/ssh"
)

// PendingTransport carries the outcome of an asynchronous transport start
// to BridgePendingSession.
type PendingTransport struct {
	Tr  WorkspaceTransport
	Err error
}

// BridgePendingSession serves one accepted outer session channel whose
// workspace transport is still starting (§19.9). Mobile clients open the
// session and send pty/shell within milliseconds of authentication, then
// time out if the replies wait on the child spawn + inner handshake — so
// every request that the live bridge would accept is acknowledged
// immediately, queued, and replayed into the inner session once the
// transport arrives. Requests the live bridge would refuse are refused here
// too; the two decisions must agree (see queueDecision vs
// applySessionRequest).
//
// Failure is client-legible: if the transport never starts, the queued
// session ends with the failure on stderr and exit-status 255 instead of a
// mute timeout. Success costs nothing beyond the normal connect latency.
// Blocks until the session ends.
func BridgePendingSession(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request, pending <-chan PendingTransport, log *slog.Logger) error {
	var queued []QueuedSessionRequest
	for {
		select {
		case <-ctx.Done():
			_, _ = channel.Stderr().Write([]byte("workspace session canceled\r\n"))
			finishChannelStatus(channel, 255)
			_ = channel.Close()
			return ctx.Err()
		case pt := <-pending:
			if pt.Err != nil || pt.Tr == nil {
				err := pt.Err
				if err == nil {
					err = errors.New("transport factory returned no transport")
				}
				_, _ = channel.Stderr().Write([]byte("workspace is unavailable\r\n"))
				finishChannelStatus(channel, 255)
				_ = channel.Close()
				return err
			}
			return pt.Tr.BridgeSession(ctx, channel, requests, queued)
		case req, ok := <-requests:
			if !ok {
				return errors.New("outer session closed before workspace transport ready")
			}
			if req == nil {
				log.Debug("nil request on session channel; ignored")
				continue
			}
			queueable, valid, reason := queueDecision(req.Type, req.Payload)
			if req.WantReply {
				_ = req.Reply(valid, nil)
			}
			if !valid {
				// A false reply here is client-visible and may abort the
				// client's session (§19.9 lesson): never silent.
				log.Warn("session request rejected pre-transport",
					slog.String("request_type", req.Type),
					slog.String("reason", reason),
				)
				continue
			}
			if queueable {
				queued = append(queued, QueuedSessionRequest{Type: req.Type, Payload: req.Payload})
			}
		}
	}
}

// finishChannelStatus sends exit-status and half-closes, mirroring
// finishSession's failure presentation for sessions that never started.
func finishChannelStatus(channel ssh.Channel, status uint32) {
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: status}))
	_ = channel.CloseWrite()
}

// queueDecision reports how a session request is handled before the
// transport exists: queueable requests are acknowledged and replayed later;
// valid non-queueable requests (e.g. window-change pre-start) are
// acknowledged and dropped, matching the live bridge's pre-start handling;
// invalid requests are refused with a reason (never silent). This must stay
// consistent with applySessionRequest's pre-start behavior.
func queueDecision(typ string, payload []byte) (queueable, valid bool, reason string) {
	switch typ {
	case "env":
		var r envRequest
		if ssh.Unmarshal(payload, &r) != nil || !validSessionString(r.Name, 256) || !validSessionString(r.Value, 32*1024) {
			return false, false, "malformed or invalid env request"
		}
		return true, true, ""
	case "auth-agent-req@openssh.com":
		return true, true, ""
	case "pty-req":
		if _, _, err := ParsePtyRequest(payload); err != nil {
			return false, false, "invalid pty-req: " + err.Error()
		}
		return true, true, ""
	case "shell":
		if len(payload) != 0 {
			return false, false, "shell request carries unexpected payload"
		}
		return true, true, ""
	case "exec":
		var r execRequest
		if ssh.Unmarshal(payload, &r) != nil || !validSessionString(r.Command, 4096) {
			return false, false, "malformed or invalid exec request"
		}
		return true, true, ""
	case "subsystem":
		var r subsystemRequest
		if ssh.Unmarshal(payload, &r) != nil || !validSessionString(r.Name, 64) {
			return false, false, "malformed or invalid subsystem request"
		}
		return true, true, ""
	default:
		return false, false, "unsupported request type"
	}
}
