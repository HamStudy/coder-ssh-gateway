package keymgmt

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
)

// Audit event types emitted by this package.
const (
	EventTypeSSHKeyRemoved  = "ssh_key_removed"
	EventTypeAccountDeleted = "account_deleted"
)

// Stable ASCII failure detail codes. They never carry key material,
// fingerprints, or labels.
const (
	detailCurrentSessionKey = "current_session_key"
	detailStoreError        = "store_error"
)

const (
	resultSuccess = "success"
	resultFailure = "failure"
)

// recordEvent emits one audit event stamped with the ID/timestamp pattern
// used by the sshauth recorder (sshauth callbacks.go record). keyID zero
// means the event carries no key ID (account-level events). Events carry
// IDs only — never fingerprints or labels.
func (s *Service) recordEvent(eventType, result, detailCode string, keyID uuid.UUID) {
	if s.Audit == nil {
		return
	}
	ev := audit.Event{
		ConnectionID: s.ConnectionID,
		PeerAddress:  s.PeerAddress,
		AccountID:    s.Account.ID.String(),
		EventType:    eventType,
		Result:       result,
		DetailCode:   detailCode,
	}
	if s.Account.DeploymentID != uuid.Nil {
		ev.DeploymentID = s.Account.DeploymentID.String()
	}
	if keyID != uuid.Nil {
		ev.SSHKeyID = keyID.String()
	}
	ev.ID = uuid.NewString()
	ev.OccurredAtMs = time.Now().UnixMilli()
	if err := s.Audit.Record(context.Background(), ev); err != nil {
		s.logger().Debug("keymgmt: audit record failed",
			slog.String("event_type", eventType),
			slog.String("detail", err.Error()))
	}
}
