// Package tunnel provides the coder subprocess tunnel lifecycle: argv/env
// building, process spawning, stream proxy, supervision, and credential
// rechecking after failure.
package tunnel

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
)

// Rechecker verifies stored credentials after a tunnel child exits before
// carrying a useful inner connection, per §19.8. It is safe for concurrent use.
type Rechecker struct {
	Verifier interface {
		Verify(ctx context.Context, token []byte) (core.CoderIdentity, error)
	}
	Store interface {
		LoadCredential(ctx context.Context, accountID uuid.UUID) (core.CredentialSnapshot, error)
		MarkCredentialInvalid(ctx context.Context, accountID uuid.UUID, expectedGeneration int64, reason string) error
	}
	Log *slog.Logger
}

// RecheckAfterFailure is called when a child exits before carrying a useful
// inner connection (TUNNEL_CODER_EXITED or TUNNEL_START_TIMEOUT result,
// §19.8). It loads the credential snapshot for accountID at generation; if the
// generation on disk no longer matches, the credential changed while the child
// ran and nothing is done. Otherwise it re-validates the token via HTTP; a 401
// marks that generation invalid in the store; other error kinds are classified
// and logged but never cause a store mutation. This method never parses stderr.
func (r *Rechecker) RecheckAfterFailure(ctx context.Context, accountID uuid.UUID, generation int64) {
	log := r.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	snap, err := r.Store.LoadCredential(ctx, accountID)
	if err != nil {
		log.Debug("RecheckAfterFailure: LoadCredential failed",
			slog.String("account_id", accountID.String()),
			slog.Int64("generation", generation),
			slog.String("error", err.Error()),
		)
		return
	}
	// §21.5: the caller owns this snapshot's token; it is verified here and
	// never passed onward, so wipe it on every path.
	defer secretbox.BestEffortWipe(snap.Token)

	// Generation changed while child ran — credential replaced, do nothing.
	if snap.Generation != generation {
		log.Debug("RecheckAfterFailure: generation changed, skipping",
			slog.String("account_id", accountID.String()),
			slog.Int64("wanted_generation", generation),
			slog.Int64("current_generation", snap.Generation),
		)
		return
	}

	// No token to verify — nothing to recheck.
	if snap.State == core.CredentialStateMissing || len(snap.Token) == 0 {
		log.Debug("RecheckAfterFailure: credential missing, nothing to mark",
			slog.String("account_id", accountID.String()),
			slog.Int64("generation", generation),
		)
		return
	}

	_, err = r.Verifier.Verify(ctx, snap.Token)
	kind := core.KindOf(err)

	switch kind {
	case core.CredentialInvalid:
		// 401-class: mark this generation invalid. MarkCredentialInvalid is
		// silent on stale generation (CAS inside), so we call it optimistically.
		reason := core.AUTH_CREDENTIAL_UNAUTHORIZED
		if markErr := r.Store.MarkCredentialInvalid(ctx, accountID, generation, reason); markErr != nil {
			log.Debug("RecheckAfterFailure: MarkCredentialInvalid failed",
				slog.String("account_id", accountID.String()),
				slog.Int64("generation", generation),
				slog.String("error", markErr.Error()),
			)
		} else {
			log.Info("RecheckAfterFailure: credential marked invalid",
				slog.String("account_id", accountID.String()),
				slog.Int64("generation", generation),
			)
		}

	case "":
		// No error — token still valid, nothing to do.

	default:
		// Other kinds (forbidden, unavailable, incompatible, malformed): classify
		// and log only, never mark (§11.4). These are interesting signals but
		// not a credential state flip.
		log.Info("RecheckAfterFailure: non-401 error",
			slog.String("account_id", accountID.String()),
			slog.Int64("generation", generation),
			slog.String("kind", string(kind)),
		)
	}
}
