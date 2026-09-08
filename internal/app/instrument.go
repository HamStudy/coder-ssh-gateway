package app

import (
	"context"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/coderapi"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/limits"
	"github.com/HamStudy/coder-ssh-gateway/internal/metrics"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
)

// instrumentedVerifier wraps the raw Coder verifier with the §20 global
// Coder-API concurrency semaphore and §34.2 validation metrics. It sits
// INSIDE the cached verifier so cache hits consume neither semaphore slots
// nor metric samples, and it backs the renewal/recheck paths directly.
//
// Semaphore exhaustion fails soft as ControlPlaneUnavailable (retryable):
// channel-open revalidation rejects with ConnectionFailed and keeps the
// transport (§11.4); auth-time validation shows the temporary-unavailability
// banner. Overload must never mark a credential invalid.
type instrumentedVerifier struct {
	inner    *coderapi.Verifier
	counters *limits.Counters
	rec      metrics.Recorder
}

func (v *instrumentedVerifier) Verify(ctx context.Context, token []byte) (core.CoderIdentity, error) {
	release, ok := v.counters.AcquireCoderAPI()
	if !ok {
		v.rec.LimitRejection(string(limits.ReasonCoderAPI))
		v.rec.CredentialValidation(metrics.ValidationUnavailable, 0)
		return core.CoderIdentity{}, &core.CredentialError{
			Kind:       core.ControlPlaneUnavailable,
			Retryable:  true,
			DetailCode: core.AUTH_CODER_UNAVAILABLE,
		}
	}
	defer release()
	start := time.Now()
	ident, err := v.inner.Verify(ctx, token)
	v.rec.CredentialValidation(validationResultLabel(err), time.Since(start))
	return ident, err
}

// validationResultLabel maps a verifier outcome to a bounded §34.2 result
// label; unclassified errors collapse to "error".
func validationResultLabel(err error) string {
	if err == nil {
		return metrics.ResultSuccess
	}
	switch core.KindOf(err) {
	case core.CredentialInvalid:
		return metrics.ValidationInvalid
	case core.CredentialForbidden:
		return metrics.ValidationForbidden
	case core.CredentialWrongIdentity:
		return metrics.ValidationWrongUser
	case core.ControlPlaneUnavailable:
		return metrics.ValidationUnavailable
	case core.ControlPlaneIncompatible:
		return metrics.ValidationIncompatible
	case core.CredentialMalformedReply:
		return metrics.ValidationMalformed
	case core.CredentialMissing:
		return metrics.ValidationMissing
	default:
		return metrics.ValidationError
	}
}

// instrumentedStore decorates the store methods on the hot path (key lookup,
// credential load/replace/clear/invalidation, account read) with
// store_operations_total samples. Embedding promotes every other method
// unchanged.
type instrumentedStore struct {
	*store.Store
	rec metrics.Recorder
}

func storeResult(err error) string {
	if err == nil {
		return metrics.ResultSuccess
	}
	return metrics.ResultFailure
}

func (s *instrumentedStore) LookupByPublicKey(ctx context.Context, deploymentID uuid.UUID, key ssh.PublicKey) (core.Account, core.SSHKeyRecord, error) {
	acct, rec, err := s.Store.LookupByPublicKey(ctx, deploymentID, key)
	s.rec.StoreOperation(metrics.StoreOpLookupKey, storeResult(err))
	return acct, rec, err
}

func (s *instrumentedStore) LoadCredential(ctx context.Context, accountID uuid.UUID) (core.CredentialSnapshot, error) {
	snap, err := s.Store.LoadCredential(ctx, accountID)
	s.rec.StoreOperation(metrics.StoreOpLoadCredential, storeResult(err))
	return snap, err
}

func (s *instrumentedStore) ReplaceCredential(ctx context.Context, req core.ReplaceCredentialRequest) (core.CredentialSnapshot, error) {
	snap, err := s.Store.ReplaceCredential(ctx, req)
	s.rec.StoreOperation(metrics.StoreOpReplaceCred, storeResult(err))
	return snap, err
}

func (s *instrumentedStore) GetAccount(id uuid.UUID) (core.Account, error) {
	acct, err := s.Store.GetAccount(id)
	s.rec.StoreOperation(metrics.StoreOpGetAccount, storeResult(err))
	return acct, err
}

func (s *instrumentedStore) ClearCredential(ctx context.Context, accountID uuid.UUID, expectedGeneration int64) error {
	err := s.Store.ClearCredential(ctx, accountID, expectedGeneration)
	s.rec.StoreOperation(metrics.StoreOpClearCredential, storeResult(err))
	return err
}

func (s *instrumentedStore) MarkCredentialInvalid(ctx context.Context, accountID uuid.UUID, expectedGeneration int64, reason string) error {
	err := s.Store.MarkCredentialInvalid(ctx, accountID, expectedGeneration, reason)
	s.rec.StoreOperation(metrics.StoreOpMarkInvalid, storeResult(err))
	return err
}

// auditMetricBridge decorates the audit logger, deriving the
// credential_renewals_total and enrollments_total families from §34.3/CD-2
// audit events (the only layer that sees handshake, maintenance, and
// enrollment outcomes without touching the sshauth package). All events
// pass through unchanged.
type auditMetricBridge struct {
	inner audit.Logger
	rec   metrics.Recorder
}

func (b *auditMetricBridge) Record(ctx context.Context, ev audit.Event) error {
	switch ev.EventType {
	case sshauth.EventTypeCredentialRenewal:
		result := metrics.ResultFailure
		if ev.Result == sshauth.ResultSuccess {
			result = metrics.ResultSuccess
		}
		b.rec.CredentialRenewal(metrics.MethodToken, result)
	case sshauth.EventTypeWrongUserToken:
		b.rec.CredentialRenewal(metrics.MethodToken, metrics.ResultWrongUser)
	case sshauth.EventTypeEnrollmentSuccess:
		b.rec.Enrollment(metrics.EnrollmentSuccess)
	case sshauth.EventTypeEnrollmentRejected:
		b.rec.Enrollment(enrollmentRejectionLabel(ev.DetailCode))
	}
	return b.inner.Record(ctx, ev)
}

// enrollmentRejectionLabel maps the CD-2 rejection detail codes onto the
// bounded enrollments_total result labels.
func enrollmentRejectionLabel(detailCode string) string {
	switch detailCode {
	case sshauth.DetailEnrollmentKeyAlreadyLinked:
		return metrics.EnrollmentKeyConflict
	case sshauth.DetailEnrollmentRateLimited:
		return metrics.EnrollmentRateLimited
	default:
		return metrics.EnrollmentRejected
	}
}
