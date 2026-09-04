package sshauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/audit"
	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/store"
)

// ErrPublicKeyRejected is the single generic outward-facing rejection for
// every auth failure (§25.2, §35: identical message, no existence oracle).
var ErrPublicKeyRejected = errors.New("public key rejected")

// errRenewalNotImplemented is returned by the placeholder renewal callbacks
// until T20 wires real token renewal.
var errRenewalNotImplemented = errors.New("credential renewal is not yet implemented")

// Audit event types and results emitted by this package (§34.3). Candidate
// key lookups never produce audit events; only proof-of-possession outcomes
// and rejections do.
const (
	EventTypeKeyVerified  = "ssh_key_verified"
	EventTypeAuthRejected = "ssh_auth_rejected"

	ResultSuccess = "success"
	ResultFailure = "failure"
)

// publicKeyCallback implements the §9.3 candidate stage: username gate,
// certificate policy, store lookup, candidate permissions. It performs no
// Coder network call and records no successful-login audit event.
func (c AuthConfig) publicKeyCallback(state *ConnState, cfgErr error, meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	log := c.logger().With(
		slog.String("connection_id", state.ID()),
		slog.String("peer", state.PeerAddr()),
	)
	reject := func(reason, detailCode string, attrs ...slog.Attr) error {
		args := []any{
			slog.String("reason", reason),
			slog.String("detail_code", detailCode),
		}
		for _, a := range attrs {
			args = append(args, a)
		}
		log.Debug("public key candidate rejected", args...)
		// §34.3 audits public-key rejections. The detail code is a generic,
		// stable reason — never user input — and the outward error stays
		// identical for every cause (§35).
		c.recordAuthRejected(state.Context(), state, detailCode, uuid.Nil, uuid.Nil)
		return ErrPublicKeyRejected
	}

	if cfgErr != nil {
		return nil, reject("config_invalid", core.STORE_UNAVAILABLE, slog.String("detail", cfgErr.Error()))
	}

	user := meta.User()
	if user != c.TransportUser && user != c.MaintenanceUser {
		return nil, reject("unknown_username", core.AUTH_UNKNOWN_KEY)
	}

	if !c.AllowSSHCertificates {
		if _, isCert := key.(*ssh.Certificate); isCert {
			return nil, reject("certificate_not_allowed", core.AUTH_UNKNOWN_KEY)
		}
	}

	account, keyRecord, err := c.Store.LookupByPublicKey(state.Context(), c.DeploymentID, key)
	if err != nil {
		return nil, reject("key_lookup_failed", store.CodeOf(err))
	}

	state.setCandidate(account, keyRecord)
	log.Debug("public key candidate accepted",
		slog.String("user", user),
		slog.String("account_id", account.ID.String()),
		slog.String("ssh_key_id", keyRecord.ID.String()),
		slog.String("algorithm", key.Type()),
	)
	return CandidatePermissions(account.ID, keyRecord.ID), nil
}

// verifiedPublicKeyCallback implements the §9.3 verified stage (§25.3): it
// runs only after the client proves private-key possession. Maintenance mode
// requires no token (§14.1); transport mode validates the stored credential
// and returns final permissions, partial success with renewal continuations
// (renewable kinds only, §11.4/§13.1), or a generic rejection.
func (c AuthConfig) verifiedPublicKeyCallback(state *ConnState, cfgErr error, meta ssh.ConnMetadata, key ssh.PublicKey, candidate *ssh.Permissions, sigAlg string) (*ssh.Permissions, error) {
	ctx := state.Context()
	log := c.logger().With(
		slog.String("connection_id", state.ID()),
		slog.String("peer", state.PeerAddr()),
	)
	reject := func(reason, detailCode string, accountID, keyID uuid.UUID) error {
		log.Debug("verified public key rejected",
			slog.String("reason", reason),
			slog.String("detail_code", detailCode),
		)
		c.recordAuthRejected(ctx, state, detailCode, accountID, keyID)
		return ErrPublicKeyRejected
	}

	if cfgErr != nil {
		return nil, reject("config_invalid", core.STORE_UNAVAILABLE, uuid.Nil, uuid.Nil)
	}

	perms, err := ParseCandidatePermissions(candidate)
	if err != nil {
		return nil, reject("candidate_permissions_invalid", core.AUTH_UNKNOWN_KEY, uuid.Nil, uuid.Nil)
	}
	account, keyRecord, ok := state.candidateFor(perms.AccountID, perms.SSHKeyID)
	if !ok {
		return nil, reject("candidate_identity_mismatch", core.AUTH_UNKNOWN_KEY, uuid.Nil, uuid.Nil)
	}

	state.SetVerifiedIdentity(account, keyRecord, sigAlg)
	c.recordVerifiedKey(ctx, state, account, keyRecord, sigAlg)

	if meta.User() == c.MaintenanceUser {
		return FinalMaintenancePermissions(account.ID, keyRecord.ID), nil
	}

	snap, err := c.Store.LoadCredential(ctx, account.ID)
	if err != nil {
		return nil, reject("credential_load_failed", store.CodeOf(err), account.ID, keyRecord.ID)
	}

	if snap.State == core.CredentialStateMissing || len(snap.Token) == 0 {
		return c.startRenewal(state, log, account, keyRecord, core.CredentialMissing)
	}

	identity, err := c.Verifier.VerifyCached(ctx, account.ID, snap.Generation, snap.Token)
	if err == nil {
		if account.CoderUserID == nil {
			// A valid credential implies a previous bind (§10.5 binds at
			// store time); unbound here means inconsistent state.
			log.Warn("valid credential on unbound account; rejecting",
				slog.String("account_id", account.ID.String()))
			return nil, reject("inconsistent_unbound_account", core.AUTH_WRONG_CODER_IDENTITY, account.ID, keyRecord.ID)
		}
		if identity.ID != *account.CoderUserID {
			// Token resolves to a different Coder user than the binding:
			// security-relevant, audited loudly (§10.4, §35).
			log.Warn("credential resolved to wrong Coder identity",
				slog.String("account_id", account.ID.String()))
			return nil, reject("wrong_coder_identity", core.AUTH_WRONG_CODER_IDENTITY, account.ID, keyRecord.ID)
		}
		return FinalTransportPermissions(account.ID, c.DeploymentID, keyRecord.ID, snap.Generation, false), nil
	}

	kind := core.KindOf(err)
	if kind.Renewable() {
		return c.startRenewal(state, log, account, keyRecord, kind)
	}

	state.SendBanner(nonRenewableBanner(kind))
	return nil, reject("credential_not_usable", detailCodeFor(err, kind), account.ID, keyRecord.ID)
}

// startRenewal enters the §13 renewal path: extend the connection deadline
// (§13.5), send renewal instructions (§13.3), and return partial success
// with continuation callbacks and NIL permissions (§9.5).
func (c AuthConfig) startRenewal(state *ConnState, log *slog.Logger, account core.Account, keyRecord core.SSHKeyRecord, kind core.CredentialErrorKind) (*ssh.Permissions, error) {
	if c.RenewalAuthTimeout > 0 {
		if err := state.SetDeadline(time.Now().Add(c.RenewalAuthTimeout)); err != nil {
			log.Debug("cannot extend deadline for renewal", slog.String("detail", err.Error()))
			c.recordAuthRejected(state.Context(), state, core.STORE_UNAVAILABLE, account.ID, keyRecord.ID)
			return nil, ErrPublicKeyRejected
		}
	}
	state.SendBanner(c.renewalInstructions())
	log.Debug("entering credential renewal",
		slog.String("account_id", account.ID.String()),
		slog.String("credential_kind", string(kind)),
	)
	return nil, &ssh.PartialSuccessError{
		Next: ssh.ServerAuthCallbacks{
			KeyboardInteractiveCallback: placeholderRenewalKeyboardInteractive,
			PasswordCallback:            placeholderRenewalPassword,
		},
	}
}

// TODO(T20): replace both placeholder renewal callbacks with real token
// renewal (sanitize -> verify -> CAS store -> must_reconnect permissions).
// Until then they are dumb rejectors; they exist so clients see the offered
// continuation methods (keyboard-interactive, password) after partial
// success.

func placeholderRenewalKeyboardInteractive(meta ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	return nil, errRenewalNotImplemented
}

func placeholderRenewalPassword(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	wipeBytes(password)
	return nil, errRenewalNotImplemented
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// renewalInstructions is the §13.3 banner for renewable credential failures.
// It is the ONLY banner that may contain the /cli-auth URL (§35).
func (c AuthConfig) renewalInstructions() string {
	cliAuth := "your Coder deployment's /cli-auth page"
	if c.CoderURL != nil {
		u := *c.CoderURL
		u.Path = "/cli-auth"
		u.RawQuery = ""
		u.Fragment = ""
		cliAuth = u.String()
	}
	return "Your registered SSH key is valid, but the saved Coder credential is missing or expired.\n" +
		"Generate a new token at " + cliAuth + ".\n" +
		"At the following password/token prompt, paste that token.\n" +
		"This connection will close after successful validation; reconnect to continue."
}

// nonRenewableBanner maps §11.4 non-renewable kinds to safe §35-matrix user
// messages. Messages never contain tokens, URLs, or internal detail codes.
func nonRenewableBanner(kind core.CredentialErrorKind) string {
	switch kind {
	case core.CredentialForbidden:
		return "The stored Coder credential lacks the required authorization. Contact your administrator."
	case core.ControlPlaneUnavailable:
		return "The Coder control plane is temporarily unavailable. Try again later."
	case core.ControlPlaneIncompatible:
		return "The Coder control plane is not compatible with this gateway. Contact your administrator."
	case core.CredentialMalformedReply:
		return "The Coder control plane returned an unexpected response. Contact your administrator."
	default:
		return "Authentication failed."
	}
}

// detailCodeFor extracts the stable detail code from a credential error,
// falling back to a kind-derived default.
func detailCodeFor(err error, kind core.CredentialErrorKind) string {
	var ce *core.CredentialError
	if errors.As(err, &ce) && ce.DetailCode != "" {
		return ce.DetailCode
	}
	switch kind {
	case core.CredentialForbidden:
		return core.AUTH_CREDENTIAL_FORBIDDEN
	case core.ControlPlaneUnavailable:
		return core.AUTH_CODER_UNAVAILABLE
	case core.ControlPlaneIncompatible:
		return core.AUTH_CODER_INCOMPATIBLE
	case core.CredentialMalformedReply:
		return core.AUTH_CODER_INCOMPATIBLE
	case core.CredentialMissing:
		return core.AUTH_CREDENTIAL_MISSING
	case core.CredentialInvalid:
		return core.AUTH_CREDENTIAL_UNAUTHORIZED
	default:
		return core.AUTH_UNKNOWN_KEY
	}
}

// recordVerifiedKey audits proof of possession (§34.3 public key accepted).
func (c AuthConfig) recordVerifiedKey(ctx context.Context, state *ConnState, account core.Account, keyRecord core.SSHKeyRecord, sigAlg string) {
	c.record(ctx, audit.Event{
		ConnectionID: state.ID(),
		DeploymentID: c.DeploymentID.String(),
		AccountID:    account.ID.String(),
		SSHKeyID:     keyRecord.ID.String(),
		EventType:    EventTypeKeyVerified,
		Result:       ResultSuccess,
		PeerAddress:  state.PeerAddr(),
		DetailCode:   sigAlg,
	})
}

// recordAuthRejected audits a rejection with a generic, stable reason code.
// detailCode must never embed user input or token material.
func (c AuthConfig) recordAuthRejected(ctx context.Context, state *ConnState, detailCode string, accountID, keyID uuid.UUID) {
	ev := audit.Event{
		ConnectionID: state.ID(),
		DeploymentID: c.DeploymentID.String(),
		EventType:    EventTypeAuthRejected,
		Result:       ResultFailure,
		PeerAddress:  state.PeerAddr(),
		DetailCode:   detailCode,
	}
	if accountID != uuid.Nil {
		ev.AccountID = accountID.String()
	}
	if keyID != uuid.Nil {
		ev.SSHKeyID = keyID.String()
	}
	c.record(ctx, ev)
}

func (c AuthConfig) record(ctx context.Context, ev audit.Event) {
	if c.Audit == nil {
		return
	}
	ev.ID = uuid.NewString()
	ev.OccurredAtMs = time.Now().UnixMilli()
	if err := c.Audit.Record(ctx, ev); err != nil {
		c.logger().Debug("audit record failed",
			slog.String("connection_id", ev.ConnectionID),
			slog.String("event_type", ev.EventType),
			slog.String("detail", fmt.Sprintf("%v", err)),
		)
	}
}
