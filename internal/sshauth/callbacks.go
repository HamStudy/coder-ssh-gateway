package sshauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
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
	user := meta.User()
	fingerprint := ssh.FingerprintSHA256(key)
	reject := func(reason, detailCode string, attrs ...slog.Attr) error {
		args := []any{
			slog.String("user", user),
			slog.String("fingerprint", fingerprint),
			slog.String("reason", reason),
			slog.String("detail_code", detailCode),
		}
		for _, a := range attrs {
			args = append(args, a)
		}
		log.Warn("public key candidate rejected", args...)
		// §34.3 audits public-key rejections. The detail code is a generic,
		// stable reason — never user input — and the outward error stays
		// identical for every cause (§35).
		c.recordAuthRejected(state.Context(), state, detailCode, uuid.Nil, uuid.Nil)
		return ErrPublicKeyRejected
	}

	if cfgErr != nil {
		return nil, reject("config_invalid", core.STORE_UNAVAILABLE, slog.String("detail", cfgErr.Error()))
	}

	{
		// CD-2: the enrollment user is the only other recognized username,
		// and only while enrollment is armed; otherwise it rejects
		// identically to any unknown username (§35).
		if c.enrollmentEnabled() && user == c.enrollmentUser() {
			return c.enrollmentCandidate(state, key)
		}
		// The key-management username routes to the account-scoped
		// key-management UI, checked before any route parsing like
		// enrollment. Unlike login@, only an already-enrolled key may
		// proceed — unenrolled keys must never reach the UI.
		if c.keysEnabled() && user == c.keysUser() {
			return c.keysCandidate(state, key, reject)
		}
		// Every non-reserved username is a potential direct workspace route.
		// Deliberately defer route parsing until after enrolled-key resolution
		// and proof, so neither malformed routes nor workspace existence become
		// a pre-auth oracle.
	}

	if _, isCert := key.(*ssh.Certificate); isCert {
		return nil, reject("certificate_not_allowed", core.AUTH_UNKNOWN_KEY)
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

// keysCandidate implements the candidate stage for the key-management
// username: certificates follow the §10.3 policy, then the key MUST resolve
// to an enrolled account key — unlike login@, an unenrolled key must never
// reach the UI. Rejections flow through the caller's closure so the log,
// audit, and outward error stay byte-identical to the workspace path. It
// performs no Coder network call.
func (c AuthConfig) keysCandidate(state *ConnState, key ssh.PublicKey, reject func(reason, detailCode string, attrs ...slog.Attr) error) (*ssh.Permissions, error) {
	if _, isCert := key.(*ssh.Certificate); isCert {
		return nil, reject("certificate_not_allowed", core.AUTH_UNKNOWN_KEY)
	}
	account, keyRecord, err := c.Store.LookupByPublicKey(state.Context(), c.DeploymentID, key)
	if err != nil {
		return nil, reject("key_lookup_failed", store.CodeOf(err))
	}
	state.setCandidate(account, keyRecord)
	return KeyManagementCandidatePermissions(account.ID, keyRecord.ID), nil
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
		log.Warn("verified public key rejected",
			slog.String("user", meta.User()),
			slog.String("fingerprint", ssh.FingerprintSHA256(key)),
			slog.String("reason", reason),
			slog.String("detail_code", detailCode),
		)
		c.recordAuthRejected(ctx, state, detailCode, accountID, keyID)
		return ErrPublicKeyRejected
	}

	if cfgErr != nil {
		return nil, reject("config_invalid", core.STORE_UNAVAILABLE, uuid.Nil, uuid.Nil)
	}

	// CD-2: enrollment-mode candidate permissions branch into the token-
	// anchored self-enrollment flow before the store-identity parsing.
	if candidate != nil && candidate.Extensions[PermissionMode] == ModeEnrollment {
		return c.verifiedEnrollment(state, key, candidate)
	}

	// Key-management candidates take the credential-free path: an enrolled
	// key proven is the whole authentication. No LoadCredential, no
	// VerifyCached, no renewal — an expired or missing Coder token must not
	// lock the owner out of managing their keys (and renewal success would
	// return workspace permissions, mis-routing the connection).
	if candidate != nil && candidate.Extensions[PermissionMode] == ModeKeyManagement {
		return c.verifiedKeyManagement(state, candidate, sigAlg, reject)
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

	snap, err := c.Store.LoadCredential(ctx, account.ID)
	if err != nil {
		return nil, reject("credential_load_failed", store.CodeOf(err), account.ID, keyRecord.ID)
	}
	// §21.5: this snapshot's token never leaves the verified stage (only its
	// generation is carried onward), so wipe it on every path.
	defer secretbox.BestEffortWipe(snap.Token)

	if snap.State == core.CredentialStateMissing || len(snap.Token) == 0 {
		return c.startRenewal(state, log, account, keyRecord, snap.Generation, core.CredentialMissing)
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
		return FinalWorkspacePermissions(account.ID, c.DeploymentID, keyRecord.ID, snap.Generation), nil
	}

	kind := core.KindOf(err)
	if kind.Renewable() {
		return c.startRenewal(state, log, account, keyRecord, snap.Generation, kind)
	}

	state.SendBanner(nonRenewableBanner(kind))
	return nil, reject("credential_not_usable", detailCodeFor(err, kind), account.ID, keyRecord.ID)
}

// verifiedKeyManagement completes key-management authentication: parse the
// candidate permissions, tie them to the connection's candidate identity,
// record proof of possession, and return key-management finals. The stored
// credential is never consulted on this path. It receives the caller's
// rejection closure so rejection logs and audits stay byte-identical with
// the workspace path.
func (c AuthConfig) verifiedKeyManagement(state *ConnState, candidate *ssh.Permissions, sigAlg string, reject func(reason, detailCode string, accountID, keyID uuid.UUID) error) (*ssh.Permissions, error) {
	perms, err := ParseCandidatePermissions(candidate)
	if err != nil {
		return nil, reject("candidate_permissions_invalid", core.AUTH_UNKNOWN_KEY, uuid.Nil, uuid.Nil)
	}
	account, keyRecord, ok := state.candidateFor(perms.AccountID, perms.SSHKeyID)
	if !ok {
		return nil, reject("candidate_identity_mismatch", core.AUTH_UNKNOWN_KEY, uuid.Nil, uuid.Nil)
	}

	state.SetVerifiedIdentity(account, keyRecord, sigAlg)
	c.recordVerifiedKey(state.Context(), state, account, keyRecord, sigAlg)
	return FinalKeyManagementPermissions(account.ID, c.DeploymentID, keyRecord.ID), nil
}

// startRenewal enters the §13 renewal path: record the renewal attempt on
// the connection state (§12), extend the connection deadline (§13.5), send
// renewal instructions (§13.3), and return partial success with continuation
// callbacks and NIL permissions (§9.5). With a configured Renewal the
// continuations are the real §25.4 renewal flow; otherwise the placeholders
// reject every attempt.
func (c AuthConfig) startRenewal(state *ConnState, log *slog.Logger, account core.Account, keyRecord core.SSHKeyRecord, generation int64, kind core.CredentialErrorKind) (*ssh.Permissions, error) {
	timeout := c.RenewalAuthTimeout
	if c.Renewal != nil && c.Renewal.RenewalTimeout > 0 {
		timeout = c.Renewal.RenewalTimeout
	}
	if timeout > 0 {
		if err := state.SetDeadline(time.Now().Add(timeout)); err != nil {
			log.Debug("cannot extend deadline for renewal", slog.String("detail", err.Error()))
			c.recordAuthRejected(state.Context(), state, core.STORE_UNAVAILABLE, account.ID, keyRecord.ID)
			return nil, ErrPublicKeyRejected
		}
	}
	state.SetRenewalAttempt(account, keyRecord, generation)
	state.SendBanner(c.renewalInstructions())
	log.Info("entering credential renewal",
		slog.String("account_id", account.ID.String()),
		slog.String("credential_kind", string(kind)),
	)
	next := ssh.ServerAuthCallbacks{
		KeyboardInteractiveCallback: placeholderRenewalKeyboardInteractive,
		PasswordCallback:            placeholderRenewalPassword,
	}
	if c.Renewal != nil {
		rc := *c.Renewal
		if rc.DeploymentID == uuid.Nil {
			rc.DeploymentID = c.DeploymentID
		}
		if rc.CoderURL == nil {
			rc.CoderURL = c.CoderURL
		}
		sess := &renewalSession{
			rc:                 &rc,
			state:              state,
			account:            account,
			keyRecord:          keyRecord,
			expectedGeneration: generation,
			log: log.With(
				slog.String("account_id", account.ID.String()),
				slog.String("ssh_key_id", keyRecord.ID.String()),
			),
		}
		next.KeyboardInteractiveCallback = sess.keyboardInteractive
		next.PasswordCallback = sess.password
	}
	return nil, &ssh.PartialSuccessError{Next: next}
}

// The placeholder renewal callbacks are used when AuthConfig.Renewal is nil.
// They exist so clients see the offered continuation methods
// (keyboard-interactive, password) after partial success even without
// configured renewal dependencies.

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
		"This connection continues straight into your workspace after validation.\n\n"
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
