package sshauth

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
)

// Renewal continuation errors. The client never sees these strings (x/crypto
// collapses every auth failure into a generic message); they exist so the
// renewal loop can classify outcomes and so server logs/audit stay stable.
var (
	// ErrTokenRejected marks a retryable candidate failure (sanitize
	// rejection or Coder 401): the keyboard-interactive loop re-challenges
	// while attempts remain (§13.2).
	ErrTokenRejected = errors.New("token rejected")
	// ErrWrongUserToken rejects a candidate that verifies against Coder but
	// resolves to a different Coder user UUID than the account binding
	// (§10.4). NOT retryable: re-entering the same token class can never
	// succeed, and the attempt is security-audited.
	ErrWrongUserToken = errors.New("token belongs to a different Coder account")
	// ErrCoderUnavailable fails renewal cleanly when the control plane
	// cannot be reached (§13.2/§35): no further prompts, no store write.
	ErrCoderUnavailable = errors.New("coder control plane unavailable")
	// ErrRenewalFailed is the non-retryable generic renewal failure
	// (non-renewable verify kinds, store faults).
	ErrRenewalFailed = errors.New("credential renewal failed")
	// ErrRenewalAttemptsExhausted ends the continuation when the
	// per-connection attempt bound is reached (§13.2).
	ErrRenewalAttemptsExhausted = errors.New("renewal attempts exhausted")
	// ErrRenewalRateLimited ends the continuation when the per-account
	// renewal rate limiter denies an attempt (§20).
	ErrRenewalRateLimited = errors.New("renewal rate limit exceeded")
)

// Audit event types and renewal-specific detail codes (§34.3: token renewal
// success/failure, wrong-user token attempt).
const (
	EventTypeCredentialRenewal = "ssh_credential_renewal"
	EventTypeWrongUserToken    = "ssh_wrong_user_token"

	// DetailRenewalAttemptsExhausted marks renewal failure caused by the
	// per-connection attempt bound.
	DetailRenewalAttemptsExhausted = "RENEWAL_ATTEMPTS_EXHAUSTED"
	// DetailRenewalRateLimited marks renewal failure caused by the
	// per-account rate limiter.
	DetailRenewalRateLimited = "RENEWAL_RATE_LIMITED"
	// DetailRenewalAlreadyUpdated marks the §23.2 already-updated path: the
	// generation CAS lost to a concurrent renewal, which is a SUCCESS
	// outcome (the credential is valid) that forces a reconnect.
	DetailRenewalAlreadyUpdated = "RENEWAL_ALREADY_UPDATED"
)

// DefaultMaxRenewalAttempts bounds candidate token attempts per SSH
// connection (§13.2: "no more than three candidate attempts").
const DefaultMaxRenewalAttempts = 3

const (
	// challengeName is the RFC 4256 name field of the renewal challenge.
	challengeName = "Coder SSH Gateway"
	// tokenPrompt is the single echo=false prompt of the renewal challenge.
	tokenPrompt = "Coder token: "
	// renewalSuccessBanner is sent after the replacement is stored (§13.3).
	renewalSuccessBanner = "Coder token verified. Reconnect to continue."
	// renewalAlreadyUpdatedBanner is the §23.2 losing-race message.
	renewalAlreadyUpdatedBanner = "Your Coder credential was already updated from another connection.\n" +
		"Reconnect to continue."
)

// RenewalVerifier is the narrow verifier subset the renewal continuation
// needs (§25.4). *coderapi.Verifier satisfies it. VerifyIdentity is used by
// the maintenance-mode flow (T21); renewal itself calls Verify once and
// compares the returned UUID against the account binding.
type RenewalVerifier interface {
	Verify(ctx context.Context, token []byte) (core.CoderIdentity, error)
	VerifyIdentity(ctx context.Context, token []byte, want uuid.UUID) error
}

// RenewalStore is the narrow store subset the renewal continuation needs
// (§25.4). *store.Store satisfies it.
type RenewalStore interface {
	LoadCredential(ctx context.Context, accountID uuid.UUID) (core.CredentialSnapshot, error)
	ReplaceCredential(ctx context.Context, req core.ReplaceCredentialRequest) (core.CredentialSnapshot, error)
}

// RenewalRateLimiter is the narrow rate-limiter subset the renewal
// continuation needs. *limits.RateLimits satisfies it (construct via
// limits.NewRateLimits); the interface keeps renewal testable with fakes.
type RenewalRateLimiter interface {
	AllowRenewalAttempt(accountID uuid.UUID) bool
	GrantReconnectAllowance(accountID uuid.UUID)
}

// RenewalConfig carries the dependencies and policy knobs for the §13
// credential-renewal continuations (keyboard-interactive and password) that
// follow a partial public-key success.
type RenewalConfig struct {
	// Verifier validates candidate tokens against the Coder control plane.
	Verifier RenewalVerifier
	// Store atomically replaces the credential (generation CAS, §21.4).
	Store RenewalStore
	// Rate gates per-account renewal attempts (§20) and receives the
	// §13.6 reconnect allowance. Nil disables the gate.
	Rate RenewalRateLimiter
	// Audit receives renewal success/failure/wrong-user events (§34.3).
	// Nil disables renewal audit events.
	Audit audit.Logger
	// MaxAttempts bounds candidate attempts per connection (§13.2).
	// <=0 selects DefaultMaxRenewalAttempts.
	MaxAttempts int
	// RenewalTimeout extends the raw connection deadline when renewal
	// starts (§13.5). Zero falls back to AuthConfig.RenewalAuthTimeout.
	RenewalTimeout time.Duration
	// DeploymentID scopes final transport permissions. Zero is filled
	// from AuthConfig.DeploymentID at callback-build time.
	DeploymentID uuid.UUID
	// CoderURL renders the /cli-auth URL in challenge instructions. Nil
	// is filled from AuthConfig.CoderURL at callback-build time.
	CoderURL *url.URL
	// Logger receives debug-level diagnostics. Nil selects slog.Default().
	Logger *slog.Logger
}

func (rc *RenewalConfig) logger() *slog.Logger {
	if rc.Logger != nil {
		return rc.Logger
	}
	return slog.Default()
}

func (rc *RenewalConfig) maxAttempts() int {
	if rc.MaxAttempts > 0 {
		return rc.MaxAttempts
	}
	return DefaultMaxRenewalAttempts
}

// cliAuthURL renders the deployment /cli-auth URL for challenge text. It is
// the ONLY URL that may appear in renewal user-facing text (§35).
func (rc *RenewalConfig) cliAuthURL() string {
	if rc.CoderURL == nil {
		return "your Coder deployment's /cli-auth page"
	}
	u := *rc.CoderURL
	u.Path = "/cli-auth"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// renewalScope identifies one connection for logs and audit in the shared
// §25.4 completion path. The auth continuations build it from ConnState; the
// maintenance handler (§14, post-auth on a session channel) carries the same
// identity through the context via WithConnScope.
type renewalScope struct {
	ctx  context.Context
	id   string
	peer string
}

func scopeFromState(state *ConnState) renewalScope {
	return renewalScope{ctx: state.Context(), id: state.ID(), peer: state.PeerAddr()}
}

// connScope is the WithConnScope payload: server-connection identity plus
// the authenticated SSH key ID for audit attribution.
type connScope struct {
	id     string
	peer   string
	sshKey uuid.UUID
}

type connScopeKey struct{}

// WithConnScope annotates ctx with the server-side connection identity for
// ReplaceToken (§14 maintenance mode runs post-auth, so no ConnState exists
// on the renewal path). The server channel dispatcher installs it.
func WithConnScope(ctx context.Context, connectionID, peer string, sshKeyID uuid.UUID) context.Context {
	return context.WithValue(ctx, connScopeKey{}, connScope{id: connectionID, peer: peer, sshKey: sshKeyID})
}

func scopeFromContext(ctx context.Context) connScope {
	if cs, ok := ctx.Value(connScopeKey{}).(connScope); ok {
		return cs
	}
	return connScope{}
}

// ReplaceToken is the §14.3 maintenance-mode entry to the shared §25.4
// completion path (replaceCredential). Unlike the auth continuations it
// performs NO handshake side effects — no auth banner, no reconnect
// allowance, no must_reconnect permissions — because the maintenance channel
// owns user messaging and the §14.3 transport close. Connection identity for
// logs and audit comes from WithConnScope (absent scope is tolerated).
//
// The returned generation is the credential generation after the call: the
// newly stored one, or — when a concurrent renewal won the CAS (§23.2) — the
// reloaded current generation (a success outcome: the credential is valid).
// Errors are the shared renewal sentinels; only ErrTokenRejected is
// retryable with a fresh candidate.
func (rc *RenewalConfig) ReplaceToken(ctx context.Context, account core.Account, expectedGeneration int64, rawCandidate []byte) (int64, error) {
	cs := scopeFromContext(ctx)
	keyRecord := core.SSHKeyRecord{ID: cs.sshKey, AccountID: account.ID}
	snap, _, err := rc.replaceCredential(
		renewalScope{ctx: ctx, id: cs.id, peer: cs.peer},
		account, keyRecord, expectedGeneration, rawCandidate,
	)
	if err != nil {
		return expectedGeneration, err
	}
	return snap.Generation, nil
}

// renewalSession is one connection's §12 renewal attempt: the verified
// identity and the credential generation captured when the verified-key
// callback entered the renewal path (§12 state machine, §25.4).
type renewalSession struct {
	rc                 *RenewalConfig
	state              *ConnState
	account            core.Account
	keyRecord          core.SSHKeyRecord
	expectedGeneration int64
	log                *slog.Logger
}

// keyboardInteractive implements the §13.2 continuation: challenge with a
// single echo=false token prompt, validate via the shared §25.4 path, and
// re-challenge with an error instruction while retryable failures and
// attempts remain. After success it issues a best-effort zero-prompt
// confirmation (cosmetic only — some clients do not render it).
func (s *renewalSession) keyboardInteractive(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	instruction := "Your saved Coder credential is missing or expired.\n" +
		"Open " + s.rc.cliAuthURL() + ", sign in, and paste the token below.\n" +
		"After the token is verified this connection will close; reconnect to continue."
	for {
		if s.state.RenewalAttempts() >= s.rc.maxAttempts() {
			s.log.Debug("renewal attempts exhausted",
				slog.Int("attempts", s.state.RenewalAttempts()))
			s.rc.auditRenewal(scopeFromState(s.state), s.account, s.keyRecord, ResultFailure, DetailRenewalAttemptsExhausted)
			return nil, ErrRenewalAttemptsExhausted
		}
		answers, err := challenge(challengeName, instruction, []string{tokenPrompt}, []bool{false})
		if err != nil {
			// Client aborted the challenge; not a token failure.
			return nil, err
		}
		if len(answers) != 1 {
			return nil, ErrRenewalFailed
		}
		s.state.IncrementRenewalAttempts()
		// NOTE: keyboard-interactive answers are strings; x/crypto owns
		// that memory and it cannot be wiped. SanitizeToken clones into a
		// fresh buffer which validateAndStoreReplacement wipes.
		perms, err := s.rc.validateAndStoreReplacement(
			s.state.Context(), s.state, s.account, s.keyRecord,
			s.expectedGeneration, []byte(answers[0]),
		)
		if err == nil {
			// §13.2 zero-prompt confirmation. Best-effort: its success is
			// never required for persistence.
			_, _ = challenge(challengeName, renewalSuccessBanner, nil, nil)
			return perms, nil
		}
		if !errors.Is(err, ErrTokenRejected) {
			return nil, err
		}
		s.log.Debug("renewal candidate rejected; re-challenging",
			slog.String("account_id", s.account.ID.String()))
		instruction = "Token not accepted. Verify you copied the current token from\n" +
			s.rc.cliAuthURL() + " and try again.\n" +
			"This connection will close after successful validation; reconnect to continue."
	}
}

// password implements the §13.3 continuation: the password bytes are a
// Coder token, validated through the same §25.4 path. The renewal banner
// (sent before the partial success, §13.3) is the prompt text; the success
// banner delivered by validateAndStoreReplacement is the confirmation.
func (s *renewalSession) password(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	defer wipeBytes(password)
	if s.state.RenewalAttempts() >= s.rc.maxAttempts() {
		s.log.Debug("renewal attempts exhausted",
			slog.Int("attempts", s.state.RenewalAttempts()))
		s.rc.auditRenewal(scopeFromState(s.state), s.account, s.keyRecord, ResultFailure, DetailRenewalAttemptsExhausted)
		return nil, ErrRenewalAttemptsExhausted
	}
	s.state.IncrementRenewalAttempts()
	return s.rc.validateAndStoreReplacement(
		s.state.Context(), s.state, s.account, s.keyRecord,
		s.expectedGeneration, password,
	)
}

// validateAndStoreReplacement is the §25.4 shared completion used by both
// continuation methods: the replaceCredential core (sanitize -> rate gate ->
// verify -> identity binding -> generation-CAS store replace) plus the
// handshake-only side effects (success banner, reconnect allowance,
// must_reconnect=true final permissions, §13.6).
func (rc *RenewalConfig) validateAndStoreReplacement(
	ctx context.Context,
	state *ConnState,
	account core.Account,
	keyRecord core.SSHKeyRecord,
	expectedGeneration int64,
	rawCandidate []byte,
) (*ssh.Permissions, error) {
	snap, alreadyUpdated, err := rc.replaceCredential(
		scopeFromState(state), account, keyRecord, expectedGeneration, rawCandidate,
	)
	if err != nil {
		return nil, err
	}

	if alreadyUpdated {
		// §23.2: a concurrent renewal already stored a valid token. This is
		// a success outcome — force a reconnect so the next connection
		// regenerates permissions from the NEW generation.
		state.SendBanner(renewalAlreadyUpdatedBanner)
		if rc.Rate != nil {
			rc.Rate.GrantReconnectAllowance(account.ID)
		}
		state.SetMustReconnect(true)
		return FinalTransportPermissions(account.ID, rc.DeploymentID, keyRecord.ID, snap.Generation, true), nil
	}

	// Success (§13.6): confirmation banner, one reconnect allowance, and
	// final transport permissions that force an immediate reconnect.
	state.SendBanner(renewalSuccessBanner)
	if rc.Rate != nil {
		rc.Rate.GrantReconnectAllowance(account.ID)
	}
	rc.logger().Debug("credential renewed; forcing reconnect",
		slog.String("connection_id", state.ID()),
		slog.Int64("generation", snap.Generation))
	state.SetMustReconnect(true)
	return FinalTransportPermissions(account.ID, rc.DeploymentID, keyRecord.ID, snap.Generation, true), nil
}

// replaceCredential is the side-effect-light core of the §25.4 shared
// completion: sanitize -> rate gate -> verify -> identity binding ->
// generation-CAS store replace. It emits logs and §34.3 audit events but
// touches no handshake state, so both the auth continuations and the §14.3
// maintenance session (via ReplaceToken) share it.
//
// Candidate token bytes are NEVER logged or audited (§13.2/§34.3); the
// sanitized buffer is wiped before return (the store additionally wipes it
// inside ReplaceCredential — double wipe is intentional and harmless).
//
// alreadyUpdated reports the §23.2 losing-race success: a concurrent renewal
// won the CAS, so the stored credential is already valid; snap then carries
// the reloaded current generation.
func (rc *RenewalConfig) replaceCredential(
	scope renewalScope,
	account core.Account,
	keyRecord core.SSHKeyRecord,
	expectedGeneration int64,
	rawCandidate []byte,
) (snap core.CredentialSnapshot, alreadyUpdated bool, err error) {
	log := rc.logger().With(
		slog.String("connection_id", scope.id),
		slog.String("peer", scope.peer),
		slog.String("account_id", account.ID.String()),
	)

	candidate, err := SanitizeToken(rawCandidate)
	if err != nil {
		// Sanitize errors are static sentinels; the detail never contains
		// token bytes or lengths (§13.2).
		log.Debug("renewal candidate failed sanitization", slog.String("detail", err.Error()))
		rc.auditRenewal(scope, account, keyRecord, ResultFailure, core.AUTH_CREDENTIAL_UNAUTHORIZED)
		return core.CredentialSnapshot{}, false, ErrTokenRejected
	}
	defer wipeBytes(candidate)

	if rc.Rate != nil && !rc.Rate.AllowRenewalAttempt(account.ID) {
		log.Debug("renewal attempt rate-limited")
		rc.auditRenewal(scope, account, keyRecord, ResultFailure, DetailRenewalRateLimited)
		return core.CredentialSnapshot{}, false, ErrRenewalRateLimited
	}

	identity, err := rc.Verifier.Verify(scope.ctx, candidate)
	if err != nil {
		kind := core.KindOf(err)
		detail := detailCodeFor(err, kind)
		switch kind {
		case core.CredentialInvalid:
			// Retryable: the user can paste a fresh token (§35 row
			// "replacement token returns 401").
			log.Debug("renewal candidate rejected by Coder", slog.String("detail_code", detail))
			rc.auditRenewal(scope, account, keyRecord, ResultFailure, detail)
			return core.CredentialSnapshot{}, false, ErrTokenRejected
		case core.ControlPlaneUnavailable:
			// §13.2/§35: clean failure, NO retry prompt, store untouched.
			log.Debug("coder unavailable during renewal", slog.String("detail_code", detail))
			rc.auditRenewal(scope, account, keyRecord, ResultFailure, core.AUTH_CODER_UNAVAILABLE)
			return core.CredentialSnapshot{}, false, ErrCoderUnavailable
		default:
			// 403 / incompatible / malformed (§11.4): non-renewable.
			log.Debug("renewal candidate failed non-renewably",
				slog.String("kind", string(kind)),
				slog.String("detail_code", detail),
			)
			rc.auditRenewal(scope, account, keyRecord, ResultFailure, detail)
			return core.CredentialSnapshot{}, false, ErrRenewalFailed
		}
	}

	// §10.4 identity binding. A bound account only accepts its own Coder
	// UUID; an unbound account may bind on first token (§10.5) — the bind
	// itself happens inside ReplaceCredential. A wrong-UUID token is
	// security-relevant: audited loudly and NOT retryable.
	if account.CoderUserID != nil {
		if identity.ID != *account.CoderUserID {
			log.Warn("renewal candidate resolved to wrong Coder identity")
			rc.auditWrongUserToken(scope, account, keyRecord)
			return core.CredentialSnapshot{}, false, ErrWrongUserToken
		}
	} else if !account.BindOnFirstToken {
		log.Warn("renewal candidate for unbound account without bind_on_first_token")
		rc.auditWrongUserToken(scope, account, keyRecord)
		return core.CredentialSnapshot{}, false, ErrWrongUserToken
	}

	snap, err = rc.Store.ReplaceCredential(scope.ctx, core.ReplaceCredentialRequest{
		AccountID:          account.ID,
		ExpectedGeneration: expectedGeneration,
		Token:              candidate,
		Identity:           identity,
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrGenerationConflict):
			generation := expectedGeneration
			if current, lerr := rc.Store.LoadCredential(scope.ctx, account.ID); lerr == nil {
				generation = current.Generation
				snap = current
				wipeBytes(current.Token)
			} else {
				snap = core.CredentialSnapshot{AccountID: account.ID, Generation: generation}
			}
			log.Debug("credential already updated by concurrent renewal",
				slog.Int64("generation", generation))
			rc.auditRenewal(scope, account, keyRecord, ResultSuccess, DetailRenewalAlreadyUpdated)
			return snap, true, nil
		case errors.Is(err, store.ErrWrongIdentity):
			// Defensive: the binding pre-check above should have caught
			// this; a first-bind collision (duplicate coder_user_id) also
			// lands here.
			log.Warn("store rejected renewal identity binding")
			rc.auditWrongUserToken(scope, account, keyRecord)
			return core.CredentialSnapshot{}, false, ErrWrongUserToken
		default:
			log.Debug("renewal store replace failed",
				slog.String("detail_code", store.CodeOf(err)))
			rc.auditRenewal(scope, account, keyRecord, ResultFailure, store.CodeOf(err))
			return core.CredentialSnapshot{}, false, ErrRenewalFailed
		}
	}

	rc.auditRenewal(scope, account, keyRecord, ResultSuccess, "")
	return snap, false, nil
}

// auditRenewal records a §34.3 token-renewal outcome. detailCode is a
// stable, generic code — never user input or token material.
func (rc *RenewalConfig) auditRenewal(scope renewalScope, account core.Account, keyRecord core.SSHKeyRecord, result, detailCode string) {
	rc.record(scope.ctx, audit.Event{
		ConnectionID: scope.id,
		DeploymentID: rc.DeploymentID.String(),
		AccountID:    account.ID.String(),
		SSHKeyID:     keyRecord.ID.String(),
		EventType:    EventTypeCredentialRenewal,
		Result:       result,
		PeerAddress:  scope.peer,
		DetailCode:   detailCode,
	})
}

// auditWrongUserToken records the §34.3 wrong-user token attempt
// (§10.4 security event).
func (rc *RenewalConfig) auditWrongUserToken(scope renewalScope, account core.Account, keyRecord core.SSHKeyRecord) {
	rc.record(scope.ctx, audit.Event{
		ConnectionID: scope.id,
		DeploymentID: rc.DeploymentID.String(),
		AccountID:    account.ID.String(),
		SSHKeyID:     keyRecord.ID.String(),
		EventType:    EventTypeWrongUserToken,
		Result:       ResultFailure,
		PeerAddress:  scope.peer,
		DetailCode:   core.AUTH_WRONG_CODER_IDENTITY,
	})
}

func (rc *RenewalConfig) record(ctx context.Context, ev audit.Event) {
	if rc.Audit == nil {
		return
	}
	ev.ID = uuid.NewString()
	ev.OccurredAtMs = time.Now().UnixMilli()
	if err := rc.Audit.Record(ctx, ev); err != nil {
		rc.logger().Debug("audit record failed",
			slog.String("connection_id", ev.ConnectionID),
			slog.String("event_type", ev.EventType),
		)
	}
}
