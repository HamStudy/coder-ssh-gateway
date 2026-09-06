package sshauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
)

// Enrollment continuation errors. As with the renewal sentinels, clients
// never see these strings; they classify outcomes for the continuation loop
// and for logs. Retryable classification is shared with renewal: only
// errors.Is(err, ErrTokenRejected) re-challenges.
var (
	// ErrEnrollmentFailed is the non-retryable generic enrollment failure
	// (non-renewable verify kinds, store faults).
	ErrEnrollmentFailed = errors.New("enrollment failed")
	// ErrEnrollmentKeyConflict rejects linking a key whose digest is already
	// linked to a DIFFERENT account (CD-2: a linked key can never move
	// across accounts). NOT retryable: re-entering tokens cannot change
	// which account the key belongs to.
	ErrEnrollmentKeyConflict = errors.New("key already linked to another account")
)

// Enrollment audit event types and detail codes (§34.3 extended by CD-2).
const (
	EventTypeEnrollmentSuccess  = "enrollment_success"
	EventTypeEnrollmentRejected = "enrollment_rejected"

	// DetailEnrollmentKeyAlreadyLinked marks the hard rejection of a key
	// already linked to a different account.
	DetailEnrollmentKeyAlreadyLinked = "key_already_linked"
	// DetailEnrollmentAttemptsExhausted marks failure by the per-connection
	// attempt bound.
	DetailEnrollmentAttemptsExhausted = "ENROLLMENT_ATTEMPTS_EXHAUSTED"
	// DetailEnrollmentRateLimited marks failure by the rate limiter.
	DetailEnrollmentRateLimited = "ENROLLMENT_RATE_LIMITED"
	// DetailEnrollmentAccountCreated marks that enrollment created the
	// account (versus converging onto an existing one).
	DetailEnrollmentAccountCreated = "account_created"
	// DetailEnrollmentKeyLinked marks that enrollment linked the key
	// (versus an idempotent re-enrollment of an already-linked key).
	DetailEnrollmentKeyLinked = "key_linked"
)

const (
	// enrollmentBanner is sent at the verified stage, after key possession
	// is proven and before any token prompt (proof-before-prompt, CD-2).
	enrollmentBanner = "New device enrollment. Provide your Coder token to link this key."
	// enrollmentKeyConflictBanner is the user-facing guidance for the
	// cross-account key conflict. It never names either account.
	enrollmentKeyConflictBanner = "This SSH key is already linked to another account.\n" +
		"Use a different key or contact the administrator."
	// enrollmentConfirmBanner is the KI zero-prompt confirmation after a
	// successful link (the pre-close banner already carried the username).
	enrollmentConfirmBanner = "Enrollment complete. This connection will now close;\nreconnect with your workspace connection (<workspace>@<gateway>)."
)

// KeyDigestHex computes the canonical store key digest: lowercase hex
// sha256 of the wire encoding (the keys/ filename stem, T11/T27).
func KeyDigestHex(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return hex.EncodeToString(sum[:])
}

// peerIPFromState extracts the host portion of the connection peer address
// for the per-IP PreTokenGate; unparseable addresses pass through whole.
func peerIPFromState(state *ConnState) string {
	peer := state.PeerAddr()
	if host, _, err := net.SplitHostPort(peer); err == nil {
		return host
	}
	return peer
}

// EnrollmentVerifier is the narrow verifier subset the enrollment
// continuation needs. *coderapi.Verifier satisfies it.
type EnrollmentVerifier interface {
	Verify(ctx context.Context, token []byte) (core.CoderIdentity, error)
}

// EnrollmentStore is the narrow store subset the enrollment continuation
// needs (CD-2). *store.Store satisfies it.
type EnrollmentStore interface {
	KeyDigestExists(digestHex string) (accountID uuid.UUID, exists bool, err error)
	LookupOrCreateAccountByCoderID(ctx context.Context, deploymentID, coderUserID uuid.UUID, username string) (core.Account, bool, error)
	GetAccount(id uuid.UUID) (core.Account, error)
	AddKey(accountID uuid.UUID, key ssh.PublicKey, label string) (core.SSHKeyRecord, error)
	LookupByPublicKey(ctx context.Context, deploymentID uuid.UUID, key ssh.PublicKey) (core.Account, core.SSHKeyRecord, error)
	LoadCredential(ctx context.Context, accountID uuid.UUID) (core.CredentialSnapshot, error)
	ReplaceCredential(ctx context.Context, req core.ReplaceCredentialRequest) (core.CredentialSnapshot, error)
}

// EnrollmentConfig carries the dependencies and policy knobs for the login@
// self-enrollment flow (CD-2): any client key is accepted as the first
// factor, and a valid Coder token anchors the account identity.
type EnrollmentConfig struct {
	// Enabled arms the enrollment user. When false (or EnrollmentUser
	// unresolved) the enrollment username behaves exactly like any unknown
	// username (§35: no oracle on whether enrollment exists).
	Enabled bool
	// User is the outer username that triggers enrollment (default comes
	// from AuthConfig.EnrollmentUser when empty).
	User string
	// Verifier validates candidate tokens against the Coder control plane.
	Verifier EnrollmentVerifier
	// Workspaces powers the post-enrollment hint listing the user's
	// workspaces. Nil disables the hint; failures never fail enrollment.
	Workspaces WorkspaceLister
	// Store resolves/creates accounts, links keys, and replaces credentials.
	Store EnrollmentStore
	// Rate gates token attempts and receives the §13.6-style reconnect
	// allowance. Attempts are gated on the zero-UUID bucket because the
	// account does not exist until the token is verified. Nil disables.
	Rate RenewalRateLimiter
	// PreTokenGate bounds pre-resolution token guessing per peer IP (CD-2
	// §20): it is consulted before the first token prompt is offered and
	// again before each retry/password attempt. A false return fails
	// enrollment cleanly (no prompt, no token accepted). Nil disables.
	PreTokenGate func(ip string) bool
	// Audit receives enrollment success/rejection events. Nil disables.
	Audit audit.Logger
	// MaxAttempts bounds candidate token attempts per connection.
	// <=0 selects DefaultMaxRenewalAttempts.
	MaxAttempts int
	// RenewalTimeout extends the raw connection deadline while enrollment
	// waits for a token (§13.5). Zero falls back to
	// AuthConfig.RenewalAuthTimeout.
	RenewalTimeout time.Duration
	// DeploymentID scopes account resolution and final permissions. Zero
	// is filled from AuthConfig.DeploymentID at callback-build time.
	DeploymentID uuid.UUID
	// CoderURL renders the /cli-auth URL in banner/challenge text. Nil is
	// filled from AuthConfig.CoderURL at callback-build time.
	CoderURL *url.URL
	// Logger receives debug-level diagnostics. Nil selects slog.Default().
	Logger *slog.Logger
}

func (ec *EnrollmentConfig) logger() *slog.Logger {
	if ec.Logger != nil {
		return ec.Logger
	}
	return slog.Default()
}

func (ec *EnrollmentConfig) maxAttempts() int {
	if ec.MaxAttempts > 0 {
		return ec.MaxAttempts
	}
	return DefaultMaxRenewalAttempts
}

// cliAuthURL renders the deployment /cli-auth URL for user-facing text. It
// is the only URL that may appear in enrollment text (§35 parity with §13.3).
func (ec *EnrollmentConfig) cliAuthURL() string {
	if ec.CoderURL == nil {
		return "your Coder deployment's /cli-auth page"
	}
	u := *ec.CoderURL
	u.Path = "/cli-auth"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// enrollmentCandidate implements the CD-2 candidate stage for the
// enrollment user: certificates follow the §10.3 policy, any other key is
// accepted by digest WITHOUT a store lookup (unknown keys are the point).
// No audit event is emitted here — proof-before-prompt means the verified
// stage is the first auditable milestone.
func (c AuthConfig) enrollmentCandidate(state *ConnState, key ssh.PublicKey) (*ssh.Permissions, error) {
	log := c.logger().With(
		slog.String("connection_id", state.ID()),
		slog.String("peer", state.PeerAddr()),
	)
	if _, isCert := key.(*ssh.Certificate); isCert {
		log.Debug("enrollment candidate rejected: certificate")
		c.recordAuthRejected(state.Context(), state, core.AUTH_UNKNOWN_KEY, uuid.Nil, uuid.Nil)
		return nil, ErrPublicKeyRejected
	}
	digest := KeyDigestHex(key)
	log.Debug("enrollment candidate accepted",
		slog.String("key_digest", digest),
		slog.String("algorithm", key.Type()),
	)
	return EnrollmentCandidatePermissions(digest), nil
}

// verifiedEnrollment runs after the client proves possession of the
// enrollment-candidate key: it cross-checks the echoed digest against the
// proven key (tamper guard), sends the enrollment banner, extends the
// §13.5 deadline, and offers the token continuations via partial success
// with NIL permissions (§9.5).
func (c AuthConfig) verifiedEnrollment(state *ConnState, key ssh.PublicKey, candidate *ssh.Permissions) (*ssh.Permissions, error) {
	ctx := state.Context()
	log := c.logger().With(
		slog.String("connection_id", state.ID()),
		slog.String("peer", state.PeerAddr()),
	)
	reject := func(reason string) (*ssh.Permissions, error) {
		log.Debug("enrollment verified stage rejected", slog.String("reason", reason))
		c.recordAuthRejected(ctx, state, core.AUTH_UNKNOWN_KEY, uuid.Nil, uuid.Nil)
		return nil, ErrPublicKeyRejected
	}

	if !c.enrollmentEnabled() {
		return reject("enrollment_disabled")
	}
	eperms, err := ParseEnrollmentCandidatePermissions(candidate)
	if err != nil {
		return reject("candidate_permissions_invalid")
	}
	digest := KeyDigestHex(key)
	if digest != eperms.KeyDigest {
		return reject("candidate_digest_mismatch")
	}

	ec := *c.Enrollment
	if ec.DeploymentID == uuid.Nil {
		ec.DeploymentID = c.DeploymentID
	}
	if ec.CoderURL == nil {
		ec.CoderURL = c.CoderURL
	}

	timeout := c.RenewalAuthTimeout
	if ec.RenewalTimeout > 0 {
		timeout = ec.RenewalTimeout
	}
	if timeout > 0 {
		if err := state.SetDeadline(time.Now().Add(timeout)); err != nil {
			log.Debug("cannot extend deadline for enrollment", slog.String("detail", err.Error()))
			c.recordAuthRejected(ctx, state, core.STORE_UNAVAILABLE, uuid.Nil, uuid.Nil)
			return nil, ErrPublicKeyRejected
		}
	}

	// §20: bound pre-resolution token guessing per peer IP before the
	// first prompt is offered.
	if ec.PreTokenGate != nil && !ec.PreTokenGate(peerIPFromState(state)) {
		log.Debug("enrollment pre-token gate refused")
		ec.auditEnrollment(scopeFromState(state), nil, nil, ResultFailure, DetailEnrollmentRateLimited)
		return nil, ErrPublicKeyRejected
	}

	state.SendBanner(enrollmentBanner + "\nGenerate a token at " + ec.cliAuthURL() + ".")
	log.Debug("entering device enrollment", slog.String("key_digest", digest))

	sess := &enrollmentSession{
		ec:     &ec,
		state:  state,
		key:    key,
		digest: digest,
		log:    log,
	}
	return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
		KeyboardInteractiveCallback: sess.keyboardInteractive,
		PasswordCallback:            sess.password,
	}}
}

// enrollmentSession is one connection's enrollment attempt. The closures
// returned at the verified stage capture the PROVEN key and its digest —
// no key is ever enrolled from the candidate stage alone.
type enrollmentSession struct {
	ec     *EnrollmentConfig
	state  *ConnState
	key    ssh.PublicKey
	digest string
	log    *slog.Logger
}

// keyboardInteractive implements the enrollment token continuation with the
// same challenge shape as §13.2 renewal: one echo=false token prompt,
// re-challenge with an error instruction while retryable failures and
// attempts remain, and a best-effort zero-prompt confirmation on success.
func (s *enrollmentSession) keyboardInteractive(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	instruction := "New device enrollment.\n" +
		"Open " + s.ec.cliAuthURL() + ", sign in, and paste the token below.\n" +
		"The token links this key to your Coder account. After verification\n" +
		"this connection will close; reconnect with your workspace connection."
	for {
		if s.state.RenewalAttempts() >= s.ec.maxAttempts() {
			s.log.Debug("enrollment attempts exhausted",
				slog.Int("attempts", s.state.RenewalAttempts()))
			s.ec.auditEnrollment(scopeFromState(s.state), nil, nil, ResultFailure, DetailEnrollmentAttemptsExhausted)
			return nil, ErrRenewalAttemptsExhausted
		}
		answers, err := challenge(challengeName, instruction, []string{tokenPrompt}, []bool{false})
		if err != nil {
			return nil, err
		}
		if len(answers) != 1 {
			return nil, ErrEnrollmentFailed
		}
		s.state.IncrementRenewalAttempts()
		perms, err := s.ec.validateAndLink(s.state, s.key, s.digest, []byte(answers[0]))
		if err == nil {
			_, _ = challenge(challengeName, enrollmentConfirmBanner, nil, nil)
			return perms, nil
		}
		if !errors.Is(err, ErrTokenRejected) {
			return nil, err
		}
		if s.ec.PreTokenGate != nil && !s.ec.PreTokenGate(peerIPFromState(s.state)) {
			s.log.Debug("enrollment re-challenge rate-limited")
			s.ec.auditEnrollment(scopeFromState(s.state), nil, nil, ResultFailure, DetailEnrollmentRateLimited)
			return nil, ErrRenewalRateLimited
		}
		s.log.Debug("enrollment candidate rejected; re-challenging")
		instruction = "Token not accepted. Verify you copied the current token from\n" +
			s.ec.cliAuthURL() + " and try again.\n" +
			"This connection will close after successful validation."
	}
}

// password implements the password continuation: the password bytes are a
// Coder token, validated through the same path as the keyboard-interactive
// continuation. The pre-prompt enrollment banner is the prompt text.
func (s *enrollmentSession) password(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	defer wipeBytes(password)
	if s.ec.PreTokenGate != nil && !s.ec.PreTokenGate(peerIPFromState(s.state)) {
		s.log.Debug("enrollment password attempt rate-limited")
		s.ec.auditEnrollment(scopeFromState(s.state), nil, nil, ResultFailure, DetailEnrollmentRateLimited)
		return nil, ErrRenewalRateLimited
	}
	if s.state.RenewalAttempts() >= s.ec.maxAttempts() {
		s.log.Debug("enrollment attempts exhausted",
			slog.Int("attempts", s.state.RenewalAttempts()))
		s.ec.auditEnrollment(scopeFromState(s.state), nil, nil, ResultFailure, DetailEnrollmentAttemptsExhausted)
		return nil, ErrRenewalAttemptsExhausted
	}
	s.state.IncrementRenewalAttempts()
	return s.ec.validateAndLink(s.state, s.key, s.digest, password)
}

// validateAndLink is the shared completion used by both continuations:
// sanitize -> rate gate -> verify -> linkEnrollment -> handshake side
// effects (banner, reconnect allowance, must_reconnect=true perms, §13.6).
func (ec *EnrollmentConfig) validateAndLink(state *ConnState, key ssh.PublicKey, digest string, rawCandidate []byte) (*ssh.Permissions, error) {
	scope := scopeFromState(state)
	log := ec.logger().With(
		slog.String("connection_id", scope.id),
		slog.String("peer", scope.peer),
	)

	candidate, err := SanitizeToken(rawCandidate)
	if err != nil {
		log.Debug("enrollment candidate failed sanitization", slog.String("detail", err.Error()))
		ec.auditEnrollment(scope, nil, nil, ResultFailure, core.AUTH_CREDENTIAL_UNAUTHORIZED)
		return nil, ErrTokenRejected
	}
	defer wipeBytes(candidate)

	if ec.Rate != nil && !ec.Rate.AllowRenewalAttempt(uuid.Nil) {
		log.Debug("enrollment attempt rate-limited")
		ec.auditEnrollment(scope, nil, nil, ResultFailure, DetailEnrollmentRateLimited)
		return nil, ErrRenewalRateLimited
	}

	identity, err := ec.Verifier.Verify(scope.ctx, candidate)
	if err != nil {
		kind := core.KindOf(err)
		detail := detailCodeFor(err, kind)
		switch kind {
		case core.CredentialInvalid:
			log.Debug("enrollment candidate rejected by Coder", slog.String("detail_code", detail))
			ec.auditEnrollment(scope, nil, nil, ResultFailure, detail)
			return nil, ErrTokenRejected
		case core.ControlPlaneUnavailable:
			// Clean failure, NO retry prompt, nothing stored (§13.2 parity).
			log.Debug("coder unavailable during enrollment", slog.String("detail_code", detail))
			ec.auditEnrollment(scope, nil, nil, ResultFailure, core.AUTH_CODER_UNAVAILABLE)
			return nil, ErrCoderUnavailable
		default:
			log.Debug("enrollment candidate failed non-renewably",
				slog.String("kind", string(kind)),
				slog.String("detail_code", detail),
			)
			ec.auditEnrollment(scope, nil, nil, ResultFailure, detail)
			return nil, ErrEnrollmentFailed
		}
	}

	// linkEnrollment's store call wipes candidate (§21.5 plaintext
	// ownership), so the post-link workspace hint snapshots the token
	// into its own buffer before the store consumes the original.
	var hintToken []byte
	if ec.Workspaces != nil {
		hintToken = bytes.Clone(candidate)
		defer wipeBytes(hintToken)
	}

	account, keyRecord, generation, details, err := ec.linkEnrollment(scope, candidate, identity, key, digest, state)
	if err != nil {
		return nil, err
	}

	banner := enrollmentSuccessText(identity.Username)
	if ec.Workspaces != nil {
		listCtx, cancel := context.WithTimeout(scope.ctx, workspaceListTimeout)
		names, owned, err := ec.Workspaces.ListOwnedWorkspaces(listCtx, hintToken, identity.ID, maxListedWorkspaces)
		cancel()
		switch {
		case err != nil:
			log.Debug("workspace hint skipped", slog.String("detail", err.Error()))
		case len(names) > 0:
			banner += "\n" + workspaceListText(names, owned)
		}
	}
	state.SendBanner(banner)
	if ec.Rate != nil {
		ec.Rate.GrantReconnectAllowance(account.ID)
	}
	log.Debug("device enrolled; forcing reconnect",
		slog.String("account_id", account.ID.String()),
		slog.Int64("generation", generation),
	)
	ec.auditEnrollment(scope, &account, &keyRecord, ResultSuccess, strings.Join(details, ","))
	state.SetMustReconnect(true)
	return FinalTransportPermissions(account.ID, ec.DeploymentID, keyRecord.ID, generation, true), nil
}

// linkEnrollment performs the CD-2 store mutations after a token verifies:
// cross-account key-conflict rejection, account find-or-create, credential
// replace (generation CAS), and key linking. It returns the account, the
// key record, the post-call credential generation, and the audit detail
// codes describing what changed.
func (ec *EnrollmentConfig) linkEnrollment(
	scope renewalScope,
	candidate []byte,
	identity core.CoderIdentity,
	key ssh.PublicKey,
	digest string,
	state *ConnState,
) (core.Account, core.SSHKeyRecord, int64, []string, error) {
	log := ec.logger().With(
		slog.String("connection_id", scope.id),
		slog.String("peer", scope.peer),
	)
	fail := func(detail string, err error) (core.Account, core.SSHKeyRecord, int64, []string, error) {
		ec.auditEnrollment(scope, nil, nil, ResultFailure, detail)
		return core.Account{}, core.SSHKeyRecord{}, 0, nil, err
	}

	linkedAccountID, keyExists, err := ec.Store.KeyDigestExists(digest)
	if err != nil {
		log.Debug("enrollment key digest lookup failed", slog.String("detail_code", store.CodeOf(err)))
		return fail(store.CodeOf(err), ErrEnrollmentFailed)
	}
	if keyExists {
		linked, err := ec.Store.GetAccount(linkedAccountID)
		if err != nil {
			log.Debug("enrollment linked-account lookup failed", slog.String("detail_code", store.CodeOf(err)))
			return fail(store.CodeOf(err), ErrEnrollmentFailed)
		}
		if linked.CoderUserID == nil || *linked.CoderUserID != identity.ID {
			// The key belongs to a different Coder identity than the
			// token resolves to. Hard reject, no retry, no mutation.
			log.Warn("enrollment key already linked to another account")
			state.SendBanner(enrollmentKeyConflictBanner)
			ec.auditEnrollment(scope, nil, nil, ResultFailure, DetailEnrollmentKeyAlreadyLinked)
			return core.Account{}, core.SSHKeyRecord{}, 0, nil, ErrEnrollmentKeyConflict
		}
	}

	account, created, err := ec.Store.LookupOrCreateAccountByCoderID(scope.ctx, ec.DeploymentID, identity.ID, identity.Username)
	if err != nil {
		log.Debug("enrollment account resolution failed", slog.String("detail_code", store.CodeOf(err)))
		return fail(store.CodeOf(err), ErrEnrollmentFailed)
	}
	log = log.With(slog.String("account_id", account.ID.String()))

	// Credential replace with generation CAS. A fresh account (created
	// pre-bound by the T27 helper) starts at generation 0; an existing
	// account refreshes from its current generation.
	expectedGeneration := int64(0)
	if !created {
		snap, err := ec.Store.LoadCredential(scope.ctx, account.ID)
		if err != nil {
			log.Debug("enrollment credential load failed", slog.String("detail_code", store.CodeOf(err)))
			return fail(store.CodeOf(err), ErrEnrollmentFailed)
		}
		// The current token is not needed — only its generation — so the
		// plaintext never leaves this scope.
		defer secretbox.BestEffortWipe(snap.Token)
		expectedGeneration = snap.Generation
	}

	generation := expectedGeneration
	alreadyUpdated := false
	snap, err := ec.Store.ReplaceCredential(scope.ctx, core.ReplaceCredentialRequest{
		AccountID:          account.ID,
		ExpectedGeneration: expectedGeneration,
		Token:              candidate,
		Identity:           identity,
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrGenerationConflict):
			// §23.2 parity: a concurrent enrollment/renewal already stored
			// a valid token — a SUCCESS outcome that forces a reconnect.
			alreadyUpdated = true
			if current, lerr := ec.Store.LoadCredential(scope.ctx, account.ID); lerr == nil {
				generation = current.Generation
				wipeBytes(current.Token)
			}
			log.Debug("credential already updated by concurrent writer",
				slog.Int64("generation", generation))
		case errors.Is(err, store.ErrWrongIdentity):
			// Defensive: the account was resolved BY the token's identity,
			// so this should be unreachable.
			log.Warn("store rejected enrollment identity binding")
			return fail(core.AUTH_WRONG_CODER_IDENTITY, ErrEnrollmentFailed)
		default:
			log.Debug("enrollment store replace failed", slog.String("detail_code", store.CodeOf(err)))
			return fail(store.CodeOf(err), ErrEnrollmentFailed)
		}
	} else {
		generation = snap.Generation
	}

	// Key linking. An already-linked key (same account) is the idempotent
	// re-enrollment path: recover the record without mutating.
	var keyRecord core.SSHKeyRecord
	if keyExists {
		_, keyRecord, err = ec.Store.LookupByPublicKey(scope.ctx, ec.DeploymentID, key)
		if err != nil {
			log.Debug("enrollment linked-key lookup failed", slog.String("detail_code", store.CodeOf(err)))
			return fail(store.CodeOf(err), ErrEnrollmentFailed)
		}
		if keyRecord.AccountID != account.ID {
			log.Warn("enrollment key owner drifted between digest check and link")
			return fail(DetailEnrollmentKeyAlreadyLinked, ErrEnrollmentKeyConflict)
		}
	} else {
		label := "enrolled " + time.Now().UTC().Format(time.RFC3339) + " via login@"
		keyRecord, err = ec.Store.AddKey(account.ID, key, label)
		if err != nil {
			log.Debug("enrollment key link failed", slog.String("detail_code", store.CodeOf(err)))
			return fail(store.CodeOf(err), ErrEnrollmentFailed)
		}
	}

	details := make([]string, 0, 3)
	if created {
		details = append(details, DetailEnrollmentAccountCreated)
	}
	if !keyExists {
		details = append(details, DetailEnrollmentKeyLinked)
	}
	if alreadyUpdated {
		details = append(details, DetailRenewalAlreadyUpdated)
	}
	return account, keyRecord, generation, details, nil
}

// WorkspaceLister enumerates the workspaces a freshly verified token can
// reach, for the post-enrollment hint. Best-effort by contract: implementors
// return errors, callers skip the hint.
type WorkspaceLister interface {
	ListOwnedWorkspaces(ctx context.Context, token []byte, owner uuid.UUID, limit int) (names []string, owned int, err error)
}

const (
	// maxListedWorkspaces caps the hint list; larger fleets get an
	// "and N more" tail instead of a wall of names.
	maxListedWorkspaces = 10
	// workspaceListTimeout bounds the extra control-plane round trip so
	// enrollment close latency stays predictable.
	workspaceListTimeout = 5 * time.Second
)

// enrollmentSuccessText is the post-link confirmation (banner and KI
// zero-prompt confirmation share it). The username comes from the Coder
// control plane, not from client input.
func enrollmentSuccessText(username string) string {
	return fmt.Sprintf("Enrolled. Coder user %s — key linked, token saved.\n"+
		"Reconnect using your workspace connection (<workspace>@<gateway>).", username)
}

// workspaceListText renders the hint under the enrollment confirmation.
// owned may exceed len(names) when the list was capped.
func workspaceListText(names []string, owned int) string {
	var b strings.Builder
	b.WriteString("Your workspaces:")
	for _, name := range names {
		b.WriteString("\n  " + name)
	}
	if remaining := owned - len(names); remaining > 0 {
		fmt.Fprintf(&b, "\n  … and %d more", remaining)
	}
	return b.String()
}

// auditEnrollment records a CD-2 enrollment outcome. account/keyRecord are
// nil before the account exists (sanitize/verify failures); detailCode is a
// stable, generic code — never user input or token material.
func (ec *EnrollmentConfig) auditEnrollment(scope renewalScope, account *core.Account, keyRecord *core.SSHKeyRecord, result, detailCode string) {
	ev := audit.Event{
		ConnectionID: scope.id,
		DeploymentID: ec.DeploymentID.String(),
		Result:       ResultFailure,
		PeerAddress:  scope.peer,
		DetailCode:   detailCode,
	}
	if result == ResultSuccess {
		ev.EventType = EventTypeEnrollmentSuccess
		ev.Result = ResultSuccess
	} else {
		ev.EventType = EventTypeEnrollmentRejected
	}
	if account != nil {
		ev.AccountID = account.ID.String()
	}
	if keyRecord != nil {
		ev.SSHKeyID = keyRecord.ID.String()
	}
	ec.record(scope.ctx, ev)
}

func (ec *EnrollmentConfig) record(ctx context.Context, ev audit.Event) {
	if ec.Audit == nil {
		return
	}
	ev.ID = uuid.NewString()
	ev.OccurredAtMs = time.Now().UnixMilli()
	if err := ec.Audit.Record(ctx, ev); err != nil {
		ec.logger().Debug("audit record failed",
			slog.String("connection_id", ev.ConnectionID),
			slog.String("event_type", ev.EventType),
		)
	}
}
