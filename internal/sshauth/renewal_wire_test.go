package sshauth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/sshauth"
)

// fakeRateLimiter mirrors the limits.RateLimits renewal semantics (§20,
// §13.6): a per-account token bucket plus a single-use reconnect allowance.
// limits.RateLimits has no exported constructor (T9), so wire tests use
// this fake through the sshauth.RenewalRateLimiter narrow interface.
type fakeRateLimiter struct {
	mu            sync.Mutex
	tokens        int
	allowance     bool
	grants        int
	denied        int
	allowanceUsed int
}

func newFakeRateLimiter(tokens int) *fakeRateLimiter {
	return &fakeRateLimiter{tokens: tokens}
}

func (f *fakeRateLimiter) AllowRenewalAttempt(uuid.UUID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.allowance {
		f.allowance = false
		f.allowanceUsed++
		return true
	}
	if f.tokens > 0 {
		f.tokens--
		return true
	}
	f.denied++
	return false
}

func (f *fakeRateLimiter) GrantReconnectAllowance(uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowance = true
	f.grants++
}

// coderStub is a programmable /api/v2/users/me stand-in: each known token
// maps to a status code; 200 replies carry the stub's Coder user UUID.
// Unknown tokens get 401.
type coderStub struct {
	mu       sync.Mutex
	id       uuid.UUID
	statuses map[string]int
}

type cachedVerifierBarrier struct {
	inner   sshauth.CachedTokenVerifier
	mu      sync.Mutex
	waiting int
	want    int
	ready   chan struct{}
}

func newCachedVerifierBarrier(inner sshauth.CachedTokenVerifier, want int) *cachedVerifierBarrier {
	return &cachedVerifierBarrier{
		inner: inner,
		want:  want,
		ready: make(chan struct{}),
	}
}

func (b *cachedVerifierBarrier) VerifyCached(
	ctx context.Context,
	accountID uuid.UUID,
	generation int64,
	token []byte,
) (core.CoderIdentity, error) {
	b.mu.Lock()
	b.waiting++
	if b.waiting == b.want {
		close(b.ready)
	}
	b.mu.Unlock()

	select {
	case <-b.ready:
	case <-ctx.Done():
		return core.CoderIdentity{}, ctx.Err()
	}
	return b.inner.VerifyCached(ctx, accountID, generation, token)
}

func newCoderStub(id uuid.UUID) *coderStub {
	return &coderStub{id: id, statuses: map[string]int{}}
}

func (c *coderStub) set(token string, status int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.statuses[token] = status
}

func (c *coderStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Coder-Session-Token")
	c.mu.Lock()
	status, ok := c.statuses[token]
	id := c.id
	c.mu.Unlock()
	if !ok {
		status = http.StatusUnauthorized
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":%q,"username":"taxilian","status":"active"}`, id.String())
}

// kiResponder is a scripted keyboard-interactive client: it answers each
// token prompt from answers (in order), counts zero-prompt confirmation
// challenges, and records the instruction text of every token challenge.
type kiResponder struct {
	mu           sync.Mutex
	answers      []string
	calls        int
	zeroCalls    int
	instructions []string
	stall        <-chan struct{}
}

func (k *kiResponder) challenge(_, instruction string, questions []string, _ []bool) ([]string, error) {
	if k.stall != nil {
		<-k.stall
		return nil, errors.New("test client: unblocked after stall")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(questions) == 0 {
		k.zeroCalls++
		return nil, nil
	}
	k.calls++
	k.instructions = append(k.instructions, instruction)
	if k.calls > len(k.answers) {
		return nil, errors.New("test client: no more answers")
	}
	return []string{k.answers[k.calls-1]}, nil
}

func (k *kiResponder) promptCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.calls
}

func (k *kiResponder) zeroPromptCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.zeroCalls
}

func (k *kiResponder) instructionAt(i int) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.instructions[i]
}

// renewalMethods are the client auth methods for the renewal flow: public
// key first, then the scripted keyboard-interactive continuation.
func renewalMethods(signer ssh.Signer, ki *kiResponder) []ssh.AuthMethod {
	return []ssh.AuthMethod{ssh.PublicKeys(signer), ssh.KeyboardInteractive(ki.challenge)}
}

// assertClosedAfterRenewal verifies §13.6: the server closes the outer
// connection right after a successful renewal.
func assertClosedAfterRenewal(t *testing.T, client *ssh.Client) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- client.Conn.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not close the connection after renewal (§13.6)")
	}
}

func mustParseFinalPerms(t *testing.T, perms *ssh.Permissions) sshauth.FinalPerms {
	t.Helper()
	p, err := sshauth.ParseFinalPermissions(perms)
	if err != nil {
		t.Fatalf("ParseFinalPermissions: %v", err)
	}
	return p
}

func renewalAuditEvents(f *fixture, result, detailCode string) int {
	n := 0
	for _, ev := range f.auditEvents(sshauth.EventTypeCredentialRenewal) {
		if ev.Result == result && ev.DetailCode == detailCode {
			n++
		}
	}
	return n
}

const (
	stubOldToken   = "old-token-aaaaaaaaaaaaaaaaaaaa"
	stubNewToken   = "new-token-bbbbbbbbbbbbbbbbbbbb"
	stubNewerToken = "newer-token-cccccccccccccccccc"
)

// (a) Keyboard-interactive full cycle: expired seed credential -> partial
// success -> valid token at the prompt -> stored at gen+1 -> confirmation ->
// server closes the connection -> reconnect with the same key gets full
// transport auth with NO prompt.
func TestWireRenewalKeyboardInteractive(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(wireCoderUserID)
	stub.set(stubOldToken, http.StatusUnauthorized)
	stub.set(stubNewToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)
	f.installCredential(t, stubOldToken) // generation 1

	ws := startWireServer(t, f.authConfig())
	defer ws.shutdown()

	probe := &clientProbe{}
	ki := &kiResponder{answers: []string{stubNewToken}}
	client, err := dialGateway(ws.addr(), "coder", probe, renewalMethods(f.signer, ki)...)
	if err != nil {
		t.Fatalf("renewal auth failed: %v", err)
	}
	defer client.Close()

	res := ws.lastResult()
	if res.err != nil {
		t.Fatalf("server handshake error: %v", res.err)
	}
	perms := mustParseFinalPerms(t, res.perms)
	if !perms.MustReconnect {
		t.Error("renewal success must set must_reconnect=true (§13.6)")
	}
	if perms.Mode != sshauth.ModeTransport || perms.AccountID != f.acct.ID || perms.SSHKeyID != f.keyRec.ID {
		t.Errorf("unexpected final perms: %+v", perms)
	}
	if perms.CredentialGeneration != 2 {
		t.Errorf("generation = %d, want 2", perms.CredentialGeneration)
	}

	snap, err := f.store.LoadCredential(context.Background(), f.acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.Generation != 2 || snap.State != core.CredentialStateValid {
		t.Errorf("stored credential = gen %d state %q, want gen 2 valid", snap.Generation, snap.State)
	}
	if string(snap.Token) != stubNewToken {
		t.Error("stored token is not the renewal candidate")
	}

	// §13.2/§13.3 confirmation: pre-auth success banner + zero-prompt
	// challenge.
	if !strings.Contains(probe.bannerText(), "Reconnect to continue") {
		t.Errorf("missing success banner: %q", probe.bannerText())
	}
	if ki.zeroPromptCount() != 1 {
		t.Errorf("zero-prompt confirmations = %d, want 1", ki.zeroPromptCount())
	}
	if strings.Contains(probe.bannerText(), stubNewToken) {
		t.Error("banner leaks token material")
	}

	// §13.6: deliberate disconnect.
	assertClosedAfterRenewal(t, client)

	// §34.3: one renewal success audit, no wrong-user event.
	if got := renewalAuditEvents(f, sshauth.ResultSuccess, ""); got != 1 {
		t.Errorf("renewal success audit events = %d, want 1", got)
	}
	if got := f.auditEvents(sshauth.EventTypeWrongUserToken); len(got) != 0 {
		t.Errorf("wrong-user events = %d, want 0", len(got))
	}

	// Reconnect: full transport auth with the new generation, no prompt.
	probe2 := &clientProbe{}
	client2, err := dialGateway(ws.addr(), "coder", probe2, ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("reconnect auth failed: %v", err)
	}
	defer client2.Close()
	res2 := ws.lastResult()
	if res2.err != nil {
		t.Fatalf("reconnect server error: %v", res2.err)
	}
	perms2 := mustParseFinalPerms(t, res2.perms)
	if perms2.MustReconnect {
		t.Error("reconnect must not force another reconnect")
	}
	if perms2.CredentialGeneration != 2 {
		t.Errorf("reconnect generation = %d, want 2", perms2.CredentialGeneration)
	}
	if strings.Contains(probe2.bannerText(), "/cli-auth") {
		t.Error("reconnect must not show the renewal banner")
	}
}

// (b) Password continuation: identical semantics to (a) — the password
// bytes are the Coder token (§13.3).
func TestWireRenewalPassword(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(wireCoderUserID)
	stub.set(stubOldToken, http.StatusUnauthorized)
	stub.set(stubNewToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)
	f.installCredential(t, stubOldToken)

	ws := startWireServer(t, f.authConfig())
	defer ws.shutdown()

	probe := &clientProbe{}
	client, err := dialGateway(ws.addr(), "coder", probe,
		ssh.PublicKeys(f.signer), ssh.Password(stubNewToken))
	if err != nil {
		t.Fatalf("password renewal auth failed: %v", err)
	}
	defer client.Close()

	res := ws.lastResult()
	if res.err != nil {
		t.Fatalf("server handshake error: %v", res.err)
	}
	perms := mustParseFinalPerms(t, res.perms)
	if !perms.MustReconnect || perms.CredentialGeneration != 2 {
		t.Errorf("unexpected final perms: %+v", perms)
	}

	snap, err := f.store.LoadCredential(context.Background(), f.acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.Generation != 2 || string(snap.Token) != stubNewToken {
		t.Errorf("stored credential = gen %d, want gen 2 with new token", snap.Generation)
	}

	// §13.3: the renewal instructions banner is sent BEFORE the partial
	// success (pre-password-prompt) and the success banner confirms after.
	banners := probe.bannerText()
	if !strings.Contains(banners, "/cli-auth") {
		t.Errorf("missing pre-prompt renewal instructions (§13.3): %q", banners)
	}
	if !strings.Contains(banners, "Coder token verified. Reconnect to continue.") {
		t.Errorf("missing post-success confirmation banner (§13.3): %q", banners)
	}
	if strings.Contains(banners, stubNewToken) {
		t.Error("banner leaks token material")
	}

	assertClosedAfterRenewal(t, client)

	if got := renewalAuditEvents(f, sshauth.ResultSuccess, ""); got != 1 {
		t.Errorf("renewal success audit events = %d, want 1", got)
	}
	if ws.stateAt(0).RenewalAttempts() != 1 {
		t.Errorf("renewal attempts = %d, want 1", ws.stateAt(0).RenewalAttempts())
	}
}

// (c) Wrong-user token: Coder accepts the candidate but resolves it to a
// different UUID -> rejected, security audit AUTH_WRONG_CODER_IDENTITY,
// store generation unchanged, no retry for the same class.
func TestWireRenewalWrongUserToken(t *testing.T) {
	defer leakCheck(t)

	otherUser := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	stub := newCoderStub(otherUser)
	stub.set(stubOldToken, http.StatusUnauthorized)
	stub.set(stubNewToken, http.StatusOK) // valid token, WRONG Coder user
	f := newFixture(t, stub)
	defer f.close(t)
	f.installCredential(t, stubOldToken)

	ws := startWireServer(t, f.authConfig())
	defer ws.shutdown()

	probe := &clientProbe{}
	ki := &kiResponder{answers: []string{stubNewToken, stubNewToken, stubNewToken}}
	client, err := dialGateway(ws.addr(), "coder", probe, renewalMethods(f.signer, ki)...)
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("expected auth failure for wrong-user token")
	}

	res := ws.lastResult()
	if res.err == nil {
		t.Fatal("server accepted a wrong-user token")
	}
	if res.perms != nil {
		t.Error("rejected renewal must not yield permissions")
	}

	// No retry for this failure class: exactly one token challenge.
	if ki.promptCount() != 1 {
		t.Errorf("token challenges = %d, want 1 (no retry for wrong-user)", ki.promptCount())
	}

	wrong := f.auditEvents(sshauth.EventTypeWrongUserToken)
	if len(wrong) != 1 {
		t.Fatalf("wrong-user audit events = %d, want 1", len(wrong))
	}
	if wrong[0].DetailCode != core.AUTH_WRONG_CODER_IDENTITY {
		t.Errorf("detail code = %q, want %q", wrong[0].DetailCode, core.AUTH_WRONG_CODER_IDENTITY)
	}
	if wrong[0].AccountID != f.acct.ID.String() {
		t.Errorf("wrong-user event account = %q", wrong[0].AccountID)
	}

	snap, err := f.store.LoadCredential(context.Background(), f.acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.Generation != 1 || string(snap.Token) != stubOldToken {
		t.Errorf("store mutated by wrong-user token: gen %d", snap.Generation)
	}
	if strings.Contains(probe.bannerText(), stubNewToken) {
		t.Error("banner leaks token material")
	}
}

// (d) Retry path: first candidate invalid (401) -> re-challenge with an
// error instruction -> second candidate valid -> success (attempts=2).
func TestWireRenewalRetryThenSuccess(t *testing.T) {
	defer leakCheck(t)

	badToken := "bad-token-dddddddddddddddddddd"
	stub := newCoderStub(wireCoderUserID)
	stub.set(stubOldToken, http.StatusUnauthorized)
	stub.set(badToken, http.StatusUnauthorized)
	stub.set(stubNewToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)
	f.installCredential(t, stubOldToken)

	ws := startWireServer(t, f.authConfig())
	defer ws.shutdown()

	ki := &kiResponder{answers: []string{badToken, stubNewToken}}
	client, err := dialGateway(ws.addr(), "coder", &clientProbe{}, renewalMethods(f.signer, ki)...)
	if err != nil {
		t.Fatalf("renewal with one retry failed: %v", err)
	}
	defer client.Close()

	res := ws.lastResult()
	if res.err != nil {
		t.Fatalf("server handshake error: %v", res.err)
	}
	if !mustParseFinalPerms(t, res.perms).MustReconnect {
		t.Error("expected must_reconnect=true")
	}

	if ki.promptCount() != 2 {
		t.Errorf("token challenges = %d, want 2", ki.promptCount())
	}
	if !strings.Contains(ki.instructionAt(1), "Token not accepted") {
		t.Errorf("retry instruction missing error text: %q", ki.instructionAt(1))
	}
	if got := ws.stateAt(0).RenewalAttempts(); got != 2 {
		t.Errorf("renewal attempts = %d, want 2", got)
	}

	snap, err := f.store.LoadCredential(context.Background(), f.acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.Generation != 2 || string(snap.Token) != stubNewToken {
		t.Errorf("stored credential = gen %d, want gen 2 with new token", snap.Generation)
	}

	// One retryable failure + one success audited.
	if got := renewalAuditEvents(f, sshauth.ResultFailure, core.AUTH_CREDENTIAL_UNAUTHORIZED); got != 1 {
		t.Errorf("renewal 401-failure audit events = %d, want 1", got)
	}
	if got := renewalAuditEvents(f, sshauth.ResultSuccess, ""); got != 1 {
		t.Errorf("renewal success audit events = %d, want 1", got)
	}
}

// (e) Attempts exhausted: MaxAttempts=2, client willing to answer three
// times with bad tokens -> auth failure after the second challenge.
func TestWireRenewalAttemptsExhausted(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(wireCoderUserID)
	stub.set(stubOldToken, http.StatusUnauthorized) // every candidate 401s
	f := newFixture(t, stub)
	defer f.close(t)
	f.installCredential(t, stubOldToken)

	cfg := f.authConfig()
	cfg.Renewal.MaxAttempts = 2
	ws := startWireServer(t, cfg)
	defer ws.shutdown()

	ki := &kiResponder{answers: []string{"cand-one-eeeeeeeeeeeeeeeeee", "cand-two-eeeeeeeeeeeeeeeeee", "cand-three-eeeeeeeeeeeeeeee"}}
	client, err := dialGateway(ws.addr(), "coder", &clientProbe{}, renewalMethods(f.signer, ki)...)
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("expected auth failure after exhausted attempts")
	}

	res := ws.lastResult()
	if res.err == nil {
		t.Fatal("server accepted after attempts exhausted")
	}
	if ki.promptCount() != 2 {
		t.Errorf("token challenges = %d, want 2 (MaxAttempts)", ki.promptCount())
	}
	if got := ws.stateAt(0).RenewalAttempts(); got != 2 {
		t.Errorf("renewal attempts = %d, want 2", got)
	}
	if got := renewalAuditEvents(f, sshauth.ResultFailure, sshauth.DetailRenewalAttemptsExhausted); got != 1 {
		t.Errorf("attempts-exhausted audit events = %d, want 1", got)
	}

	snap, err := f.store.LoadCredential(context.Background(), f.acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.Generation != 1 {
		t.Errorf("generation = %d, want 1 (store untouched)", snap.Generation)
	}
}

// (f) Coder 503 during renewal: clean failure, NO further prompts, and the
// stored credential is not overwritten (§13.2/§35).
func TestWireRenewalCoderUnavailable(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(wireCoderUserID)
	stub.set(stubOldToken, http.StatusUnauthorized)
	stub.set(stubNewToken, http.StatusServiceUnavailable)
	f := newFixture(t, stub)
	defer f.close(t)
	f.installCredential(t, stubOldToken)

	ws := startWireServer(t, f.authConfig())
	defer ws.shutdown()

	ki := &kiResponder{answers: []string{stubNewToken, stubNewToken, stubNewToken}}
	client, err := dialGateway(ws.addr(), "coder", &clientProbe{}, renewalMethods(f.signer, ki)...)
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("expected auth failure while Coder is unavailable")
	}

	res := ws.lastResult()
	if res.err == nil {
		t.Fatal("server accepted while Coder unavailable")
	}
	if ki.promptCount() != 1 {
		t.Errorf("token challenges = %d, want 1 (no re-prompt on 503)", ki.promptCount())
	}
	if got := renewalAuditEvents(f, sshauth.ResultFailure, core.AUTH_CODER_UNAVAILABLE); got != 1 {
		t.Errorf("coder-unavailable audit events = %d, want 1", got)
	}

	snap, err := f.store.LoadCredential(context.Background(), f.acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.Generation != 1 || string(snap.Token) != stubOldToken {
		t.Errorf("credential overwritten during outage: gen %d", snap.Generation)
	}
}

// (g) Concurrent renewals: two connections for the same account, both with
// valid-but-different tokens. Exactly one stores (generation CAS); the other
// takes the §23.2 already-updated reconnect path.
func TestWireRenewalConcurrent(t *testing.T) {
	defer leakCheck(t)

	tokenA := "token-a-ffffffffffffffffffffff"
	tokenB := "token-b-gggggggggggggggggggggg"
	stub := newCoderStub(wireCoderUserID)
	stub.set(stubOldToken, http.StatusUnauthorized)
	stub.set(tokenA, http.StatusOK)
	stub.set(tokenB, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)
	f.installCredential(t, stubOldToken)

	cfg := f.authConfig()
	cfg.Verifier = newCachedVerifierBarrier(f.verifier, 2)
	ws := startWireServer(t, cfg)
	defer ws.shutdown()

	var wg sync.WaitGroup
	clients := make([]*ssh.Client, 2)
	errs := make([]error, 2)
	tokens := []string{tokenA, tokenB}
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ki := &kiResponder{answers: []string{tokens[i]}}
			c, err := dialGateway(ws.addr(), "coder", &clientProbe{}, renewalMethods(f.signer, ki)...)
			clients[i] = c
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i := range 2 {
		if errs[i] != nil {
			t.Fatalf("concurrent renewal %d failed: %v", i, errs[i])
		}
		defer clients[i].Close()
	}

	results := ws.waitResults(2)
	for i, res := range results {
		if res.err != nil {
			t.Fatalf("server handshake %d error: %v", i, res.err)
		}
		perms := mustParseFinalPerms(t, res.perms)
		if !perms.MustReconnect {
			t.Errorf("handshake %d: expected must_reconnect=true on BOTH paths", i)
		}
	}

	snap, err := f.store.LoadCredential(context.Background(), f.acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.Generation != 2 {
		t.Errorf("generation = %d, want 2 (exactly one store won)", snap.Generation)
	}
	if got := string(snap.Token); got != tokenA && got != tokenB {
		t.Error("stored token is neither candidate")
	}

	if got := renewalAuditEvents(f, sshauth.ResultSuccess, ""); got != 1 {
		t.Errorf("plain renewal successes = %d, want 1", got)
	}
	if got := renewalAuditEvents(f, sshauth.ResultSuccess, sshauth.DetailRenewalAlreadyUpdated); got != 1 {
		t.Errorf("already-updated events = %d, want 1 (§23.2)", got)
	}
	if got := renewalAuditEvents(f, sshauth.ResultFailure, ""); got != 0 {
		t.Errorf("renewal failures = %d, want 0", got)
	}
}

// (h) Reconnect allowance: with a rate limiter holding a single token, the
// first renewal consumes it; the allowance granted on success lets the next
// connection's renewal attempt through (§13.6).
func TestWireRenewalReconnectAllowance(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(wireCoderUserID)
	stub.set(stubOldToken, http.StatusUnauthorized)
	stub.set(stubNewToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)
	f.installCredential(t, stubOldToken)

	f.rate = newFakeRateLimiter(1) // exactly one renewal attempt permitted
	ws := startWireServer(t, f.authConfig())
	defer ws.shutdown()

	ki1 := &kiResponder{answers: []string{stubNewToken}}
	client1, err := dialGateway(ws.addr(), "coder", &clientProbe{}, renewalMethods(f.signer, ki1)...)
	if err != nil {
		t.Fatalf("first renewal failed: %v", err)
	}
	defer client1.Close()
	if res := ws.lastResult(); res.err != nil {
		t.Fatalf("first handshake error: %v", res.err)
	}
	if f.rate.grants != 1 {
		t.Fatalf("reconnect grants = %d, want 1", f.rate.grants)
	}

	// The stored credential expires again immediately: the reconnect must
	// renew a second time, permitted only by the §13.6 allowance.
	stub.set(stubNewToken, http.StatusUnauthorized)
	stub.set(stubNewerToken, http.StatusOK)

	ki2 := &kiResponder{answers: []string{stubNewerToken}}
	client2, err := dialGateway(ws.addr(), "coder", &clientProbe{}, renewalMethods(f.signer, ki2)...)
	if err != nil {
		t.Fatalf("second renewal failed despite reconnect allowance: %v", err)
	}
	defer client2.Close()

	results := ws.waitResults(2)
	if results[1].err != nil {
		t.Fatalf("second handshake error: %v", results[1].err)
	}
	if perms := mustParseFinalPerms(t, results[1].perms); perms.CredentialGeneration != 3 {
		t.Errorf("second renewal generation = %d, want 3", perms.CredentialGeneration)
	}

	f.rate.mu.Lock()
	used, denied := f.rate.allowanceUsed, f.rate.denied
	f.rate.mu.Unlock()
	if used != 1 {
		t.Errorf("allowance-based attempts = %d, want 1", used)
	}
	if denied != 0 {
		t.Errorf("denied attempts = %d, want 0", denied)
	}
}

// (i) Deadline: the §13.5 renewal timeout tears down a connection whose
// client stalls at the token prompt.
func TestWireRenewalDeadline(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(wireCoderUserID)
	stub.set(stubOldToken, http.StatusUnauthorized)
	stub.set(stubNewToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)
	f.installCredential(t, stubOldToken)

	cfg := f.authConfig()
	cfg.Renewal.RenewalTimeout = 300 * time.Millisecond
	ws := startWireServer(t, cfg)
	defer ws.shutdown()

	stall := make(chan struct{})
	ki := &kiResponder{stall: stall}
	start := time.Now()
	dialErr := make(chan error, 1)
	go func() {
		c, err := dialGateway(ws.addr(), "coder", &clientProbe{}, renewalMethods(f.signer, ki)...)
		if c != nil {
			c.Close()
		}
		dialErr <- err
	}()

	// The server tears the connection down at the renewal deadline even
	// though the client never answers the challenge.
	res := ws.lastResult()
	elapsed := time.Since(start)
	if res.err == nil {
		t.Fatal("server accepted a stalled renewal")
	}
	if elapsed < 250*time.Millisecond || elapsed > 3*time.Second {
		t.Errorf("teardown at %v, want ~300ms (§13.5 renewal deadline)", elapsed)
	}

	close(stall)
	if err := <-dialErr; err == nil {
		t.Fatal("client dial unexpectedly succeeded")
	}

	snap, err := f.store.LoadCredential(context.Background(), f.acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.Generation != 1 {
		t.Errorf("generation = %d, want 1 (stalled renewal stores nothing)", snap.Generation)
	}
}
