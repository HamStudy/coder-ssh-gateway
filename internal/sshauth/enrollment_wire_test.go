package sshauth_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
)

// enrollCoderUserID is the Coder user UUID the enrollment stub resolves to.
var enrollCoderUserID = uuid.MustParse("55555555-5555-5555-5555-555555555555")

const enrollToken = "enroll-token-0123456789abcdefghij"

// enrollmentAuthConfig arms the login@ enrollment flow on the fixture's
// auth config (real store, real uncached verifier, fake rate limiter).
func (f *fixture) enrollmentAuthConfig() sshauth.AuthConfig {
	cfg := f.authConfig()
	cfg.EnrollmentUser = "login"
	cfg.Enrollment = &sshauth.EnrollmentConfig{
		Enabled:     true,
		Verifier:    f.rawVerifier,
		Store:       f.store,
		Rate:        f.rate,
		Audit:       f.audit,
		Logger:      cfg.Logger,
		CoderURL:    f.dep.CoderURL,
		MaxAttempts: 0,
	}
	return cfg
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

// enrollmentMethods are the client auth methods for the enrollment flow:
// public key first, then the scripted continuation.
func enrollmentMethods(signer ssh.Signer, ki *kiResponder, password string) []ssh.AuthMethod {
	methods := []ssh.AuthMethod{ssh.PublicKeys(signer)}
	if ki != nil {
		methods = append(methods, ssh.KeyboardInteractive(ki.challenge))
	}
	if password != "" {
		methods = append(methods, ssh.Password(password))
	}
	return methods
}

func enrollmentAuditEvents(f *fixture, eventType, result, detailContains string) int {
	n := 0
	for _, ev := range f.auditEvents(eventType) {
		if ev.Result != result {
			continue
		}
		if detailContains != "" && !strings.Contains(ev.DetailCode, detailContains) {
			continue
		}
		n++
	}
	return n
}

type countingEnrollmentVerifier struct {
	inner sshauth.EnrollmentVerifier
	calls atomic.Int32
}

type enrollmentStateSnapshot struct {
	accounts []core.Account
	keys     map[uuid.UUID][]core.SSHKeyRecord
}

func wipeTestBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func snapshotEnrollmentState(t *testing.T, f *fixture) enrollmentStateSnapshot {
	t.Helper()
	accounts, err := f.store.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	keys := make(map[uuid.UUID][]core.SSHKeyRecord, len(accounts))
	for _, account := range accounts {
		accountKeys, err := f.store.ListKeysForAccount(account.ID)
		if err != nil {
			t.Fatalf("ListKeysForAccount(%s): %v", account.ID, err)
		}
		keys[account.ID] = accountKeys
	}
	return enrollmentStateSnapshot{accounts: accounts, keys: keys}
}

func sameAccount(a, b core.Account) bool {
	if a.ID != b.ID || a.DeploymentID != b.DeploymentID || a.Label != b.Label ||
		a.CachedUsername != b.CachedUsername || a.BindOnFirstToken != b.BindOnFirstToken ||
		a.Enabled != b.Enabled {
		return false
	}
	if a.CoderUserID == nil || b.CoderUserID == nil {
		return a.CoderUserID == nil && b.CoderUserID == nil
	}
	return *a.CoderUserID == *b.CoderUserID
}

func sameKey(a, b core.SSHKeyRecord) bool {
	return a == b
}

func assertEnrollmentStateUnchanged(t *testing.T, before, after enrollmentStateSnapshot) {
	t.Helper()
	if len(after.accounts) != len(before.accounts) {
		t.Errorf("account count changed: before=%d after=%d", len(before.accounts), len(after.accounts))
	}
	for i, beforeAccount := range before.accounts {
		if i >= len(after.accounts) {
			break
		}
		afterAccount := after.accounts[i]
		if !sameAccount(beforeAccount, afterAccount) {
			t.Errorf("account[%d] changed: before=%+v after=%+v", i, beforeAccount, afterAccount)
			continue
		}

		beforeKeys := before.keys[beforeAccount.ID]
		afterKeys := after.keys[afterAccount.ID]
		if len(afterKeys) != len(beforeKeys) {
			t.Errorf("account %s key count changed: before=%d after=%d", beforeAccount.ID, len(beforeKeys), len(afterKeys))
		}
		for j, beforeKey := range beforeKeys {
			if j >= len(afterKeys) {
				break
			}
			if !sameKey(beforeKey, afterKeys[j]) {
				t.Errorf("account %s key[%d] changed: before=%+v after=%+v", beforeAccount.ID, j, beforeKey, afterKeys[j])
			}
		}
	}
	for accountID, beforeKeys := range before.keys {
		afterKeys, ok := after.keys[accountID]
		if !ok {
			continue
		}
		if len(afterKeys) != len(beforeKeys) {
			continue
		}
		for i := range beforeKeys {
			if !sameKey(beforeKeys[i], afterKeys[i]) {
				t.Errorf("account %s key[%d] changed outside aligned account list: before=%+v after=%+v", accountID, i, beforeKeys[i], afterKeys[i])
			}
		}
	}
	for accountID := range after.keys {
		if _, ok := before.keys[accountID]; !ok {
			t.Errorf("new key state appeared for account %s", accountID)
		}
	}
}

func (v *countingEnrollmentVerifier) Verify(ctx context.Context, token []byte) (core.CoderIdentity, error) {
	v.calls.Add(1)
	return v.inner.Verify(ctx, token)
}

// accountForCoderID finds the account bound to the given Coder user UUID.
func accountForCoderID(t *testing.T, f *fixture, coderID uuid.UUID) (core.Account, bool) {
	t.Helper()
	accounts, err := f.store.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	for _, a := range accounts {
		if a.CoderUserID != nil && *a.CoderUserID == coderID {
			return a, true
		}
	}
	return core.Account{}, false
}

// enrollOnce drives a full login@ enrollment and returns the parsed final
// permissions. The server is expected to close the connection (§13.6).
func enrollOnce(t *testing.T, ws *wireServer, signer ssh.Signer, ki *kiResponder, password string) (sshauth.FinalPerms, *ssh.Client) {
	t.Helper()
	probe := &clientProbe{}
	client, err := dialGateway(ws.addr(), "login", probe, enrollmentMethods(signer, ki, password)...)
	if err != nil {
		t.Fatalf("enrollment auth failed: %v", err)
	}
	res := ws.lastResult()
	if res.err != nil {
		t.Fatalf("server handshake error: %v", res.err)
	}
	perms := mustParseFinalPerms(t, res.perms)
	if !perms.MustReconnect {
		t.Error("enrollment success must set must_reconnect=true (§13.6 parity)")
	}
	if !strings.Contains(probe.bannerText(), "Enrolled. Coder user") {
		t.Errorf("missing enrollment success banner: %q", probe.bannerText())
	}
	if strings.Contains(probe.bannerText(), enrollToken) {
		t.Error("banner leaks token material")
	}
	assertClosedAfterRenewal(t, client)
	return perms, client
}

// (a) First system: fresh key + valid token (new Coder UUID) -> account
// created, key linked, credential stored at generation 1, confirmation
// banner, server closes the connection.
func TestWireEnrollmentFirstSystem(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(enrollCoderUserID)
	stub.set(enrollToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)

	ws := startWireServer(t, f.enrollmentAuthConfig())
	defer ws.shutdown()

	signer := newSigner(t)
	ki := &kiResponder{answers: []string{enrollToken}}
	perms, client := enrollOnce(t, ws, signer, ki, "")
	defer client.Close()

	account, ok := accountForCoderID(t, f, enrollCoderUserID)
	if !ok {
		t.Fatal("no account created for the token's Coder user")
	}
	if perms.AccountID != account.ID {
		t.Errorf("perms account = %v, want %v", perms.AccountID, account.ID)
	}
	if perms.Mode != sshauth.ModeTransport {
		t.Errorf("mode = %q, want transport", perms.Mode)
	}
	if perms.CredentialGeneration != 1 {
		t.Errorf("generation = %d, want 1", perms.CredentialGeneration)
	}

	owner, exists, err := f.store.KeyDigestExists(sshauth.KeyDigestHex(signer.PublicKey()))
	if err != nil || !exists {
		t.Fatalf("key digest not stored: exists=%v err=%v", exists, err)
	}
	if owner != account.ID {
		t.Errorf("key digest owner = %v, want %v", owner, account.ID)
	}

	snap, err := f.store.LoadCredential(context.Background(), account.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.Generation != 1 || snap.State != core.CredentialStateValid {
		t.Errorf("credential = gen %d state %q, want gen 1 valid", snap.Generation, snap.State)
	}
	if string(snap.Token) != enrollToken {
		t.Error("stored token is not the enrollment candidate")
	}
	wipe := snap.Token
	defer func() {
		for i := range wipe {
			wipe[i] = 0
		}
	}()

	if got := enrollmentAuditEvents(f, sshauth.EventTypeEnrollmentSuccess, sshauth.ResultSuccess, sshauth.DetailEnrollmentAccountCreated); got != 1 {
		t.Errorf("account_created success events = %d, want 1", got)
	}
	if got := enrollmentAuditEvents(f, sshauth.EventTypeEnrollmentSuccess, sshauth.ResultSuccess, sshauth.DetailEnrollmentKeyLinked); got != 1 {
		t.Errorf("key_linked success events = %d, want 1", got)
	}
	if ki.promptCount() != 1 {
		t.Errorf("token challenges = %d, want 1", ki.promptCount())
	}
}

// (b) Convergence: a second system with a fresh key and the SAME token
// converges on the same account, links key #2, and refreshes the
// credential (generation increments, created flag false).
func TestWireEnrollmentConvergence(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(enrollCoderUserID)
	stub.set(enrollToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)

	ws := startWireServer(t, f.enrollmentAuthConfig())
	defer ws.shutdown()

	accountsBefore, err := f.store.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}

	signer1 := newSigner(t)
	perms1, client1 := enrollOnce(t, ws, signer1, &kiResponder{answers: []string{enrollToken}}, "")
	defer client1.Close()

	signer2 := newSigner(t)
	perms2, client2 := enrollOnce(t, ws, signer2, &kiResponder{answers: []string{enrollToken}}, "")
	defer client2.Close()

	if perms1.AccountID != perms2.AccountID {
		t.Errorf("same token converged on different accounts: %v vs %v", perms1.AccountID, perms2.AccountID)
	}
	if perms1.SSHKeyID == perms2.SSHKeyID {
		t.Error("second key must get its own key record")
	}
	if perms2.CredentialGeneration != 2 {
		t.Errorf("second enrollment generation = %d, want 2 (token refreshed)", perms2.CredentialGeneration)
	}

	accountsAfter, err := f.store.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(accountsAfter) != len(accountsBefore)+1 {
		t.Errorf("accounts = %d, want %d (exactly one created)", len(accountsAfter), len(accountsBefore)+1)
	}

	snap, err := f.store.LoadCredential(context.Background(), perms2.AccountID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.Generation != 2 || string(snap.Token) != enrollToken {
		t.Errorf("credential = gen %d, want gen 2 with the refreshed token", snap.Generation)
	}
	wipe := snap.Token
	defer func() {
		for i := range wipe {
			wipe[i] = 0
		}
	}()

	// The second success audit carries key_linked but NOT account_created.
	var secondDetails []string
	for _, ev := range f.auditEvents(sshauth.EventTypeEnrollmentSuccess) {
		secondDetails = append(secondDetails, ev.DetailCode)
	}
	if len(secondDetails) != 2 {
		t.Fatalf("enrollment success events = %d, want 2", len(secondDetails))
	}
	if strings.Contains(secondDetails[1], sshauth.DetailEnrollmentAccountCreated) {
		t.Errorf("second enrollment must not report account_created: %q", secondDetails[1])
	}
	if !strings.Contains(secondDetails[1], sshauth.DetailEnrollmentKeyLinked) {
		t.Errorf("second enrollment must report key_linked: %q", secondDetails[1])
	}
}

// (c) Key conflict: a key already linked to account A, offered to login@
// with a token resolving to account B -> hard reject, no account mutation,
// no credential change, audit key_already_linked, no retry.
func TestWireEnrollmentKeyConflict(t *testing.T) {
	defer leakCheck(t)

	// The fixture account is bound to wireCoderUserID; the enrollment stub
	// resolves the token to a DIFFERENT Coder user.
	stub := newCoderStub(enrollCoderUserID)
	stub.set(enrollToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)
	f.installCredential(t, "acct-a-token-0123456789abcdef")

	ws := startWireServer(t, f.enrollmentAuthConfig())
	defer ws.shutdown()

	accountsBefore, err := f.store.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}

	probe := &clientProbe{}
	ki := &kiResponder{answers: []string{enrollToken, enrollToken, enrollToken}}
	client, err := dialGateway(ws.addr(), "login", probe, enrollmentMethods(f.signer, ki, "")...)
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("expected auth failure for cross-account key conflict")
	}

	res := ws.lastResult()
	if res.err == nil {
		t.Fatal("server accepted a key already linked to another account")
	}
	if res.perms != nil {
		t.Error("conflict rejection must not yield permissions")
	}
	if ki.promptCount() != 1 {
		t.Errorf("token challenges = %d, want 1 (no retry for key conflict)", ki.promptCount())
	}
	if !strings.Contains(probe.bannerText(), "already linked to another account") {
		t.Errorf("missing conflict guidance banner: %q", probe.bannerText())
	}

	if got := enrollmentAuditEvents(f, sshauth.EventTypeEnrollmentRejected, sshauth.ResultFailure, sshauth.DetailEnrollmentKeyAlreadyLinked); got != 1 {
		t.Errorf("key_already_linked events = %d, want 1", got)
	}

	accountsAfter, err := f.store.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(accountsAfter) != len(accountsBefore) {
		t.Errorf("accounts = %d, want %d (no account mutation)", len(accountsAfter), len(accountsBefore))
	}
	snap, err := f.store.LoadCredential(context.Background(), f.acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.Generation != 1 || string(snap.Token) != "acct-a-token-0123456789abcdef" {
		t.Errorf("account A credential changed: gen %d", snap.Generation)
	}
	wipe := snap.Token
	defer func() {
		for i := range wipe {
			wipe[i] = 0
		}
	}()
}

// (d) Invalid token re-prompts; retries are bounded by MaxAttempts;
// exhaustion fails auth and stores nothing. Unavailable Coder (503) fails
// cleanly with no prompt loop and nothing stored.
func TestWireEnrollmentInvalidTokenAndUnavailable(t *testing.T) {
	defer leakCheck(t)

	t.Run("invalid token bounded retry", func(t *testing.T) {
		stub := newCoderStub(enrollCoderUserID) // every candidate 401s
		f := newFixture(t, stub)
		defer f.close(t)

		cfg := f.enrollmentAuthConfig()
		cfg.Enrollment.MaxAttempts = 2
		ws := startWireServer(t, cfg)
		defer ws.shutdown()

		ki := &kiResponder{answers: []string{
			"cand-one-eeeeeeeeeeeeeeeeeeee",
			"cand-two-eeeeeeeeeeeeeeeeeeee",
			"cand-three-eeeeeeeeeeeeeeeeee",
		}}
		client, err := dialGateway(ws.addr(), "login", &clientProbe{}, enrollmentMethods(newSigner(t), ki, "")...)
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatal("expected auth failure after exhausted attempts")
		}
		if ki.promptCount() != 2 {
			t.Errorf("token challenges = %d, want 2 (MaxAttempts)", ki.promptCount())
		}
		if !strings.Contains(ki.instructionAt(1), "Token not accepted") {
			t.Errorf("retry instruction missing error text: %q", ki.instructionAt(1))
		}
		if got := enrollmentAuditEvents(f, sshauth.EventTypeEnrollmentRejected, sshauth.ResultFailure, core.AUTH_CREDENTIAL_UNAUTHORIZED); got != 2 {
			t.Errorf("401 rejection events = %d, want 2", got)
		}
		if got := enrollmentAuditEvents(f, sshauth.EventTypeEnrollmentRejected, sshauth.ResultFailure, sshauth.DetailEnrollmentAttemptsExhausted); got != 1 {
			t.Errorf("attempts-exhausted events = %d, want 1", got)
		}
		if _, ok := accountForCoderID(t, f, enrollCoderUserID); ok {
			t.Error("nothing must be stored for rejected tokens")
		}
	})

	t.Run("coder unavailable clean failure", func(t *testing.T) {
		stub := newCoderStub(enrollCoderUserID)
		stub.set(enrollToken, http.StatusServiceUnavailable)
		f := newFixture(t, stub)
		defer f.close(t)

		ws := startWireServer(t, f.enrollmentAuthConfig())
		defer ws.shutdown()

		ki := &kiResponder{answers: []string{enrollToken, enrollToken, enrollToken}}
		client, err := dialGateway(ws.addr(), "login", &clientProbe{}, enrollmentMethods(newSigner(t), ki, "")...)
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatal("expected auth failure while Coder is unavailable")
		}
		if ki.promptCount() != 1 {
			t.Errorf("token challenges = %d, want 1 (no re-prompt on 503)", ki.promptCount())
		}
		if got := enrollmentAuditEvents(f, sshauth.EventTypeEnrollmentRejected, sshauth.ResultFailure, core.AUTH_CODER_UNAVAILABLE); got != 1 {
			t.Errorf("coder-unavailable events = %d, want 1", got)
		}
		if _, ok := accountForCoderID(t, f, enrollCoderUserID); ok {
			t.Error("nothing must be stored while Coder is unavailable")
		}
	})
}

// (e) Enrollment disabled (nil config, then Enabled=false): login@ rejects
// byte-identically to any unknown username (§35 — no oracle).
func TestWireEnrollmentDisabledUniformReject(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(enrollCoderUserID)
	stub.set(enrollToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)

	rejectText := func(cfg sshauth.AuthConfig, user string) string {
		ws := startWireServer(t, cfg)
		defer ws.shutdown()
		signer := newSigner(t)
		ki := &kiResponder{answers: []string{enrollToken}}
		client, err := dialGateway(ws.addr(), user, &clientProbe{}, enrollmentMethods(signer, ki, "")...)
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatalf("expected auth failure for user %q", user)
		}
		if ki.promptCount() != 0 {
			t.Errorf("user %q: token challenges = %d, want 0", user, ki.promptCount())
		}
		return err.Error()
	}

	unknownRef := rejectText(f.authConfig(), "nosuchuser")

	if got := rejectText(f.authConfig(), "login"); got != unknownRef {
		t.Errorf("nil enrollment config: login@ error differs from unknown username:\n  %q\n  %q", got, unknownRef)
	}

	disabled := f.enrollmentAuthConfig()
	disabled.Enrollment.Enabled = false
	if got := rejectText(disabled, "login"); got != unknownRef {
		t.Errorf("disabled enrollment: login@ error differs from unknown username:\n  %q\n  %q", got, unknownRef)
	}
}

// (f) Password continuation parity: the password bytes are the Coder
// token; the link outcome is identical to the KI path.
func TestWireEnrollmentPassword(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(enrollCoderUserID)
	stub.set(enrollToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)

	ws := startWireServer(t, f.enrollmentAuthConfig())
	defer ws.shutdown()

	signer := newSigner(t)
	perms, client := enrollOnce(t, ws, signer, nil, enrollToken)
	defer client.Close()

	account, ok := accountForCoderID(t, f, enrollCoderUserID)
	if !ok {
		t.Fatal("no account created via password continuation")
	}
	if perms.AccountID != account.ID || perms.CredentialGeneration != 1 {
		t.Errorf("unexpected final perms: %+v", perms)
	}
	if got := enrollmentAuditEvents(f, sshauth.EventTypeEnrollmentSuccess, sshauth.ResultSuccess, sshauth.DetailEnrollmentKeyLinked); got != 1 {
		t.Errorf("key_linked success events = %d, want 1", got)
	}
}

// (g) After enrollment, the same key authenticates as coder@ with the
// stored credential: enrollment produced a usable account end-to-end.
func TestWireEnrollmentThenTransportAuth(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(enrollCoderUserID)
	stub.set(enrollToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)

	ws := startWireServer(t, f.enrollmentAuthConfig())
	defer ws.shutdown()

	signer := newSigner(t)
	enrollPerms, client := enrollOnce(t, ws, signer, &kiResponder{answers: []string{enrollToken}}, "")
	defer client.Close()

	probe := &clientProbe{}
	client2, err := dialGateway(ws.addr(), "coder", probe, ssh.PublicKeys(signer))
	if err != nil {
		t.Fatalf("transport auth with enrolled key failed: %v", err)
	}
	defer client2.Close()

	res := ws.lastResult()
	if res.err != nil {
		t.Fatalf("server handshake error: %v", res.err)
	}
	perms := mustParseFinalPerms(t, res.perms)
	if perms.Mode != sshauth.ModeTransport || perms.MustReconnect {
		t.Errorf("unexpected perms: %+v", perms)
	}
	if perms.AccountID != enrollPerms.AccountID || perms.SSHKeyID != enrollPerms.SSHKeyID {
		t.Errorf("identity mismatch: %+v vs %+v", perms, enrollPerms)
	}
	if strings.Contains(probe.bannerText(), "/cli-auth") {
		t.Error("transport auth must not show renewal/enrollment banners")
	}
}

// (h) A certificate offered to login@ is rejected (§10.3 unchanged).
func TestWireEnrollmentRejectsCertificate(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(enrollCoderUserID)
	stub.set(enrollToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)

	cfg := f.enrollmentAuthConfig()
	verifier := &countingEnrollmentVerifier{inner: cfg.Enrollment.Verifier}
	cfg.Enrollment.Verifier = verifier
	const initialToken = "original-enrollment-token-0123456789"
	initial := f.installCredential(t, initialToken)
	defer wipeTestBytes(initial.Token)
	expectedToken := []byte(initialToken)
	defer wipeTestBytes(expectedToken)
	stateBefore := snapshotEnrollmentState(t, f)
	ws := startWireServer(t, cfg)
	defer ws.shutdown()

	keySigner := newSigner(t)
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             keySigner.PublicKey(),
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "enroll-cert",
		ValidPrincipals: []string{"login"},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, keySigner)
	if err != nil {
		t.Fatalf("NewCertSigner: %v", err)
	}

	ki := &kiResponder{answers: []string{enrollToken}}
	client, err := dialGateway(ws.addr(), "login", &clientProbe{}, enrollmentMethods(certSigner, ki, "")...)
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("expected auth failure for certificate on login@")
	}
	if ki.promptCount() != 0 {
		t.Errorf("token challenges = %d, want 0 (certificate rejected at candidate stage)", ki.promptCount())
	}
	if got := verifier.calls.Load(); got != 0 {
		t.Errorf("enrollment verifier calls = %d, want 0", got)
	}
	stateAfter := snapshotEnrollmentState(t, f)
	assertEnrollmentStateUnchanged(t, stateBefore, stateAfter)
	after, err := f.store.LoadCredential(context.Background(), f.acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential after certificate: %v", err)
	}
	defer wipeTestBytes(after.Token)
	tokenEqual := bytes.Equal(after.Token, expectedToken)
	if after.AccountID != initial.AccountID ||
		after.Generation != initial.Generation ||
		after.State != initial.State ||
		!tokenEqual ||
		!after.LastValidatedAt.Equal(initial.LastValidatedAt) {
		t.Errorf(
			"credential changed: account_id %s generation %d state %q token_equal=%t last_validated_at %s; want account_id %s generation %d state %q token_equal=true last_validated_at %s",
			after.AccountID,
			after.Generation,
			after.State,
			tokenEqual,
			after.LastValidatedAt,
			initial.AccountID,
			initial.Generation,
			initial.State,
			initial.LastValidatedAt,
		)
	}
	if got := enrollmentAuditEvents(f, sshauth.EventTypeEnrollmentSuccess, sshauth.ResultSuccess, ""); got != 0 {
		t.Errorf("enrollment success events = %d, want 0", got)
	}
}

// (i) Candidate probe without proof of possession: no token prompt is
// offered and no enrollment audit event is recorded
// (proof-before-prompt invariant, CD-2).
type failingSigner struct{ ssh.Signer }

func (s failingSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errors.New("test signer: refuses to sign")
}

func TestWireEnrollmentProbeWithoutProof(t *testing.T) {
	defer leakCheck(t)

	stub := newCoderStub(enrollCoderUserID)
	stub.set(enrollToken, http.StatusOK)
	f := newFixture(t, stub)
	defer f.close(t)

	ws := startWireServer(t, f.enrollmentAuthConfig())
	defer ws.shutdown()

	probe := &clientProbe{}
	ki := &kiResponder{answers: []string{enrollToken}}
	client, err := dialGateway(ws.addr(), "login", probe,
		ssh.PublicKeys(failingSigner{newSigner(t)}),
		ssh.KeyboardInteractive(ki.challenge),
	)
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("expected auth failure when the client never proves possession")
	}
	if ki.promptCount() != 0 {
		t.Errorf("token challenges = %d, want 0 (no prompt before proof)", ki.promptCount())
	}
	if strings.Contains(probe.bannerText(), "enrollment") || strings.Contains(probe.bannerText(), "/cli-auth") {
		t.Errorf("no enrollment banner before proof of possession: %q", probe.bannerText())
	}
	if got := len(f.auditEvents(sshauth.EventTypeEnrollmentSuccess)) + len(f.auditEvents(sshauth.EventTypeEnrollmentRejected)); got != 0 {
		t.Errorf("enrollment audit events = %d, want 0", got)
	}
	if _, ok := accountForCoderID(t, f, enrollCoderUserID); ok {
		t.Error("probe must not create an account")
	}
}

// (j) Per-IP pre-token gate (CD-2 §20): an exhausted gate rejects BEFORE
// the first prompt (no banner, no challenge, audit ENROLLMENT_RATE_LIMITED);
// between retries it ends the re-challenge loop cleanly. The gate sees the
// bare peer IP, not host:port.

// recordingGate is a race-safe PreTokenGate fake: it records each peer IP
// and refuses once allow is false or tripsAfter calls have passed.
type recordingGate struct {
	mu         sync.Mutex
	allow      bool
	tripsAfter int
	ips        []string
}

func (g *recordingGate) check(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ips = append(g.ips, ip)
	if g.tripsAfter > 0 && len(g.ips) > g.tripsAfter {
		return false
	}
	return g.allow
}

func (g *recordingGate) calls() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.ips...)
}
func TestWireEnrollmentPreTokenGate(t *testing.T) {
	defer leakCheck(t)

	t.Run("exhausted before first prompt", func(t *testing.T) {
		stub := newCoderStub(enrollCoderUserID)
		stub.set(enrollToken, http.StatusOK)
		f := newFixture(t, stub)
		defer f.close(t)

		gate := &recordingGate{allow: false}
		cfg := f.enrollmentAuthConfig()
		cfg.Enrollment.PreTokenGate = gate.check
		ws := startWireServer(t, cfg)
		defer ws.shutdown()

		probe := &clientProbe{}
		ki := &kiResponder{answers: []string{enrollToken}}
		client, err := dialGateway(ws.addr(), "login", probe, enrollmentMethods(newSigner(t), ki, "")...)
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatal("expected auth failure with the pre-token gate exhausted")
		}
		if ki.promptCount() != 0 {
			t.Errorf("token challenges = %d, want 0 (gate refused before the prompt)", ki.promptCount())
		}
		if strings.Contains(probe.bannerText(), "enrollment") || strings.Contains(probe.bannerText(), "/cli-auth") {
			t.Errorf("no enrollment banner when the gate refuses: %q", probe.bannerText())
		}
		if got := gate.calls(); len(got) != 1 || got[0] != "127.0.0.1" {
			t.Errorf("gate calls = %v, want one call with the bare peer IP", got)
		}
		if got := enrollmentAuditEvents(f, sshauth.EventTypeEnrollmentRejected, sshauth.ResultFailure, sshauth.DetailEnrollmentRateLimited); got != 1 {
			t.Errorf("rate-limited rejection events = %d, want 1", got)
		}
		if _, ok := accountForCoderID(t, f, enrollCoderUserID); ok {
			t.Error("nothing must be stored when the gate refuses")
		}
	})

	t.Run("exhausted between retries", func(t *testing.T) {
		stub := newCoderStub(enrollCoderUserID) // every candidate 401s
		f := newFixture(t, stub)
		defer f.close(t)

		gate := &recordingGate{allow: true, tripsAfter: 1}
		cfg := f.enrollmentAuthConfig()
		cfg.Enrollment.PreTokenGate = gate.check
		ws := startWireServer(t, cfg)
		defer ws.shutdown()

		ki := &kiResponder{answers: []string{
			"cand-one-eeeeeeeeeeeeeeeeeeee",
			"cand-two-eeeeeeeeeeeeeeeeeeee",
		}}
		client, err := dialGateway(ws.addr(), "login", &clientProbe{}, enrollmentMethods(newSigner(t), ki, "")...)
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatal("expected auth failure once the gate trips")
		}
		if ki.promptCount() != 1 {
			t.Errorf("token challenges = %d, want 1 (retry gated)", ki.promptCount())
		}
		if got := gate.calls(); len(got) != 2 {
			t.Errorf("gate calls = %d, want 2 (first prompt + retry)", len(got))
		}
		if got := enrollmentAuditEvents(f, sshauth.EventTypeEnrollmentRejected, sshauth.ResultFailure, sshauth.DetailEnrollmentRateLimited); got != 1 {
			t.Errorf("rate-limited rejection events = %d, want 1", got)
		}
	})
}

// Unit-level: enrollment candidate permissions round-trip and validation.
func TestEnrollmentCandidatePermissions(t *testing.T) {
	digest := sshauth.KeyDigestHex(mustPublicKey(t))
	perms := sshauth.EnrollmentCandidatePermissions(digest)
	parsed, err := sshauth.ParseEnrollmentCandidatePermissions(perms)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Mode != sshauth.ModeEnrollment || parsed.KeyDigest != digest {
		t.Errorf("parsed = %+v, want mode enrollment digest %q", parsed, digest)
	}

	// The generic candidate parser must reject enrollment perms (distinct
	// modes), and the enrollment parser must reject garbage.
	if _, err := sshauth.ParseCandidatePermissions(perms); err == nil {
		t.Error("ParseCandidatePermissions accepted enrollment perms")
	}
	bad := sshauth.EnrollmentCandidatePermissions("zzzz")
	if _, err := sshauth.ParseEnrollmentCandidatePermissions(bad); !errors.Is(err, sshauth.ErrInvalidEnrollmentKeyDigest) {
		t.Errorf("non-hex digest error = %v, want ErrInvalidEnrollmentKeyDigest", err)
	}
	upper := sshauth.EnrollmentCandidatePermissions(strings.ToUpper(digest))
	if _, err := sshauth.ParseEnrollmentCandidatePermissions(upper); !errors.Is(err, sshauth.ErrInvalidEnrollmentKeyDigest) {
		t.Errorf("uppercase digest error = %v, want ErrInvalidEnrollmentKeyDigest", err)
	}
}

func mustPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	return newSigner(t).PublicKey()
}
