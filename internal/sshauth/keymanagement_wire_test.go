package sshauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
)

// --- key-management test infrastructure ---------------------------------------

// countingHandler wraps the httptest Coder double and counts every request
// so the wire tests can assert the key-management path makes ZERO Coder
// HTTP calls (no credential load, no verify, no renewal).
type countingHandler struct {
	inner http.Handler
	hits  atomic.Int64
}

func (h *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.hits.Add(1)
	h.inner.ServeHTTP(w, r)
}

func (h *countingHandler) requests() int64 { return h.hits.Load() }

// newKeysFixture builds the standard wire fixture against a counting Coder
// double.
func newKeysFixture(t *testing.T, inner http.Handler) (*fixture, *countingHandler) {
	t.Helper()
	counter := &countingHandler{inner: inner}
	f := newFixture(t, counter)
	return f, counter
}

// keysAuthConfig arms the key-management username on the fixture's auth
// config.
func (f *fixture) keysAuthConfig() sshauth.AuthConfig {
	cfg := f.authConfig()
	cfg.KeyManagementUser = "login-admin"
	cfg.KeyManagement = &sshauth.KeyManagementEnabled{Enabled: true}
	return cfg
}

// assertKeyManagementFinals validates a terminal key-management outcome:
// correct mode and identity IDs, generation 0 (no credential consulted),
// no forced reconnect.
func assertKeyManagementFinals(t *testing.T, f *fixture, perms sshauth.FinalPerms) {
	t.Helper()
	if perms.Mode != sshauth.ModeKeyManagement {
		t.Errorf("mode = %q, want %q", perms.Mode, sshauth.ModeKeyManagement)
	}
	if perms.AccountID != f.acct.ID {
		t.Errorf("account = %v, want %v", perms.AccountID, f.acct.ID)
	}
	if perms.DeploymentID != f.dep.ID {
		t.Errorf("deployment = %v, want %v", perms.DeploymentID, f.dep.ID)
	}
	if perms.SSHKeyID != f.keyRec.ID {
		t.Errorf("key = %v, want %v", perms.SSHKeyID, f.keyRec.ID)
	}
	if perms.CredentialGeneration != 0 {
		t.Errorf("generation = %d, want 0 (no credential consulted)", perms.CredentialGeneration)
	}
	if perms.MustReconnect {
		t.Error("must_reconnect must be false for key-management finals")
	}
}

// (a) keys username + enrolled key: terminal keymanagement finals with
// generation 0 — even with a VALID credential stored, the Coder double sees
// zero requests and one ssh_key_verified audit event records the session
// start.
func TestWireKeyManagementAuthSuccess(t *testing.T) {
	defer leakCheck(t)

	f, counter := newKeysFixture(t, coderOKHandler(wireCoderUserID))
	defer f.close(t)
	f.installCredential(t, "keys-valid-token-0123456789ab")

	ws := startWireServer(t, f.keysAuthConfig())
	defer ws.shutdown()

	probe := &clientProbe{}
	client, err := dialGateway(ws.addr(), "login-admin", probe, ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("key-management auth failed: %v", err)
	}
	defer client.Close()

	res := ws.lastResult()
	if res.err != nil {
		t.Fatalf("server handshake error: %v", res.err)
	}
	assertKeyManagementFinals(t, f, mustParseFinalPerms(t, res.perms))

	if got := counter.requests(); got != 0 {
		t.Errorf("Coder HTTP requests = %d, want 0 (credential must not be consulted)", got)
	}
	verified := f.auditEvents(sshauth.EventTypeKeyVerified)
	if len(verified) != 1 {
		t.Fatalf("verified audit events = %d, want 1", len(verified))
	}
	if verified[0].Result != sshauth.ResultSuccess ||
		verified[0].AccountID != f.acct.ID.String() ||
		verified[0].SSHKeyID != f.keyRec.ID.String() {
		t.Errorf("verified audit event = %+v", verified[0])
	}
	if got := f.auditEvents(sshauth.EventTypeAuthRejected); len(got) != 0 {
		t.Errorf("auth-rejected events = %d, want 0", len(got))
	}
	if strings.Contains(probe.bannerText(), "/cli-auth") {
		t.Errorf("no renewal banner expected on the key-management path: %q", probe.bannerText())
	}
}

// (b) A missing or cleared credential still reaches keymanagement finals:
// this path never consults the stored credential (the cleanup scenario — an
// expired token must not lock the owner out of managing keys). Zero Coder
// HTTP hits and no partial success: a public-key-only client finishes auth.
func TestWireKeyManagementCredentialMissing(t *testing.T) {
	defer leakCheck(t)

	run := func(t *testing.T, label string, clear bool) {
		f, counter := newKeysFixture(t, coderOKHandler(wireCoderUserID))
		defer f.close(t)
		if clear {
			snap := f.installCredential(t, "keys-doomed-token-0123456789")
			if err := f.store.ClearCredential(context.Background(), f.acct.ID, snap.Generation); err != nil {
				t.Fatalf("ClearCredential: %v", err)
			}
		}

		ws := startWireServer(t, f.keysAuthConfig())
		defer ws.shutdown()

		client, err := dialGateway(ws.addr(), "login-admin", &clientProbe{}, ssh.PublicKeys(f.signer))
		if err != nil {
			t.Fatalf("key-management auth with %s credential failed: %v", label, err)
		}
		defer client.Close()

		res := ws.lastResult()
		if res.err != nil {
			t.Fatalf("server handshake error: %v", res.err)
		}
		assertKeyManagementFinals(t, f, mustParseFinalPerms(t, res.perms))
		if got := counter.requests(); got != 0 {
			t.Errorf("Coder HTTP requests = %d, want 0 (credential %s)", got, label)
		}
		if got := f.auditEvents(sshauth.EventTypeKeyVerified); len(got) != 1 {
			t.Errorf("verified audit events = %d, want 1", len(got))
		}
	}

	t.Run("never set", func(t *testing.T) { run(t, "missing", false) })
	t.Run("cleared", func(t *testing.T) { run(t, "cleared", true) })
}

// (c) keys username + unenrolled key: rejection byte-identical to the
// unknown-username rejection — unenrolled keys never reach the UI and add
// no existence oracle.
func TestWireKeyManagementUnenrolledKeyUniformReject(t *testing.T) {
	defer leakCheck(t)

	f, counter := newKeysFixture(t, coderOKHandler(wireCoderUserID))
	defer f.close(t)
	authCfg := f.keysAuthConfig()

	rejectText := func(user string) string {
		ws := startWireServer(t, authCfg)
		defer ws.shutdown()
		signer := newSigner(t)
		client, err := dialGateway(ws.addr(), user, &clientProbe{}, allAuthMethods(signer)...)
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatalf("expected auth failure for user %q", user)
		}
		return err.Error()
	}

	unknownRef := rejectText("nosuchuser")
	if got := rejectText("login-admin"); got != unknownRef {
		t.Errorf("unenrolled key on keys username error differs from unknown username:\n  %q\n  %q", got, unknownRef)
	}
	if got := counter.requests(); got != 0 {
		t.Errorf("Coder HTTP requests = %d, want 0", got)
	}
	if got := f.auditEvents(sshauth.EventTypeKeyVerified); len(got) != 0 {
		t.Errorf("verified audit events = %d, want 0", len(got))
	}
}

// (d) keys feature disabled (nil config, then Enabled=false): the keys
// username rejects byte-identically to any unknown username (§35 — no
// oracle on whether key management exists).
func TestWireKeyManagementDisabledUniformReject(t *testing.T) {
	defer leakCheck(t)

	f, _ := newKeysFixture(t, coderOKHandler(wireCoderUserID))
	defer f.close(t)

	rejectText := func(cfg sshauth.AuthConfig, user string) string {
		ws := startWireServer(t, cfg)
		defer ws.shutdown()
		signer := newSigner(t)
		client, err := dialGateway(ws.addr(), user, &clientProbe{}, allAuthMethods(signer)...)
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatalf("expected auth failure for user %q", user)
		}
		return err.Error()
	}

	unknownRef := rejectText(f.keysAuthConfig(), "nosuchuser")

	nilCfg := f.keysAuthConfig()
	nilCfg.KeyManagement = nil
	if got := rejectText(nilCfg, "login-admin"); got != unknownRef {
		t.Errorf("nil key-management config: keys-username error differs from unknown username:\n  %q\n  %q", got, unknownRef)
	}

	disabled := f.keysAuthConfig()
	disabled.KeyManagement.Enabled = false
	if got := rejectText(disabled, "login-admin"); got != unknownRef {
		t.Errorf("disabled key management: keys-username error differs from unknown username:\n  %q\n  %q", got, unknownRef)
	}
}

// (e) A certificate offered on the keys username is rejected at the
// candidate stage — even though the underlying key is enrolled and a valid
// credential is stored.
func TestWireKeyManagementRejectsCertificate(t *testing.T) {
	defer leakCheck(t)

	f, counter := newKeysFixture(t, coderOKHandler(wireCoderUserID))
	defer f.close(t)
	f.installCredential(t, "keys-cert-token-0123456789ab")

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             f.signer.PublicKey(),
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "keys-cert",
		ValidPrincipals: []string{"login-admin"},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, f.signer)
	if err != nil {
		t.Fatalf("NewCertSigner: %v", err)
	}

	ws := startWireServer(t, f.keysAuthConfig())
	defer ws.shutdown()

	reject := func(user string) string {
		client, err := dialGateway(ws.addr(), user, &clientProbe{}, allAuthMethods(certSigner)...)
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatalf("expected auth failure for certificate on user %q", user)
		}
		return err.Error()
	}
	unknownRef := reject("nosuchuser")
	if got := reject("login-admin"); got != unknownRef {
		t.Errorf("certificate on keys username error differs from unknown username:\n  %q\n  %q", got, unknownRef)
	}

	for i, res := range ws.waitResults(2) {
		if res.err == nil || res.perms != nil {
			t.Errorf("result[%d]: server accepted certificate auth (err=%v perms=%v)", i, res.err, res.perms)
		}
	}
	if got := f.auditEvents(sshauth.EventTypeKeyVerified); len(got) != 0 {
		t.Errorf("verified audit events = %d, want 0", len(got))
	}
	rejected := f.auditEvents(sshauth.EventTypeAuthRejected)
	if len(rejected) == 0 {
		t.Fatal("no auth-rejected events for certificate offers")
	}
	for _, ev := range rejected {
		if ev.DetailCode != core.AUTH_UNKNOWN_KEY {
			t.Errorf("auth-rejected detail code = %q, want %q", ev.DetailCode, core.AUTH_UNKNOWN_KEY)
		}
	}
	if !f.logs.contains("certificate_not_allowed") {
		t.Errorf("missing certificate_not_allowed rejection log\nlogs:\n%s", f.logs.dump())
	}
	if got := counter.requests(); got != 0 {
		t.Errorf("Coder HTTP requests = %d, want 0", got)
	}
}

// --- direct-callback tests ----------------------------------------------------

// connMetaStub is a minimal ssh.ConnMetadata for driving BuildCallbacks
// closures directly (the wire cannot forge server-side candidate
// permissions, so the verified-stage tamper guards are exercised here).
type connMetaStub struct{ user string }

func (m connMetaStub) User() string          { return m.user }
func (m connMetaStub) SessionID() []byte     { return []byte("keymgmt-test-session") }
func (m connMetaStub) ClientVersion() []byte { return []byte("SSH-2.0-keymgmt-test") }
func (m connMetaStub) ServerVersion() []byte { return []byte("SSH-2.0-keymgmt-test") }
func (m connMetaStub) RemoteAddr() net.Addr  { return keymgmtAddrStub{} }
func (m connMetaStub) LocalAddr() net.Addr   { return keymgmtAddrStub{} }

type keymgmtAddrStub struct{}

func (keymgmtAddrStub) Network() string { return "tcp" }
func (keymgmtAddrStub) String() string  { return "127.0.0.1:51234" }

// (f) Verified-stage tamper guards: a keymanagement candidate whose IDs do
// not match the connection's stashed candidate identity, or one that fails
// to parse, rejects with ErrPublicKeyRejected; the untampered candidate
// reaches keymanagement finals. No Coder HTTP call on any path.
func TestKeyManagementCandidateTampering(t *testing.T) {
	defer leakCheck(t)

	f, counter := newKeysFixture(t, coderOKHandler(wireCoderUserID))
	defer f.close(t)

	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()
	state := sshauth.NewConnState(serverEnd)
	defer state.Close()

	publicKey, verifiedKey := sshauth.BuildCallbacks(f.keysAuthConfig(), state)
	meta := connMetaStub{user: "login-admin"}

	cand, err := publicKey(meta, f.signer.PublicKey())
	if err != nil {
		t.Fatalf("candidate stage: %v", err)
	}
	candPerms, err := sshauth.ParseCandidatePermissions(cand)
	if err != nil {
		t.Fatalf("ParseCandidatePermissions: %v", err)
	}
	if candPerms.Mode != sshauth.ModeKeyManagement ||
		candPerms.AccountID != f.acct.ID ||
		candPerms.SSHKeyID != f.keyRec.ID {
		t.Errorf("candidate perms = %+v", candPerms)
	}

	// Tampered account ID: candidateFor identity mismatch.
	tampered := sshauth.KeyManagementCandidatePermissions(uuid.New(), f.keyRec.ID)
	if perms, err := verifiedKey(meta, f.signer.PublicKey(), tampered, "ssh-ed25519"); err == nil || perms != nil {
		t.Errorf("tampered candidate accepted: perms=%v err=%v", perms, err)
	} else if !errors.Is(err, sshauth.ErrPublicKeyRejected) {
		t.Errorf("tampered candidate error = %v, want ErrPublicKeyRejected", err)
	}

	// Malformed candidate: parse failure.
	malformed := &ssh.Permissions{Extensions: map[string]string{
		sshauth.PermissionMode:      sshauth.ModeKeyManagement,
		sshauth.PermissionAccountID: "not-a-uuid",
	}}
	if perms, err := verifiedKey(meta, f.signer.PublicKey(), malformed, "ssh-ed25519"); err == nil || perms != nil {
		t.Errorf("malformed candidate accepted: perms=%v err=%v", perms, err)
	} else if !errors.Is(err, sshauth.ErrPublicKeyRejected) {
		t.Errorf("malformed candidate error = %v, want ErrPublicKeyRejected", err)
	}

	// Untampered candidate: terminal keymanagement finals.
	perms, err := verifiedKey(meta, f.signer.PublicKey(), cand, "ssh-ed25519")
	if err != nil {
		t.Fatalf("verified stage: %v", err)
	}
	assertKeyManagementFinals(t, f, mustParseFinalPerms(t, perms))

	if got := counter.requests(); got != 0 {
		t.Errorf("Coder HTTP requests = %d, want 0", got)
	}
	if got := f.auditEvents(sshauth.EventTypeKeyVerified); len(got) != 1 {
		t.Errorf("verified audit events = %d, want 1", len(got))
	}
	if got := f.auditEvents(sshauth.EventTypeAuthRejected); len(got) != 2 {
		t.Errorf("auth-rejected events = %d, want 2 (tampered + malformed)", len(got))
	}
}

// (g) AuthConfig fail-closed: enabled key management without a username, or
// an enrollment/keys username collision, invalidates the WHOLE config —
// every callback rejects (cfgErr path), including normal workspace auth.
// Distinct usernames keep both features usable on one connection endpoint.
func TestKeyManagementConfigValidation(t *testing.T) {
	defer leakCheck(t)

	f, counter := newKeysFixture(t, coderOKHandler(wireCoderUserID))
	defer f.close(t)
	f.installCredential(t, "keys-validate-token-0123456")

	// assertWorkspaceRejected: an ordinary workspace auth with the valid
	// enrolled key must fail while the config is invalid.
	assertWorkspaceRejected := func(t *testing.T, cfg sshauth.AuthConfig, label string) {
		t.Helper()
		ws := startWireServer(t, cfg)
		defer ws.shutdown()
		client, err := dialGateway(ws.addr(), "coder", &clientProbe{}, ssh.PublicKeys(f.signer))
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatalf("%s: expected fail-closed rejection of workspace auth", label)
		}
		if !f.logs.contains("config_invalid") {
			t.Errorf("%s: missing config_invalid rejection log\nlogs:\n%s", label, f.logs.dump())
		}
	}

	t.Run("enabled requires a username", func(t *testing.T) {
		cfg := f.keysAuthConfig()
		cfg.KeyManagementUser = ""
		assertWorkspaceRejected(t, cfg, "empty keys username")
	})

	t.Run("username collision with enrollment", func(t *testing.T) {
		cfg := f.enrollmentAuthConfig()
		cfg.KeyManagementUser = "login"
		cfg.KeyManagement = &sshauth.KeyManagementEnabled{Enabled: true}
		assertWorkspaceRejected(t, cfg, "colliding usernames")
	})

	t.Run("distinct usernames coexist", func(t *testing.T) {
		cfg := f.enrollmentAuthConfig()
		cfg.KeyManagementUser = "login-admin"
		cfg.KeyManagement = &sshauth.KeyManagementEnabled{Enabled: true}
		ws := startWireServer(t, cfg)
		defer ws.shutdown()
		client, err := dialGateway(ws.addr(), "login-admin", &clientProbe{}, ssh.PublicKeys(f.signer))
		if err != nil {
			t.Fatalf("key-management auth with enrollment armed failed: %v", err)
		}
		client.Close()
		res := ws.lastResult()
		if res.err != nil {
			t.Fatalf("server handshake error: %v", res.err)
		}
		assertKeyManagementFinals(t, f, mustParseFinalPerms(t, res.perms))
	})

	if got := counter.requests(); got != 0 {
		t.Errorf("Coder HTTP requests = %d, want 0", got)
	}
}
