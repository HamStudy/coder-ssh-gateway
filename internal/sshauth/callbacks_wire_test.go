package sshauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/coderapi"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
)

// leakCheck runs goleak after all explicit defers have torn down the
// fixture. HTTP keep-alive goroutines are ignored: connection reuse is an
// intentional coderapi feature (T8), not an sshauth leak.
func leakCheck(t *testing.T) {
	t.Helper()
	goleak.VerifyNone(t,
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
	)
}

// --- test infrastructure ----------------------------------------------------

type logCapture struct {
	mu      sync.Mutex
	records []string
}

func (h *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (h *logCapture) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Message)
	return nil
}
func (h *logCapture) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *logCapture) WithGroup(string) slog.Handler      { return h }

func (h *logCapture) contains(sub string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

type memKeyProvider struct {
	keyID string
	key   []byte
}

func newMemKeyProvider(t *testing.T) *memKeyProvider {
	t.Helper()
	k := make([]byte, secretbox.KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	return &memKeyProvider{keyID: "v1", key: k}
}

func (m *memKeyProvider) ActiveKey(context.Context) (string, []byte, error) {
	return m.keyID, append([]byte(nil), m.key...), nil
}

func (m *memKeyProvider) Key(_ context.Context, keyID string) ([]byte, error) {
	if keyID != m.keyID {
		return nil, fmt.Errorf("key %q: %w", keyID, secretbox.ErrKeyNotFound)
	}
	return append([]byte(nil), m.key...), nil
}

// wireCoderUserID is the fixed Coder user UUID every fixture binds to.
var wireCoderUserID = uuid.MustParse("33333333-3333-3333-3333-333333333333")

// fixture bundles a real store (temp dir), a real CachedVerifier against an
// httptest Coder API, and a real audit logger (task requirement: no fakes on
// the auth path). Callers must defer close() BEFORE the deferred leakCheck
// so teardown completes before goroutine verification.
type fixture struct {
	store       *store.Store
	dep         core.Deployment
	acct        core.Account
	keyRec      core.SSHKeyRecord
	signer      ssh.Signer
	coderUserID uuid.UUID
	audit       *audit.InMemoryLogger
	logs        *logCapture
	coder       *httptest.Server
	verifier    *coderapi.CachedVerifier
	rawVerifier *coderapi.Verifier
	rate        *fakeRateLimiter
}

func (f *fixture) close(t *testing.T) {
	t.Helper()
	f.coder.Close()
	if err := f.store.Close(); err != nil {
		t.Errorf("store close: %v", err)
	}
}

func coderOKHandler(id uuid.UUID) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"username":"taxilian","status":"active"}`, id.String())
	})
}

func statusHandler(code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	})
}

func newFixture(t *testing.T, handler http.Handler) *fixture {
	t.Helper()

	coderSrv := httptest.NewServer(handler)
	coderURL, err := url.Parse(coderSrv.URL)
	if err != nil {
		t.Fatalf("parse coder URL: %v", err)
	}

	f := &fixture{
		coder:       coderSrv,
		coderUserID: wireCoderUserID,
		audit:       audit.NewInMemoryLogger(),
		logs:        &logCapture{},
	}

	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	f.store = s

	f.dep = core.Deployment{
		ID:          uuid.New(),
		CoderURL:    coderURL,
		CoderBinary: "/usr/local/bin/coder",
		WaitMode:    "auto",
	}
	if err := s.EnsureDeployment(f.dep); err != nil {
		t.Fatalf("EnsureDeployment: %v", err)
	}

	f.acct = core.Account{
		ID:             uuid.New(),
		DeploymentID:   f.dep.ID,
		Label:          "wire test account",
		CoderUserID:    &f.coderUserID,
		CachedUsername: "taxilian",
		Enabled:        true,
	}
	if err := s.AddAccount(f.acct); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	f.signer = signer

	keyRec, err := s.AddKey(f.acct.ID, signer.PublicKey(), "wire key")
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	f.keyRec = keyRec

	s.SetKeyProvider(newMemKeyProvider(t))

	v, err := coderapi.New(f.dep, coderapi.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("coderapi.New: %v", err)
	}
	f.verifier = coderapi.NewCachedVerifier(f.dep.ID, v, time.Minute)
	f.rawVerifier = v
	f.rate = newFakeRateLimiter(100)

	return f
}

// installCredential stores a validated token bound to the fixture Coder user.
func (f *fixture) installCredential(t *testing.T, token string) core.CredentialSnapshot {
	t.Helper()
	snap, err := f.store.ReplaceCredential(context.Background(), core.ReplaceCredentialRequest{
		AccountID:          f.acct.ID,
		ExpectedGeneration: 0,
		Token:              []byte(token),
		Identity: core.CoderIdentity{
			ID:       f.coderUserID,
			Username: "taxilian",
			Status:   "active",
		},
	})
	if err != nil {
		t.Fatalf("ReplaceCredential: %v", err)
	}
	return snap
}

func (f *fixture) authConfig() sshauth.AuthConfig {
	return sshauth.AuthConfig{
		TransportUser: "coder",
		DeploymentID:  f.dep.ID,
		CoderURL:      f.dep.CoderURL,
		Store:         f.store,
		Verifier:      f.verifier,
		Audit:         f.audit,
		Logger:        slog.New(f.logs),
		Renewal:       f.renewalConfig(),
	}
}

// renewalConfig builds the real §13 continuation config against the
// fixture's uncached verifier and fake rate limiter.
func (f *fixture) renewalConfig() *sshauth.RenewalConfig {
	return &sshauth.RenewalConfig{
		Verifier: f.rawVerifier,
		Store:    f.store,
		Rate:     f.rate,
		Audit:    f.audit,
		Logger:   slog.New(f.logs),
	}
}

func (f *fixture) auditEvents(eventType string) []audit.Event {
	var out []audit.Event
	for _, ev := range f.audit.Events() {
		if ev.EventType == eventType {
			out = append(out, ev)
		}
	}
	return out
}

// --- wire harness -----------------------------------------------------------

type wireResult struct {
	perms *ssh.Permissions
	err   error
}

type wireServer struct {
	t          *testing.T
	ln         net.Listener
	hostSigner ssh.Signer
	cfg        sshauth.AuthConfig

	mu      sync.Mutex
	results []wireResult
	read    int
	states  []*sshauth.ConnState
	conns   []*ssh.ServerConn
	wg      sync.WaitGroup
}

func hostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	return signer
}

// startWireServer starts a real SSH server with the package-under-test
// callbacks. Callers must defer shutdown() BEFORE the deferred leakCheck.
func startWireServer(t *testing.T, cfg sshauth.AuthConfig) *wireServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ws := &wireServer{t: t, ln: ln, hostSigner: hostKey(t), cfg: cfg}
	ws.wg.Add(1)
	go ws.acceptLoop()
	return ws
}

func (ws *wireServer) addr() string { return ws.ln.Addr().String() }

func (ws *wireServer) acceptLoop() {
	defer ws.wg.Done()
	for {
		raw, err := ws.ln.Accept()
		if err != nil {
			return
		}
		ws.wg.Add(1)
		go ws.serve(raw)
	}
}

func (ws *wireServer) serve(raw net.Conn) {
	defer ws.wg.Done()
	state := sshauth.NewConnState(raw)
	ws.mu.Lock()
	ws.states = append(ws.states, state)
	ws.mu.Unlock()

	scfg := &ssh.ServerConfig{}
	scfg.AddHostKey(ws.hostSigner)
	pkCb, vCb := sshauth.BuildCallbacks(ws.cfg, state)
	scfg.PublicKeyCallback = pkCb
	scfg.VerifiedPublicKeyCallback = vCb
	scfg.PreAuthConnCallback = state.SetPreAuthConn

	sc, chans, reqs, err := ssh.NewServerConn(raw, scfg)
	var perms *ssh.Permissions
	if sc != nil {
		perms = sc.Permissions
	}
	ws.mu.Lock()
	ws.results = append(ws.results, wireResult{perms: perms, err: err})
	ws.mu.Unlock()
	if err != nil {
		_ = raw.Close()
		return
	}
	// §13.6: after a credential renewal the outer connection closes
	// immediately, without starting a channel dispatcher.
	if perms != nil && perms.Extensions[sshauth.PermissionMustReconnect] == "true" {
		_ = sc.Close()
		return
	}
	ws.mu.Lock()
	ws.conns = append(ws.conns, sc)
	ws.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(ssh.Prohibited, "T14 wire harness: channels not in scope")
		}
	}()
}

func (ws *wireServer) shutdown() {
	_ = ws.ln.Close()
	ws.mu.Lock()
	for _, c := range ws.conns {
		_ = c.Close()
	}
	ws.mu.Unlock()
	ws.wg.Wait()
}

// lastResult blocks until the server completes the next unread handshake.
func (ws *wireServer) lastResult() wireResult {
	deadline := time.Now().Add(5 * time.Second)
	for {
		ws.mu.Lock()
		if ws.read < len(ws.results) {
			result := ws.results[ws.read]
			ws.read++
			ws.mu.Unlock()
			return result
		}
		ws.mu.Unlock()
		if time.Now().After(deadline) {
			ws.t.Fatal("timed out waiting for next server handshake result")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitResults blocks until the server has completed at least n handshakes.
func (ws *wireServer) waitResults(n int) []wireResult {
	deadline := time.Now().Add(5 * time.Second)
	for {
		ws.mu.Lock()
		if len(ws.results) >= n {
			out := append([]wireResult(nil), ws.results...)
			ws.mu.Unlock()
			return out
		}
		ws.mu.Unlock()
		if time.Now().After(deadline) {
			ws.t.Fatalf("timed out waiting for %d server handshake result(s)", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// stateAt returns the ConnState of the i-th accepted connection.
func (ws *wireServer) stateAt(i int) *sshauth.ConnState {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if i >= len(ws.states) {
		ws.t.Fatalf("only %d connection states recorded", len(ws.states))
	}
	return ws.states[i]
}

// clientProbe captures client-visible banner text.
type clientProbe struct {
	mu      sync.Mutex
	banners []string
}

func (p *clientProbe) banner(msg string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.banners = append(p.banners, msg)
	return nil
}

func (p *clientProbe) bannerText() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.banners, "\n")
}

func dialGateway(addr, user string, probe *clientProbe, auth ...ssh.AuthMethod) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback:  probe.banner,
		Timeout:         10 * time.Second,
	})
}

// allAuthMethods mirrors a real client willing to continue after partial
// success (§13.4).
func allAuthMethods(signer ssh.Signer) []ssh.AuthMethod {
	return []ssh.AuthMethod{
		ssh.PublicKeys(signer),
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			return nil, errors.New("test client: no answers")
		}),
		ssh.Password("placeholder-token"),
	}
}

// --- wire tests --------------------------------------------------------------

// (1)+(8) Registered key, valid credential, transport user: auth succeeds with
// final transport permissions; the candidate query emits only a debug log,
// never a verified audit event per probe.
func TestWireTransportAuthSuccess(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(wireCoderUserID))
	defer f.close(t)
	snap := f.installCredential(t, "wire-token-transport-0123456789")

	ws := startWireServer(t, f.authConfig())
	defer ws.shutdown()
	probe := &clientProbe{}
	client, err := dialGateway(ws.addr(), "coder", probe, ssh.PublicKeys(f.signer))
	if err != nil {
		t.Fatalf("transport auth failed: %v", err)
	}
	defer client.Close()

	res := ws.lastResult()
	if res.err != nil {
		t.Fatalf("server handshake error: %v", res.err)
	}
	perms, err := sshauth.ParseFinalPermissions(res.perms)
	if err != nil {
		t.Fatalf("ParseFinalPermissions: %v", err)
	}
	if perms.Mode != sshauth.ModeTransport {
		t.Errorf("mode = %q", perms.Mode)
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
	if perms.CredentialGeneration != snap.Generation {
		t.Errorf("generation = %d, want %d", perms.CredentialGeneration, snap.Generation)
	}
	if perms.MustReconnect {
		t.Error("must_reconnect must be false on the normal path (§13.1)")
	}

	// (8) Exactly one verified-key audit event despite the client's
	// unsigned candidate probe(s); candidate stage logs at debug only.
	verified := f.auditEvents(sshauth.EventTypeKeyVerified)
	if len(verified) != 1 {
		t.Fatalf("verified audit events = %d, want 1", len(verified))
	}
	if verified[0].Result != sshauth.ResultSuccess {
		t.Errorf("verified result = %q", verified[0].Result)
	}
	if verified[0].AccountID != f.acct.ID.String() {
		t.Errorf("verified account = %q", verified[0].AccountID)
	}
	if !f.logs.contains("candidate accepted") {
		t.Error("missing debug candidate-seen log")
	}
	if strings.Contains(probe.bannerText(), "cli-auth") {
		t.Error("no renewal banner expected on success path")
	}
}

// (3)+(4)+(5)+(9) All rejections produce a byte-identical outward client
// error — no existence oracle (§35).
func TestWireRejectUniformity(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, coderOKHandler(uuid.New()))
	defer f.close(t)
	authCfg := f.authConfig()

	// (5) Build an SSH certificate over the registered key.
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
		KeyId:           "wire-cert",
		ValidPrincipals: []string{"coder"},
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

	unknownSigner, err := func() (ssh.Signer, error) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return ssh.NewSignerFromKey(priv)
	}()
	if err != nil {
		t.Fatalf("unknown signer: %v", err)
	}

	cases := map[string]struct {
		user   string
		signer ssh.Signer
	}{
		"unknown key":            {"coder", unknownSigner},
		"unknown key wrong user": {"root", unknownSigner},
		"certificate offered":    {"coder", certSigner},
	}

	msgs := make(map[string]string, len(cases))
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ws := startWireServer(t, authCfg)
			defer ws.shutdown()
			client, err := dialGateway(ws.addr(), tc.user, &clientProbe{}, allAuthMethods(tc.signer)...)
			if client != nil {
				client.Close()
			}
			if err == nil {
				t.Fatal("expected auth failure")
			}
			res := ws.lastResult()
			if res.err == nil {
				t.Fatal("server accepted a rejected identity")
			}
			if res.perms != nil {
				t.Error("rejected auth must not yield permissions")
			}
			if got := f.auditEvents(sshauth.EventTypeKeyVerified); len(got) != 0 {
				t.Errorf("verified events = %d, want 0 (no proof of possession)", len(got))
			}
			msgs[name] = err.Error()
			t.Logf("outward client error: %q", msgs[name])
		})
	}

	// (9) Disabled account: same outward message.
	t.Run("disabled account", func(t *testing.T) {
		if err := f.store.SetAccountEnabled(f.acct.ID, false); err != nil {
			t.Fatalf("SetAccountEnabled: %v", err)
		}
		defer func() {
			if err := f.store.SetAccountEnabled(f.acct.ID, true); err != nil {
				t.Fatalf("re-enable: %v", err)
			}
		}()
		ws := startWireServer(t, authCfg)
		defer ws.shutdown()
		client, err := dialGateway(ws.addr(), "coder", &clientProbe{}, allAuthMethods(f.signer)...)
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatal("expected auth failure for disabled account")
		}
		msgs["disabled account"] = err.Error()
		t.Logf("outward client error: %q", msgs["disabled account"])
	})

	ref := msgs["unknown key"]
	for name, m := range msgs {
		if m != ref {
			t.Errorf("client error for %q differs from unknown-key error:\n  %q\n  %q", name, m, ref)
		}
	}
	t.Logf("all %d rejection paths produced byte-identical outward errors", len(msgs))
}

// (6) Expired credential (Coder 401) yields partial success, a renewal banner
// with the /cli-auth URL, and the real §13 continuation methods. This client
// cannot supply a valid token (its keyboard-interactive callback aborts and
// its password is a bogus token that Coder rejects with 401), so the overall
// authentication still fails.
func TestWireExpiredCredentialPartialSuccess(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, statusHandler(http.StatusUnauthorized))
	defer f.close(t)
	f.installCredential(t, "wire-token-expired-0123456789ab")

	cfg := f.authConfig()
	cfg.RenewalAuthTimeout = 5 * time.Minute
	ws := startWireServer(t, cfg)
	defer ws.shutdown()
	probe := &clientProbe{}

	client, err := dialGateway(ws.addr(), "coder", probe, allAuthMethods(f.signer)...)
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("expected overall auth failure (client supplied no valid token)")
	}
	msg := err.Error()
	// Partial success must have offered the continuation methods; the
	// client attempted them and the real renewal flow rejected the bogus
	// candidates.
	if !strings.Contains(msg, "keyboard-interactive") {
		t.Errorf("client error does not show keyboard-interactive continuation: %q", msg)
	}
	if !strings.Contains(msg, "password") {
		t.Errorf("client error does not show password continuation: %q", msg)
	}

	banners := probe.bannerText()
	if !strings.Contains(banners, "/cli-auth") {
		t.Errorf("renewal banner missing /cli-auth URL (§13.3): %q", banners)
	}
	if strings.Contains(banners, "wire-token") {
		t.Errorf("banner leaks token material: %q", banners)
	}

	res := ws.lastResult()
	if res.perms != nil {
		t.Error("§9.5: partial success must carry NIL permissions")
	}
	if got := f.auditEvents(sshauth.EventTypeKeyVerified); len(got) != 1 {
		t.Errorf("verified events = %d, want 1 (key possession proven before renewal)", len(got))
	}
}

// (7) Coder 503 at the verified stage is a straight rejection — no partial
// success, no /cli-auth banner, outward error identical to unknown key.
func TestWireCoderUnavailableStraightReject(t *testing.T) {
	defer leakCheck(t)

	f := newFixture(t, statusHandler(http.StatusServiceUnavailable))
	defer f.close(t)
	f.installCredential(t, "wire-token-unavailable-0123456789")

	ws := startWireServer(t, f.authConfig())
	defer ws.shutdown()
	probe := &clientProbe{}
	client, err := dialGateway(ws.addr(), "coder", probe, allAuthMethods(f.signer)...)
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("expected auth failure")
	}
	msg := err.Error()
	if strings.Contains(msg, "keyboard-interactive") || strings.Contains(msg, "password") {
		t.Errorf("non-renewable failure must not offer continuations (§11.4): %q", msg)
	}
	banners := probe.bannerText()
	if strings.Contains(banners, "/cli-auth") {
		t.Errorf("cli-auth URL only allowed for renewable kinds (§35): %q", banners)
	}
	if !strings.Contains(banners, "temporarily unavailable") {
		t.Errorf("expected §35-matrix unavailability banner, got %q", banners)
	}
	res := ws.lastResult()
	if res.perms != nil {
		t.Error("rejected auth must not yield permissions")
	}
	// Key possession was proven, then the credential stage rejected.
	if got := f.auditEvents(sshauth.EventTypeKeyVerified); len(got) != 1 {
		t.Errorf("verified events = %d, want 1", len(got))
	}
	if got := f.auditEvents(sshauth.EventTypeAuthRejected); len(got) != 1 {
		t.Errorf("auth-rejected events = %d, want 1", len(got))
	} else if got[0].DetailCode != core.AUTH_CODER_UNAVAILABLE {
		t.Errorf("detail code = %q, want %q", got[0].DetailCode, core.AUTH_CODER_UNAVAILABLE)
	}
}
