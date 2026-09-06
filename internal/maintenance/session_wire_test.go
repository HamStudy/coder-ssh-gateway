package maintenance_test

// Full-server wire tests for the §14 maintenance session: a REAL
// internal/server listener with the REAL maintenance handler wired via
// ServerConfig.MaintenanceHandler, a REAL store + httptest Coder API, and a
// REAL x/crypto SSH client. The security assertion is that a typed token
// NEVER appears in the bytes the client receives (§14.3 no-echo).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/coderapi"
	"github.com/HamStudy/coder-ssh-gateway/internal/config"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/limits"
	"github.com/HamStudy/coder-ssh-gateway/internal/maintenance"
	"github.com/HamStudy/coder-ssh-gateway/internal/route"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
	"github.com/HamStudy/coder-ssh-gateway/internal/server"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
)

// leakCheck mirrors the server-package convention: coderapi's keep-alive
// persistConn goroutines are intentional; everything else must unwind.
// Register `defer leakCheck(t)` FIRST in every test.
func leakCheck(t *testing.T) {
	t.Helper()
	goleak.VerifyNone(t,
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
	)
}

const (
	// wireToken is a marker token the stub Coder accepts for the bound
	// user. It is deliberately distinctive so any echo into channel output
	// is caught by substring assertion.
	wireToken       = "T21-WIRE-MARKER-TOKEN-9f8e7d6c5b4a3c2d"
	dialTimeout     = 10 * time.Second
	conditionWindow = 10 * time.Second
)

var wireCoderUserID = uuid.MustParse("55555555-5555-5555-5555-555555555555")

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

// fakeRateLimiter mirrors the limits.RateLimits renewal semantics through
// the sshauth.RenewalRateLimiter narrow interface (limits.RateLimits has no
// exported constructor — T9/T20 learnings).
type fakeRateLimiter struct {
	mu     sync.Mutex
	tokens int
}

func (f *fakeRateLimiter) AllowRenewalAttempt(uuid.UUID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokens > 0 {
		f.tokens--
		return true
	}
	return false
}

func (f *fakeRateLimiter) GrantReconnectAllowance(uuid.UUID) {}

// coderStub answers /api/v2/users/me: tokens in known return the configured
// status (200 carries the bound Coder user UUID); anything else gets 401.
type coderStub struct {
	mu     sync.Mutex
	id     uuid.UUID
	status map[string]int
}

func (c *coderStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Coder-Session-Token"), "")
	c.mu.Lock()
	status, known := c.status[token]
	c.mu.Unlock()
	if !known {
		status = http.StatusUnauthorized
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":%q,"username":"taxilian","status":"active"}`, c.id.String())
}

// fakeStarter satisfies server.TunnelStarter; maintenance-mode tests never
// reach it, but server.New fails closed without one.
type fakeStarter struct{}

func (fakeStarter) Start(_ context.Context, ch ssh.Channel, _ core.Route, _ core.CredentialSnapshot) error {
	return ch.Close()
}

// wireFixture bundles the real auth + maintenance stack against a stub
// Coder. Defer close() BEFORE the deferred leakCheck (LIFO: teardown runs
// first).
type wireFixture struct {
	store   *store.Store
	dep     core.Deployment
	acct    core.Account
	signer  ssh.Signer
	stub    *coderStub
	coder   *httptest.Server
	rawVer  *coderapi.Verifier
	audit   *audit.InMemoryLogger
	rate    *fakeRateLimiter
	handler *maintenance.Handler
}

func newWireFixture(t *testing.T) *wireFixture {
	t.Helper()

	stub := &coderStub{id: wireCoderUserID, status: map[string]int{wireToken: http.StatusOK}}
	coderSrv := httptest.NewServer(stub)
	coderURL, err := url.Parse(coderSrv.URL)
	if err != nil {
		t.Fatalf("parse coder URL: %v", err)
	}

	f := &wireFixture{
		stub:  stub,
		coder: coderSrv,
		audit: audit.NewInMemoryLogger(),
		rate:  &fakeRateLimiter{tokens: 100},
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

	boundID := wireCoderUserID
	f.acct = core.Account{
		ID:             uuid.New(),
		DeploymentID:   f.dep.ID,
		Label:          "wire maintenance account",
		CoderUserID:    &boundID,
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
	f.signer, err = ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if _, err := s.AddKey(f.acct.ID, f.signer.PublicKey(), "wire key"); err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	s.SetKeyProvider(newMemKeyProvider(t))

	raw, err := coderapi.New(f.dep, coderapi.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("coderapi.New: %v", err)
	}
	f.rawVer = raw

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rc := &sshauth.RenewalConfig{
		Verifier:     raw,
		Store:        s,
		Rate:         f.rate,
		Audit:        f.audit,
		DeploymentID: f.dep.ID,
		CoderURL:     coderURL,
		Logger:       log,
	}
	f.handler = &maintenance.Handler{
		Store:    s,
		Renewal:  rc,
		Verifier: raw,
		CoderURL: f.dep.CoderURL.String(),
		Config: maintenance.Config{
			SessionTimeout: 30 * time.Second,
			InputTimeout:   10 * time.Second,
		},
	}
	return f
}

func (f *wireFixture) close(t *testing.T) {
	t.Helper()
	f.coder.Close()
	if err := f.store.Close(); err != nil {
		t.Errorf("store close: %v", err)
	}
}

// installCredential stores token as a valid credential; returns the
// resulting generation.
func (f *wireFixture) installCredential(t *testing.T, token string) int64 {
	t.Helper()
	snap, err := f.store.ReplaceCredential(context.Background(), core.ReplaceCredentialRequest{
		AccountID:          f.acct.ID,
		ExpectedGeneration: 0,
		Token:              []byte(token),
		Identity: core.CoderIdentity{
			ID:       wireCoderUserID,
			Username: "taxilian",
			Status:   "active",
		},
	})
	if err != nil {
		t.Fatalf("ReplaceCredential: %v", err)
	}
	return snap.Generation
}

func (f *wireFixture) credentialState(t *testing.T) (core.CredentialState, int64) {
	t.Helper()
	snap, err := f.store.LoadCredential(context.Background(), f.acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	secretbox.BestEffortWipe(snap.Token)
	return snap.State, snap.Generation
}

// startWireServer runs the REAL server with the maintenance handler wired.
// Defer shutdown() BEFORE leakCheck.
type wireServer struct {
	srv    *server.Server
	ln     net.Listener
	cancel context.CancelFunc
	errCh  chan error
}

func (f *wireFixture) startWireServer(t *testing.T) *wireServer {
	t.Helper()
	codec := route.NewCodec()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	cached := coderapi.NewCachedVerifier(f.dep.ID, f.rawVer, time.Minute)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := server.New(server.ServerConfig{
		HostSigners: []ssh.Signer{hostSigner},
		Auth: sshauth.AuthConfig{
			TransportUser:   "coder",
			MaintenanceUser: "auth",
			DeploymentID:    f.dep.ID,
			CoderURL:        f.dep.CoderURL,
			Store:           f.store,
			Verifier:        cached,
			Audit:           f.audit,
			Logger:          log,
		},
		Counters:           limits.New(config.Default()),
		RouteCodec:         codec,
		TunnelStarter:      fakeStarter{},
		MaintenanceHandler: f.handler,
		Logger:             log,
		Audit:              f.audit,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ws := &wireServer{srv: srv, ln: ln, cancel: cancel, errCh: make(chan error, 1)}
	go func() { ws.errCh <- srv.Serve(ctx, ln) }()
	return ws
}

func (ws *wireServer) addr() string { return ws.ln.Addr().String() }

func (ws *wireServer) shutdown(t *testing.T) {
	t.Helper()
	ws.cancel()
	select {
	case err := <-ws.errCh:
		if err != nil {
			t.Errorf("Serve returned error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return within 5s of cancel")
	}
}

func (f *wireFixture) dial(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "auth",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(f.signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         dialTimeout,
	})
	if err != nil {
		t.Fatalf("dial maintenance user: %v", err)
	}
	return client
}

// clientChan captures everything the server sends on one channel: all data
// bytes, and the exit-status request.
type clientChan struct {
	ch     ssh.Channel
	mu     sync.Mutex
	out    []byte
	status *uint32
	eof    chan struct{}
	// readDone closes when the data-read goroutine exits (channel EOF). It
	// is the happens-before edge that guarantees every received byte is in
	// cc.out before output() is read — without it the final append races
	// the test's read under CPU contention.
	readDone chan struct{}
}

func openClientChan(t *testing.T, client *ssh.Client) *clientChan {
	t.Helper()
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session channel: %v", err)
	}
	cc := &clientChan{ch: ch, eof: make(chan struct{}), readDone: make(chan struct{})}
	go func() {
		defer close(cc.eof)
		for req := range reqs {
			if req.Type == "exit-status" {
				var es struct{ Status uint32 }
				if err := ssh.Unmarshal(req.Payload, &es); err == nil {
					cc.mu.Lock()
					s := es.Status
					cc.status = &s
					cc.mu.Unlock()
				}
			}
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()
	go func() {
		defer close(cc.readDone)
		buf := make([]byte, 4096)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				cc.mu.Lock()
				cc.out = append(cc.out, buf[:n]...)
				cc.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return cc
}

func (cc *clientChan) output() string {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return string(cc.out)
}

func (cc *clientChan) waitOutput(t *testing.T, substr string) {
	t.Helper()
	deadline := time.Now().Add(conditionWindow)
	for !strings.Contains(cc.output(), substr) {
		if time.Now().After(deadline) {
			t.Fatalf("output never contained %q; got:\n%s", substr, cc.output())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitClosed waits for the server to finish the channel AND close the outer
// transport (§14.3/§27: a finished maintenance session ends the connection).
func (cc *clientChan) waitClosed(t *testing.T, client *ssh.Client) {
	t.Helper()
	select {
	case <-cc.eof:
	case <-time.After(conditionWindow):
		t.Fatal("channel request loop did not end (transport not closed)")
	}
	// Drain the read goroutine too: the server writes the rejection text
	// BEFORE exit-status/close, so by readDone every byte is captured.
	select {
	case <-cc.readDone:
	case <-time.After(conditionWindow):
		t.Fatal("channel read loop did not end (no EOF after transport close)")
	}
	done := make(chan error, 1)
	go func() { done <- client.Conn.Wait() }()
	select {
	case <-done:
	case <-time.After(conditionWindow):
		t.Fatal("outer transport not closed after maintenance session end")
	}
}

func (cc *clientChan) exitStatus(t *testing.T) uint32 {
	t.Helper()
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.status == nil {
		t.Fatal("no exit-status received; output:\n" + string(cc.out))
	}
	return *cc.status
}

// requestPty sends a well-formed pty-req (x/crypto marshaling).
func (cc *clientChan) requestPty(t *testing.T) {
	t.Helper()
	pty := struct {
		Term     string
		W, H     uint32
		Wpx, Hpx uint32
		Modes    string
	}{Term: "xterm", W: 80, H: 24}
	ok, err := cc.ch.SendRequest("pty-req", true, ssh.Marshal(&pty))
	if err != nil || !ok {
		t.Fatalf("pty-req: ok=%v err=%v", ok, err)
	}
}

func (cc *clientChan) requestShell(t *testing.T) {
	t.Helper()
	ok, err := cc.ch.SendRequest("shell", true, nil)
	if err != nil || !ok {
		t.Fatalf("shell request: ok=%v err=%v", ok, err)
	}
}

// runExec sends one exec request and collects output + exit-status + the
// §27 transport close.
func runExec(t *testing.T, client *ssh.Client, payload string) (string, uint32) {
	t.Helper()
	cc := openClientChan(t, client)
	ok, err := cc.ch.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{payload}))
	if err != nil || !ok {
		t.Fatalf("exec request: ok=%v err=%v", ok, err)
	}
	cc.waitClosed(t, client)
	return cc.output(), cc.exitStatus(t)
}

// (a) Interactive renew over a real connection: PTY + shell, banner with
// /cli-auth URL + account info, hidden token entry, success, exit 0,
// server-side transport close, store generation +1, and — the security
// assertion — the typed token NEVER appears in the captured output.
func TestWireInteractiveRenew(t *testing.T) {
	defer leakCheck(t)
	f := newWireFixture(t)
	defer f.close(t)
	ws := f.startWireServer(t)
	defer ws.shutdown(t)

	beforeState, beforeGen := f.credentialState(t)
	if beforeState != core.CredentialStateMissing {
		t.Fatalf("precondition state = %s, want missing", beforeState)
	}

	client := f.dial(t, ws.addr())
	defer client.Close()

	cc := openClientChan(t, client)
	cc.requestPty(t)
	cc.requestShell(t)

	cc.waitOutput(t, "Paste Coder token: ")
	out := cc.output()
	for _, want := range []string{
		"Coder SSH Gateway credential maintenance",
		"Gateway account: wire maintenance account",
		"Coder server:    " + f.dep.CoderURL.String(),
		"taxilian",
		f.dep.CoderURL.String() + "/cli-auth",
		"Credential:      missing",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("banner missing %q; banner:\n%s", want, out)
		}
	}
	if strings.Contains(out, f.acct.ID.String()) {
		t.Error("banner leaks the internal account UUID")
	}

	if _, err := cc.ch.Write([]byte(wireToken + "\r")); err != nil {
		t.Fatalf("type token: %v", err)
	}

	cc.waitClosed(t, client)
	out = cc.output()

	if got := cc.exitStatus(t); got != 0 {
		t.Fatalf("exit-status = %d, want 0; output:\n%s", got, out)
	}
	for _, want := range []string{"Token verified for Coder user taxilian.", "Reconnect to the workspace connection."} {
		if !strings.Contains(out, want) {
			t.Errorf("missing confirmation %q; output:\n%s", want, out)
		}
	}
	if strings.Contains(out, wireToken) {
		t.Fatal("SECURITY: typed token bytes were echoed into channel output")
	}

	afterState, afterGen := f.credentialState(t)
	if afterState != core.CredentialStateValid {
		t.Errorf("post-renew state = %s, want valid", afterState)
	}
	if afterGen != beforeGen+1 {
		t.Errorf("generation = %d, want %d", afterGen, beforeGen+1)
	}
}

// (b) §14.1: maintenance auth and the repair interface work with NO stored
// credential at all.
func TestWireMaintenanceCredentialMissing(t *testing.T) {
	defer leakCheck(t)
	f := newWireFixture(t)
	defer f.close(t)
	ws := f.startWireServer(t)
	defer ws.shutdown(t)

	// No credential installed; the dial itself proves §14.1 (no token
	// validity required for maintenance auth).
	client := f.dial(t, ws.addr())
	defer client.Close()

	out, status := runExec(t, client, "status")
	if status != 0 {
		t.Fatalf("status exit = %d, want 0; output:\n%s", status, out)
	}
	if !strings.Contains(out, "Credential state:  missing") {
		t.Errorf("status output missing 'missing' state; output:\n%s", out)
	}
}

// (c) exec status: nonsecret fields only — deployment URL, abbreviated
// bound UUID, state — never the token nor the ciphertext.
func TestWireExecStatusNonsecret(t *testing.T) {
	defer leakCheck(t)
	f := newWireFixture(t)
	defer f.close(t)
	ws := f.startWireServer(t)
	defer ws.shutdown(t)

	f.installCredential(t, wireToken)

	client := f.dial(t, ws.addr())
	defer client.Close()

	out, status := runExec(t, client, "status")
	if status != 0 {
		t.Fatalf("status exit = %d, want 0; output:\n%s", status, out)
	}
	for _, want := range []string{
		"Coder server:      " + f.dep.CoderURL.String(),
		wireCoderUserID.String()[:8], // abbreviated bound UUID
		"Credential state:  valid",
		"Control plane:     reachable",
		"Generation:        1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status missing %q; output:\n%s", want, out)
		}
	}
	// Abbreviated, never full: the full UUID must not appear.
	if strings.Contains(out, wireCoderUserID.String()) {
		t.Error("status prints the full bound UUID; §14.4 requires abbreviated")
	}
	if strings.Contains(out, f.acct.ID.String()) {
		t.Error("status prints the internal account UUID")
	}
	if strings.Contains(out, wireToken) {
		t.Fatal("SECURITY: status output contains the stored token")
	}
	rec, err := f.store.LoadCredentialRecord(f.acct.ID)
	if err != nil {
		t.Fatalf("LoadCredentialRecord: %v", err)
	}
	if rec.Ciphertext == nil {
		t.Fatal("expected stored ciphertext for a valid credential")
	}
	if strings.Contains(out, base64.StdEncoding.EncodeToString(rec.Ciphertext)) {
		t.Fatal("SECURITY: status output contains credential ciphertext")
	}
	if strings.Contains(out, base64.StdEncoding.EncodeToString(rec.Nonce)) {
		t.Fatal("SECURITY: status output contains the credential nonce")
	}
}

// (d) exec clear: tombstone (state=missing, generation+1) and an honest
// message that Coder-side revocation is a separate step (§14.5).
func TestWireExecClear(t *testing.T) {
	defer leakCheck(t)
	f := newWireFixture(t)
	defer f.close(t)
	ws := f.startWireServer(t)
	defer ws.shutdown(t)

	gen := f.installCredential(t, wireToken)

	client := f.dial(t, ws.addr())
	defer client.Close()

	out, status := runExec(t, client, "clear")
	if status != 0 {
		t.Fatalf("clear exit = %d, want 0; output:\n%s", status, out)
	}
	if !strings.Contains(out, "revoke") || !strings.Contains(out, "Coder") {
		t.Errorf("clear message must mention separate Coder-side revocation; output:\n%s", out)
	}
	state, newGen := f.credentialState(t)
	if state != core.CredentialStateMissing {
		t.Errorf("post-clear state = %s, want missing (tombstone)", state)
	}
	if newGen != gen+1 {
		t.Errorf("post-clear generation = %d, want %d", newGen, gen+1)
	}
}

// (e) exec help lists exactly the four commands.
func TestWireExecHelp(t *testing.T) {
	defer leakCheck(t)
	f := newWireFixture(t)
	defer f.close(t)
	ws := f.startWireServer(t)
	defer ws.shutdown(t)

	client := f.dial(t, ws.addr())
	defer client.Close()

	out, status := runExec(t, client, "help")
	if status != 0 {
		t.Fatalf("help exit = %d, want 0; output:\n%s", status, out)
	}
	for _, cmd := range []string{"status", "renew", "clear", "help"} {
		if !strings.Contains(out, cmd) {
			t.Errorf("help output missing command %q; output:\n%s", cmd, out)
		}
	}
}

// (f) §14.2/§36: arbitrary payloads are "unknown command" — nothing is ever
// executed. Assert the child-process count of this test process is stable.
func TestWireExecRejectNoExecution(t *testing.T) {
	defer leakCheck(t)
	f := newWireFixture(t)
	defer f.close(t)
	ws := f.startWireServer(t)
	defer ws.shutdown(t)

	childrenBefore := childProcessCount(t)

	for _, payload := range []string{"rm -rf /", "status; id"} {
		client := f.dial(t, ws.addr())
		out, status := runExec(t, client, payload)
		client.Close()
		if status != 1 {
			t.Errorf("exec %q: exit = %d, want 1; output:\n%s", payload, status, out)
		}
		if !strings.Contains(out, "unknown command") {
			t.Errorf("exec %q: expected 'unknown command' rejection; output:\n%s", payload, out)
		}
	}

	if got := childProcessCount(t); got != childrenBefore {
		t.Errorf("child processes before=%d after=%d — a subprocess was spawned (§14.2 violation)", childrenBefore, got)
	}
}

// childProcessCount counts direct children of this test process via pgrep.
// A zero-count failure (pgrep exits 1 when empty) is still a valid 0.
func childProcessCount(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("pgrep", "-P", fmt.Sprint(os.Getpid())).Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return 0
		}
		t.Fatalf("pgrep: %v", err)
	}
	fields := strings.Fields(string(out))
	return len(fields)
}

// (g) §8.3: a second session channel on the same maintenance connection is
// rejected Prohibited; direct-tcpip in maintenance mode is rejected.
func TestWireSecondChannelAndDirectTCPIPRejected(t *testing.T) {
	defer leakCheck(t)
	f := newWireFixture(t)
	defer f.close(t)
	ws := f.startWireServer(t)
	defer ws.shutdown(t)

	client := f.dial(t, ws.addr())
	defer client.Close()

	// First session wins and stays parked at the hidden prompt.
	first := openClientChan(t, client)
	first.requestShell(t)
	first.waitOutput(t, "Paste Coder token: ")

	if _, _, err := client.OpenChannel("session", nil); err == nil {
		t.Error("second session channel accepted; §8.3 requires rejection")
	}
	if _, err := client.Dial("tcp", "ws1:22"); err == nil {
		t.Error("direct-tcpip accepted in maintenance mode; §8.3 requires rejection")
	}

	// End the parked session cleanly via Ctrl-C so teardown is prompt.
	if _, err := first.ch.Write([]byte{0x03}); err != nil {
		t.Fatalf("ctrl-c: %v", err)
	}
	first.waitClosed(t, client)
}

// (h) Ctrl-C at the hidden prompt cancels: "Cancelled." + nonzero exit.
func TestWireCtrlCCancels(t *testing.T) {
	defer leakCheck(t)
	f := newWireFixture(t)
	defer f.close(t)
	ws := f.startWireServer(t)
	defer ws.shutdown(t)

	client := f.dial(t, ws.addr())
	defer client.Close()

	cc := openClientChan(t, client)
	cc.requestPty(t)
	cc.requestShell(t)
	cc.waitOutput(t, "Paste Coder token: ")

	if _, err := cc.ch.Write([]byte{0x03}); err != nil {
		t.Fatalf("ctrl-c: %v", err)
	}
	cc.waitClosed(t, client)
	out := cc.output()
	if !strings.Contains(out, "Cancelled.") {
		t.Errorf("missing cancellation message; output:\n%s", out)
	}
	if got := cc.exitStatus(t); got == 0 {
		t.Errorf("exit-status = 0 after Ctrl-C, want nonzero")
	}
}

// (i) Oversized exec payload (8KB) is rejected cleanly: unknown command,
// exit 1, no panic, connection still well-formed.
func TestWireExecOversizedPayload(t *testing.T) {
	defer leakCheck(t)
	f := newWireFixture(t)
	defer f.close(t)
	ws := f.startWireServer(t)
	defer ws.shutdown(t)

	client := f.dial(t, ws.addr())
	defer client.Close()

	out, status := runExec(t, client, strings.Repeat("A", 8192))
	if status != 1 {
		t.Errorf("oversized exec exit = %d, want 1; output:\n%s", status, out)
	}
	if !strings.Contains(out, "unknown command") {
		t.Errorf("oversized exec: expected 'unknown command'; output:\n%s", out)
	}
}
