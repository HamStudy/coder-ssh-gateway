package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

	"github.com/taxilian/coder-ssh-gateway/internal/audit"
	"github.com/taxilian/coder-ssh-gateway/internal/coderapi"
	"github.com/taxilian/coder-ssh-gateway/internal/config"
	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/limits"
	"github.com/taxilian/coder-ssh-gateway/internal/secretbox"
	"github.com/taxilian/coder-ssh-gateway/internal/server"
	"github.com/taxilian/coder-ssh-gateway/internal/sshauth"
	"github.com/taxilian/coder-ssh-gateway/internal/store"
)

// leakCheck mirrors T14's convention: goleak runs only after all explicit
// defers (client close, server shutdown, fixture close) have completed.
// Register `defer leakCheck(t)` FIRST in every test.
func leakCheck(t *testing.T) {
	t.Helper()
	goleak.VerifyNone(t,
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
	)
}

type logCapture struct {
	mu      sync.Mutex
	records []string
}

func (h *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (h *logCapture) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var sb strings.Builder
	sb.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&sb, " %s=%v", a.Key, a.Value)
		return true
	})
	h.records = append(h.records, sb.String())
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

var testCoderUserID = uuid.MustParse("44444444-4444-4444-4444-444444444444")

// gwFixture wires the real auth stack (store + httptest Coder + cached
// verifier + audit) that the server under test consumes. No fakes on the
// auth path (task requirement).
type gwFixture struct {
	store    *store.Store
	dep      core.Deployment
	acct     core.Account
	keyRec   core.SSHKeyRecord
	signer   ssh.Signer
	audit    *audit.InMemoryLogger
	logs     *logCapture
	coder    *httptest.Server
	verifier *coderapi.CachedVerifier
}

func (f *gwFixture) close(t *testing.T) {
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

func newFixture(t *testing.T, handler http.Handler) *gwFixture {
	t.Helper()

	coderSrv := httptest.NewServer(handler)
	coderURL, err := url.Parse(coderSrv.URL)
	if err != nil {
		t.Fatalf("parse coder URL: %v", err)
	}

	f := &gwFixture{
		coder: coderSrv,
		audit: audit.NewInMemoryLogger(),
		logs:  &logCapture{},
	}

	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	f.store = s

	f.dep = core.Deployment{
		ID:           uuid.New(),
		CoderURL:     coderURL,
		TargetSuffix: "coder-gateway.example.com",
		CoderBinary:  "/usr/local/bin/coder",
		WaitMode:     "auto",
	}
	if err := s.EnsureDeployment(f.dep); err != nil {
		t.Fatalf("EnsureDeployment: %v", err)
	}

	coderUserID := testCoderUserID
	f.acct = core.Account{
		ID:             uuid.New(),
		DeploymentID:   f.dep.ID,
		Label:          "server test account",
		CoderUserID:    &coderUserID,
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

	f.keyRec, err = s.AddKey(f.acct.ID, f.signer.PublicKey(), "server test key")
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	s.SetKeyProvider(newMemKeyProvider(t))

	v, err := coderapi.New(f.dep, coderapi.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("coderapi.New: %v", err)
	}
	f.verifier = coderapi.NewCachedVerifier(f.dep.ID, v, time.Minute)

	return f
}

func (f *gwFixture) installCredential(t *testing.T, token string) {
	t.Helper()
	_, err := f.store.ReplaceCredential(context.Background(), core.ReplaceCredentialRequest{
		AccountID:          f.acct.ID,
		ExpectedGeneration: 0,
		Token:              []byte(token),
		Identity: core.CoderIdentity{
			ID:       testCoderUserID,
			Username: "taxilian",
			Status:   "active",
		},
	})
	if err != nil {
		t.Fatalf("ReplaceCredential: %v", err)
	}
}

func (f *gwFixture) auditEvents(eventType string) []audit.Event {
	var out []audit.Event
	for _, ev := range f.audit.Events() {
		if ev.EventType == eventType {
			out = append(out, ev)
		}
	}
	return out
}

func (f *gwFixture) authConfig() sshauth.AuthConfig {
	return sshauth.AuthConfig{
		TransportUser:   "coder",
		MaintenanceUser: "auth",
		DeploymentID:    f.dep.ID,
		CoderURL:        f.dep.CoderURL,
		Store:           f.store,
		Verifier:        f.verifier,
		Audit:           f.audit,
		Logger:          slog.New(f.logs),
	}
}

func hostSigner(t *testing.T) ssh.Signer {
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

// testServer wraps a running Server. Callers must defer shutdown() AFTER
// `defer leakCheck(t)` so teardown happens before goroutine verification.
type testServer struct {
	srv    *server.Server
	ln     net.Listener
	cancel context.CancelFunc
	errCh  chan error
}

func startTestServer(t *testing.T, f *gwFixture, mutate func(*server.ServerConfig, *config.Config)) *testServer {
	t.Helper()

	limitsCfg := config.Default()
	sc := server.ServerConfig{
		HostSigners: []ssh.Signer{hostSigner(t)},
		Auth:        f.authConfig(),
		Audit:       f.audit,
		Logger:      slog.New(f.logs),
	}
	if mutate != nil {
		mutate(&sc, limitsCfg)
	}
	sc.Counters = limits.New(limitsCfg)

	srv, err := server.New(sc)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ts := &testServer{srv: srv, ln: ln, cancel: cancel, errCh: make(chan error, 1)}
	go func() {
		ts.errCh <- srv.Serve(ctx, ln)
	}()
	return ts
}

func (ts *testServer) addr() string { return ts.ln.Addr().String() }

func (ts *testServer) shutdown(t *testing.T) {
	t.Helper()
	ts.cancel()
	select {
	case err := <-ts.errCh:
		if err != nil {
			t.Errorf("Serve returned error on graceful shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return within 5s of context cancel")
	}
}

func dialGateway(addr, user string, auth ...ssh.AuthMethod) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
}

func dialRaw(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func newClientSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	return signer
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
