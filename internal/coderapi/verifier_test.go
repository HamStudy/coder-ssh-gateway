package coderapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/coderapi"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

const testToken = "test-session-token"

func deploymentFor(t *testing.T, rawURL string) core.Deployment {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	return core.Deployment{ID: uuid.New(), CoderURL: u}
}

func requireCredentialErr(t *testing.T, err error) *core.CredentialError {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ce *core.CredentialError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *core.CredentialError, got %T: %v", err, err)
	}
	return ce
}

func requireKind(t *testing.T, err error, kind core.CredentialErrorKind) *core.CredentialError {
	t.Helper()
	ce := requireCredentialErr(t, err)
	if ce.Kind != kind {
		t.Fatalf("kind = %q, want %q (detail=%q http=%d)", ce.Kind, kind, ce.DetailCode, ce.HTTPStatus)
	}
	return ce
}

func assertNoSecretsInError(t *testing.T, err error) {
	t.Helper()
	s := err.Error()
	if len(s) > 512 {
		t.Fatalf("error text suspiciously long (%d bytes): %.64q...", len(s), s)
	}
	if got := fmt.Sprintf("%v", err); got != s {
		t.Fatalf("inconsistent error rendering")
	}
	for _, bad := range []string{testToken, "secret-body", "{", "}"} {
		if contains(s, bad) {
			t.Fatalf("error text %q leaks %q", s, bad)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && (len(haystack) >= len(needle)) && indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// --- Verifier tests (§38.1 HTTP verifier bullets) ---

func TestVerifySuccessExpectedUUID(t *testing.T) {
	wantID := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/users/me" {
			t.Errorf("path = %q, want /api/v2/users/me", r.URL.Path)
		}
		if got := r.Header.Get("Coder-Session-Token"); got != testToken {
			t.Errorf("token header = %q, want %q", got, testToken)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("accept = %q, want application/json", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"username":"taxilian","status":"active"}`, wantID.String())
	}))
	defer srv.Close()

	v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := v.Verify(context.Background(), []byte(testToken))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.ID != wantID {
		t.Fatalf("id = %s, want %s", id.ID, wantID)
	}
	if id.Username != "taxilian" || id.Status != "active" {
		t.Fatalf("identity = %+v", id)
	}
}

func TestVerifyMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id": not-json`)
	}))
	defer srv.Close()

	v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = v.Verify(context.Background(), []byte(testToken))
	ce := requireKind(t, err, core.CredentialMalformedReply)
	if ce.HTTPStatus != 200 {
		t.Fatalf("http status = %d, want 200", ce.HTTPStatus)
	}
	if ce.Retryable {
		t.Fatal("malformed reply must not be retryable")
	}
	assertNoSecretsInError(t, err)
}

func TestVerifyZeroID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id":%q,"username":"x","status":"active"}`, uuid.Nil.String())
	}))
	defer srv.Close()

	v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = v.Verify(context.Background(), []byte(testToken))
	requireKind(t, err, core.CredentialMalformedReply)
	assertNoSecretsInError(t, err)
}

func TestVerifyInvalidID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"not-a-uuid","username":"x","status":"active"}`)
	}))
	defer srv.Close()

	v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = v.Verify(context.Background(), []byte(testToken))
	requireKind(t, err, core.CredentialMalformedReply)
	assertNoSecretsInError(t, err)
}

func TestVerifyOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		// Valid JSON prefix then enough filler to exceed 1 MiB.
		fmt.Fprint(w, `{"id":"`)
		for i := 0; i < (1<<20)/64+1; i++ {
			fmt.Fprint(w, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		}
		fmt.Fprint(w, `","username":"x","status":"active"}`)
	}))
	defer srv.Close()

	v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = v.Verify(context.Background(), []byte(testToken))
	requireKind(t, err, core.CredentialMalformedReply)
	assertNoSecretsInError(t, err)
}

func TestVerifyStatusClassification(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		kind      core.CredentialErrorKind
		retryable bool
		detail    string
	}{
		{"401", 401, core.CredentialInvalid, false, core.AUTH_CREDENTIAL_UNAUTHORIZED},
		{"403", 403, core.CredentialForbidden, false, core.AUTH_CREDENTIAL_FORBIDDEN},
		{"404", 404, core.ControlPlaneIncompatible, false, core.AUTH_CODER_INCOMPATIBLE},
		{"429", 429, core.ControlPlaneUnavailable, true, core.AUTH_CODER_UNAVAILABLE},
		{"500", 500, core.ControlPlaneUnavailable, true, core.AUTH_CODER_UNAVAILABLE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, "secret-body that must never leak into errors")
			}))
			defer srv.Close()

			v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_, err = v.Verify(context.Background(), []byte(testToken))
			ce := requireKind(t, err, tc.kind)
			if ce.HTTPStatus != tc.status {
				t.Fatalf("http status = %d, want %d", ce.HTTPStatus, tc.status)
			}
			if ce.Retryable != tc.retryable {
				t.Fatalf("retryable = %v, want %v", ce.Retryable, tc.retryable)
			}
			if ce.DetailCode != tc.detail {
				t.Fatalf("detail = %q, want %q", ce.DetailCode, tc.detail)
			}
			assertNoSecretsInError(t, err)
		})
	}
}

func TestVerifyTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()

	v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	start := time.Now()
	_, err = v.Verify(context.Background(), []byte(testToken))
	ce := requireKind(t, err, core.ControlPlaneUnavailable)
	if !ce.Retryable {
		t.Fatal("timeout must be retryable")
	}
	if ce.DetailCode != core.AUTH_CODER_UNAVAILABLE {
		t.Fatalf("detail = %q, want %q", ce.DetailCode, core.AUTH_CODER_UNAVAILABLE)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("timeout took %v, client timeout not enforced", elapsed)
	}
	assertNoSecretsInError(t, err)
}

func TestVerifyRedirectBlockedAndTokenNeverSent(t *testing.T) {
	var redirectSawToken atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Coder-Session-Token") != "" {
			redirectSawToken.Store(true)
		}
		fmt.Fprint(w, `{"id":"`+uuid.NewString()+`","username":"x","status":"active"}`)
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/v2/users/me", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = v.Verify(context.Background(), []byte(testToken))
	ce := requireKind(t, err, core.ControlPlaneIncompatible)
	if ce.Retryable {
		t.Fatal("redirect must fail closed, not retryable")
	}
	if ce.DetailCode == core.AUTH_CODER_INCOMPATIBLE {
		t.Fatalf("redirect must use a distinct DetailCode variant, got plain %q", ce.DetailCode)
	}
	if redirectSawToken.Load() {
		t.Fatal("token was sent to redirect target — FAIL CLOSED VIOLATION")
	}
	assertNoSecretsInError(t, err)
}

func TestVerifyExtraStaticHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Static-Test"); got != "present" {
			t.Errorf("static header = %q, want present", got)
		}
		fmt.Fprintf(w, `{"id":%q,"username":"x","status":"active"}`, uuid.NewString())
	}))
	defer srv.Close()

	v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{
		Headers: http.Header{"X-Static-Test": {"present"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(context.Background(), []byte(testToken)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyUserAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if len(ua) < len("coder-ssh-gateway/") || ua[:len("coder-ssh-gateway/")] != "coder-ssh-gateway/" {
			t.Errorf("User-Agent = %q, want coder-ssh-gateway/<version>", ua)
		}
		fmt.Fprintf(w, `{"id":%q,"username":"x","status":"active"}`, uuid.NewString())
	}))
	defer srv.Close()

	v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(context.Background(), []byte(testToken)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = v.Verify(ctx, []byte(testToken))
	requireKind(t, err, core.ControlPlaneUnavailable)
	assertNoSecretsInError(t, err)
}

func TestVerifyConnectionRefused(t *testing.T) {
	// Bind then close to get an address that refuses connections.
	l := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := l.URL
	l.Close()

	v, err := coderapi.New(deploymentFor(t, addr), coderapi.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = v.Verify(context.Background(), []byte(testToken))
	ce := requireKind(t, err, core.ControlPlaneUnavailable)
	if !ce.Retryable {
		t.Fatal("connect failure must be retryable")
	}
	assertNoSecretsInError(t, err)
}

func TestVerifyTransportReuse(t *testing.T) {
	var connCount atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id":%q,"username":"x","status":"active"}`, uuid.NewString())
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			connCount.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := v.Verify(context.Background(), []byte(testToken)); err != nil {
			t.Fatalf("Verify %d: %v", i, err)
		}
	}
	if n := connCount.Load(); n != 1 {
		t.Fatalf("connections = %d, want 1 (transport keep-alive reuse)", n)
	}
}

func TestVerifyCustomCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id":%q,"username":"x","status":"active"}`, uuid.NewString())
	}))
	defer srv.Close()

	t.Run("with pool succeeds", func(t *testing.T) {
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{RootCAs: pool})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := v.Verify(context.Background(), []byte(testToken)); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	t.Run("without pool fails as unavailable", func(t *testing.T) {
		v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, err = v.Verify(context.Background(), []byte(testToken))
		requireKind(t, err, core.ControlPlaneUnavailable)
		assertNoSecretsInError(t, err)
	})
}

func selfSignedCertPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gateway-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestVerifyMutualTLS(t *testing.T) {
	// Server requires a client certificate signed by its own CA.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id":%q,"username":"x","status":"active"}`, uuid.NewString())
	}))
	caPool := x509.NewCertPool()
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	caPool.AddCert(srv.Certificate())
	defer srv.Close()

	clientCertPEM, clientKeyPEM := selfSignedCertPEM(t)

	t.Run("with client cert succeeds", func(t *testing.T) {
		v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{
			RootCAs:           caPool,
			ClientCertificate: []byte(clientCertPEM),
			ClientKey:         []byte(clientKeyPEM),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := v.Verify(context.Background(), []byte(testToken)); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	t.Run("without client cert fails as unavailable", func(t *testing.T) {
		v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{RootCAs: caPool})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, err = v.Verify(context.Background(), []byte(testToken))
		requireKind(t, err, core.ControlPlaneUnavailable)
	})
}

func TestNewRejectsBadClientCert(t *testing.T) {
	_, err := coderapi.New(deploymentFor(t, "https://example.invalid"), coderapi.Options{
		ClientCertificate: []byte("not a cert"),
		ClientKey:         []byte("not a key"),
	})
	if err == nil {
		t.Fatal("expected error for unparseable client certificate")
	}
}

func TestListOwnedWorkspaces(t *testing.T) {
	owner := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Coder-Session-Token")
		if r.URL.Query().Get("limit") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"workspaces":[`+
			`{"name":"general","owner_id":%q},`+
			`{"name":"other","owner_id":"33333333-3333-3333-3333-333333333333"},`+
			`{"name":"second","owner_id":%q}],`+
			`"count":2}`, owner.String(), owner.String())
	}))
	defer srv.Close()

	v, err := coderapi.New(deploymentFor(t, srv.URL), coderapi.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	names, owned, err := v.ListOwnedWorkspaces(context.Background(), []byte(testToken), owner, 10)
	if err != nil {
		t.Fatalf("ListOwnedWorkspaces: %v", err)
	}
	if seenAuth != testToken {
		t.Errorf("token header = %q, want the session token", seenAuth)
	}
	if owned != 2 || len(names) != 2 || names[0] != "general" || names[1] != "second" {
		t.Errorf("names = %v (owned %d), want [general second] (owned 2)", names, owned)
	}

	t.Run("caps at limit", func(t *testing.T) {
		names, owned, err := v.ListOwnedWorkspaces(context.Background(), []byte(testToken), owner, 1)
		if err != nil {
			t.Fatalf("ListOwnedWorkspaces: %v", err)
		}
		if len(names) != 1 || owned != 2 {
			t.Errorf("names = %v (owned %d), want 1 capped name (owned 2)", names, owned)
		}
	})

	t.Run("server error is returned for caller to skip", func(t *testing.T) {
		broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer broken.Close()
		vb, err := coderapi.New(deploymentFor(t, broken.URL), coderapi.Options{})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, _, err := vb.ListOwnedWorkspaces(context.Background(), []byte(testToken), owner, 10); err == nil {
			t.Fatal("expected error from 500 reply")
		}
	})
}
