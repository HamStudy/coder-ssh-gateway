package coderapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/taxilian/coder-ssh-gateway/internal/coderapi"
	"github.com/taxilian/coder-ssh-gateway/internal/core"
)

const cacheTestToken = "test-session-token"

func buildVerifier(t *testing.T, srv *httptest.Server) (*coderapi.Verifier, func()) {
	t.Helper()
	dep := core.Deployment{
		ID:       uuid.New(),
		CoderURL: mustParseURL(srv.URL),
	}
	v, err := coderapi.New(dep, coderapi.Options{})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v, func() { srv.Close() }
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

type usersMeReply struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Status   string `json:"status"`
}

func TestTTLExpiry(t *testing.T) {
	var hitCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		id := uuid.New()
		json.NewEncoder(w).Encode(usersMeReply{
			ID:       id.String(),
			Username: "testuser",
			Status:   "active",
		})
	}))
	defer srv.Close()

	v, srvCleanup := buildVerifier(t, srv)
	defer srvCleanup()

	cv := coderapi.NewCachedVerifier(uuid.New(), v, 50*time.Millisecond)
	accountID := uuid.New()
	token := []byte(cacheTestToken)

	ident, err := cv.VerifyCached(context.Background(), accountID, 1, token)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if ident.ID == uuid.Nil {
		t.Fatal("expected non-nil identity")
	}
	if got := atomic.LoadInt32(&hitCount); got != 1 {
		t.Fatalf("first call hitCount = %d, want 1", got)
	}

	time.Sleep(60 * time.Millisecond)

	ident, err = cv.VerifyCached(context.Background(), accountID, 1, token)
	if err != nil {
		t.Fatalf("second call after expiry: %v", err)
	}
	if ident.ID == uuid.Nil {
		t.Fatal("expected non-nil identity after expiry")
	}
	if got := atomic.LoadInt32(&hitCount); got != 2 {
		t.Fatalf("after expiry hitCount = %d, want 2", got)
	}
}

func TestSingleflightCoalesce(t *testing.T) {
	var hitCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		time.Sleep(50 * time.Millisecond)
		id := uuid.New()
		json.NewEncoder(w).Encode(usersMeReply{
			ID:       id.String(),
			Username: "testuser",
			Status:   "active",
		})
	}))
	defer srv.Close()

	v, srvCleanup := buildVerifier(t, srv)
	defer srvCleanup()

	cv := coderapi.NewCachedVerifier(uuid.New(), v, 10*time.Second)
	accountID := uuid.New()
	token := []byte(cacheTestToken)

	const n = 50
	var wg sync.WaitGroup
	results := make(chan core.CoderIdentity, n)
	errs := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ident, err := cv.VerifyCached(context.Background(), accountID, 1, token)
			if err != nil {
				errs <- err
				return
			}
			results <- ident
		}()
	}

	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent call error: %v", err)
	}

	first := <-results
	for ident := range results {
		if ident.ID != first.ID {
			t.Fatalf("got different identities: %v vs %v", ident.ID, first.ID)
		}
	}

	if got := atomic.LoadInt32(&hitCount); got != 1 {
		t.Fatalf("hitCount = %d, want 1 (singleflight should coalesce %d calls)", got, n)
	}
}

func TestUnavailableNotCached(t *testing.T) {
	var hitCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	v, srvCleanup := buildVerifier(t, srv)
	defer srvCleanup()

	cv := coderapi.NewCachedVerifier(uuid.New(), v, 10*time.Second)
	accountID := uuid.New()
	token := []byte(cacheTestToken)

	_, err := cv.VerifyCached(context.Background(), accountID, 1, token)
	if err == nil {
		t.Fatal("expected error for 503")
	}
	ce := &core.CredentialError{}
	if !errors.As(err, &ce) {
		t.Fatalf("expected CredentialError, got %T", err)
	}
	if ce.Kind != core.ControlPlaneUnavailable {
		t.Fatalf("kind = %v, want ControlPlaneUnavailable", ce.Kind)
	}

	if got := atomic.LoadInt32(&hitCount); got != 1 {
		t.Fatalf("first call hitCount = %d, want 1", got)
	}

	_, err = cv.VerifyCached(context.Background(), accountID, 1, token)
	if err == nil {
		t.Fatal("expected error for second 503")
	}

	if got := atomic.LoadInt32(&hitCount); got != 2 {
		t.Fatalf("second call hitCount = %d, want 2 (unavailable must not be cached)", got)
	}
}

func TestInvalidCredentialCached(t *testing.T) {
	var hitCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	v, srvCleanup := buildVerifier(t, srv)
	defer srvCleanup()

	cv := coderapi.NewCachedVerifier(uuid.New(), v, 50*time.Millisecond)
	accountID := uuid.New()
	token := []byte(cacheTestToken)

	_, err := cv.VerifyCached(context.Background(), accountID, 1, token)
	if err == nil {
		t.Fatal("expected error for 401")
	}
	ce := &core.CredentialError{}
	if !errors.As(err, &ce) {
		t.Fatalf("expected CredentialError, got %T", err)
	}
	if ce.Kind != core.CredentialInvalid {
		t.Fatalf("kind = %v, want CredentialInvalid", ce.Kind)
	}

	if got := atomic.LoadInt32(&hitCount); got != 1 {
		t.Fatalf("first call hitCount = %d, want 1", got)
	}

	_, err = cv.VerifyCached(context.Background(), accountID, 1, token)
	if err == nil {
		t.Fatal("expected error for second 401")
	}

	if got := atomic.LoadInt32(&hitCount); got != 1 {
		t.Fatalf("second call hitCount = %d, want 1 (401 should be cached short ttl)", got)
	}

	time.Sleep(60 * time.Millisecond)

	_, err = cv.VerifyCached(context.Background(), accountID, 1, token)
	if err == nil {
		t.Fatal("expected error after cache expiry")
	}

	if got := atomic.LoadInt32(&hitCount); got != 2 {
		t.Fatalf("after expiry hitCount = %d, want 2", got)
	}
}

func TestGenerationBumpNewKey(t *testing.T) {
	var hitCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		id := uuid.New()
		json.NewEncoder(w).Encode(usersMeReply{
			ID:       id.String(),
			Username: "testuser",
			Status:   "active",
		})
	}))
	defer srv.Close()

	v, srvCleanup := buildVerifier(t, srv)
	defer srvCleanup()

	cv := coderapi.NewCachedVerifier(uuid.New(), v, 10*time.Second)
	accountID := uuid.New()
	token := []byte(cacheTestToken)

	_, err := cv.VerifyCached(context.Background(), accountID, 1, token)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if got := atomic.LoadInt32(&hitCount); got != 1 {
		t.Fatalf("first call hitCount = %d, want 1", got)
	}

	_, err = cv.VerifyCached(context.Background(), accountID, 2, token)
	if err != nil {
		t.Fatalf("call with generation 2: %v", err)
	}
	if got := atomic.LoadInt32(&hitCount); got != 2 {
		t.Fatalf("generation bump hitCount = %d, want 2 (new key = new HTTP call)", got)
	}
}

func TestTokenNeverInCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New()
		json.NewEncoder(w).Encode(usersMeReply{
			ID:       id.String(),
			Username: "testuser",
			Status:   "active",
		})
	}))
	defer srv.Close()

	v, srvCleanup := buildVerifier(t, srv)
	defer srvCleanup()

	cv := coderapi.NewCachedVerifier(uuid.New(), v, 10*time.Second)
	accountID := uuid.New()
	token := []byte("super-secret-token-12345")

	_, err := cv.VerifyCached(context.Background(), accountID, 1, token)
	if err != nil {
		t.Fatalf("call: %v", err)
	}

	n := cv.CacheStats()
	if n == 0 {
		t.Fatal("expected at least 1 cache entry")
	}

	if n > 2 {
		t.Fatalf("cache has %d entries, want <= 2 (one per call)", n)
	}
}

func TestInvalidate(t *testing.T) {
	var hitCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		id := uuid.New()
		json.NewEncoder(w).Encode(usersMeReply{
			ID:       id.String(),
			Username: "testuser",
			Status:   "active",
		})
	}))
	defer srv.Close()

	v, srvCleanup := buildVerifier(t, srv)
	defer srvCleanup()

	cv := coderapi.NewCachedVerifier(uuid.New(), v, 10*time.Second)
	accountID := uuid.New()
	token := []byte(cacheTestToken)

	_, err := cv.VerifyCached(context.Background(), accountID, 1, token)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if got := atomic.LoadInt32(&hitCount); got != 1 {
		t.Fatalf("first call hitCount = %d, want 1", got)
	}

	cv.Invalidate(accountID, 1)

	_, err = cv.VerifyCached(context.Background(), accountID, 1, token)
	if err != nil {
		t.Fatalf("call after Invalidate: %v", err)
	}
	if got := atomic.LoadInt32(&hitCount); got != 2 {
		t.Fatalf("after Invalidate hitCount = %d, want 2", got)
	}
}

func TestMalformedReplyNotCached(t *testing.T) {
	var hitCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	v, srvCleanup := buildVerifier(t, srv)
	defer srvCleanup()

	cv := coderapi.NewCachedVerifier(uuid.New(), v, 10*time.Second)
	accountID := uuid.New()
	token := []byte(cacheTestToken)

	_, err := cv.VerifyCached(context.Background(), accountID, 1, token)
	if err == nil {
		t.Fatal("expected error for malformed reply")
	}
	ce := &core.CredentialError{}
	if !errors.As(err, &ce) {
		t.Fatalf("expected CredentialError, got %T", err)
	}
	if ce.Kind != core.CredentialMalformedReply {
		t.Fatalf("kind = %v, want CredentialMalformedReply", ce.Kind)
	}

	if got := atomic.LoadInt32(&hitCount); got != 1 {
		t.Fatalf("first call hitCount = %d, want 1", got)
	}

	_, err = cv.VerifyCached(context.Background(), accountID, 1, token)
	if err == nil {
		t.Fatal("expected error for second malformed reply")
	}

	if got := atomic.LoadInt32(&hitCount); got != 2 {
		t.Fatalf("second call hitCount = %d, want 2 (malformed not cached)", got)
	}
}

func TestControlPlaneIncompatibleNotCached(t *testing.T) {
	var hitCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	v, srvCleanup := buildVerifier(t, srv)
	defer srvCleanup()

	cv := coderapi.NewCachedVerifier(uuid.New(), v, 10*time.Second)
	accountID := uuid.New()
	token := []byte(cacheTestToken)

	_, err := cv.VerifyCached(context.Background(), accountID, 1, token)
	if err == nil {
		t.Fatal("expected error for 404")
	}
	ce := &core.CredentialError{}
	if !errors.As(err, &ce) {
		t.Fatalf("expected CredentialError, got %T", err)
	}
	if ce.Kind != core.ControlPlaneIncompatible {
		t.Fatalf("kind = %v, want ControlPlaneIncompatible", ce.Kind)
	}

	if got := atomic.LoadInt32(&hitCount); got != 1 {
		t.Fatalf("first call hitCount = %d, want 1", got)
	}

	_, err = cv.VerifyCached(context.Background(), accountID, 1, token)
	if err == nil {
		t.Fatal("expected error for second 404")
	}

	if got := atomic.LoadInt32(&hitCount); got != 2 {
		t.Fatalf("second call hitCount = %d, want 2 (ControlPlaneIncompatible not cached)", got)
	}
}

func TestCacheStampedeRace(t *testing.T) {
	var hitCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		time.Sleep(10 * time.Millisecond)
		id := uuid.New()
		json.NewEncoder(w).Encode(usersMeReply{
			ID:       id.String(),
			Username: "testuser",
			Status:   "active",
		})
	}))
	defer srv.Close()

	v, srvCleanup := buildVerifier(t, srv)
	defer srvCleanup()

	cv := coderapi.NewCachedVerifier(uuid.New(), v, 10*time.Second)

	const n = 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			accountID := uuid.New()
			token := []byte(cacheTestToken)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cv.VerifyCached(ctx, accountID, int64(i%10), token)
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&hitCount); got != n {
		t.Fatalf("hitCount = %d, want %d (each account should get its own call)", got, n)
	}
}
