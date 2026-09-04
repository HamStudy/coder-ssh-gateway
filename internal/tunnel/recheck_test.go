package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/secretbox"
	"github.com/taxilian/coder-ssh-gateway/internal/store"
	"github.com/taxilian/coder-ssh-gateway/internal/testleaks"
)

type recheckTestHarness struct {
	t           *testing.T
	store       *store.Store
	srv         *httptest.Server
	verifier    *recheckVerifier
	rechecker   *Rechecker
	keyProvider *recheckKP
	dep         core.Deployment
}

type recheckVerifier struct {
	verifyFn func(ctx context.Context, token []byte) (core.CoderIdentity, error)
}

func (v *recheckVerifier) Verify(ctx context.Context, token []byte) (core.CoderIdentity, error) {
	return v.verifyFn(ctx, token)
}

type recheckKP struct {
	key []byte
}

func (kp *recheckKP) ActiveKey(ctx context.Context) (string, []byte, error) {
	return "v1", kp.key, nil
}

func (kp *recheckKP) Key(ctx context.Context, keyID string) ([]byte, error) {
	return kp.key, nil
}

func newRecheckHarness(t *testing.T) *recheckTestHarness {
	t.Helper()
	h := &recheckTestHarness{t: t}

	var err error
	h.store, err = store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	h.keyProvider = &recheckKP{key: make([]byte, secretbox.KeySize)}
	for i := range h.keyProvider.key {
		h.keyProvider.key[i] = byte(i)
	}
	h.store.SetKeyProvider(h.keyProvider)

	h.dep = core.Deployment{
		ID:       uuid.New(),
		CoderURL: func() *url.URL { u, _ := url.Parse("https://coder.example.com"); return u }(),
	}
	if err := h.store.EnsureDeployment(h.dep); err != nil {
		t.Fatalf("EnsureDeployment: %v", err)
	}

	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := uuid.New()
		w.Write([]byte(`{"id":"` + id.String() + `","username":"testuser","status":"active"}`))
	}))
	defer h.srv.Close()

	h.verifier = &recheckVerifier{verifyFn: func(ctx context.Context, token []byte) (core.CoderIdentity, error) {
		u := h.dep.CoderURL.JoinPath("/api/v2/users/me").String()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return core.CoderIdentity{}, err
		}
		req.Header.Set("Coder-Session-Token", string(token))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return core.CoderIdentity{}, &core.CredentialError{
				Kind: core.ControlPlaneUnavailable, HTTPStatus: 0,
				Retryable: true, DetailCode: core.AUTH_CODER_UNAVAILABLE,
			}
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			return core.CoderIdentity{}, &core.CredentialError{
				Kind: core.CredentialInvalid, HTTPStatus: http.StatusUnauthorized,
				Retryable: true, DetailCode: core.AUTH_CREDENTIAL_UNAUTHORIZED,
			}
		}
		if resp.StatusCode != http.StatusOK {
			return core.CoderIdentity{}, &core.CredentialError{
				Kind: core.ControlPlaneUnavailable, HTTPStatus: resp.StatusCode,
				Retryable: true, DetailCode: core.AUTH_CODER_UNAVAILABLE,
			}
		}
		return core.CoderIdentity{ID: uuid.New(), Username: "testuser"}, nil
	}}

	h.rechecker = &Rechecker{
		Verifier: h.verifier,
		Store:    h.store,
		Log:      slog.New(slog.DiscardHandler),
	}

	return h
}

func (h *recheckTestHarness) addAccount(t *testing.T) core.Account {
	t.Helper()
	acct := core.Account{
		ID:               uuid.New(),
		DeploymentID:     h.dep.ID,
		Label:            "test-account",
		BindOnFirstToken: true,
		Enabled:          true,
	}
	if err := h.store.AddAccount(acct); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	return acct
}

func TestRecheckerStaleGenNoOp(t *testing.T) {
	defer testleaks.Verify(t)

	h := newRecheckHarness(t)
	ctx := context.Background()
	acct := h.addAccount(t)
	ident := core.CoderIdentity{ID: uuid.New(), Username: "testuser"}

	snap, err := h.store.ReplaceCredential(ctx, core.ReplaceCredentialRequest{
		AccountID: acct.ID, ExpectedGeneration: 0,
		Token: []byte("token-gen1"), Identity: ident,
	})
	if err != nil {
		t.Fatalf("ReplaceCredential gen0: %v", err)
	}
	if snap.Generation != 1 {
		t.Fatalf("first generation = %d, want 1", snap.Generation)
	}

	h.store.ReplaceCredential(ctx, core.ReplaceCredentialRequest{
		AccountID: acct.ID, ExpectedGeneration: 1,
		Token: []byte("token-gen2"), Identity: ident,
	})

	h.verifier.verifyFn = func(ctx context.Context, token []byte) (core.CoderIdentity, error) {
		return core.CoderIdentity{}, &core.CredentialError{
			Kind: core.CredentialInvalid, HTTPStatus: http.StatusUnauthorized,
			Retryable: true, DetailCode: core.AUTH_CREDENTIAL_UNAUTHORIZED,
		}
	}

	h.rechecker.RecheckAfterFailure(ctx, acct.ID, 1)

	snap, _ = h.store.LoadCredential(ctx, acct.ID)
	if snap.Generation != 2 {
		t.Errorf("generation = %d, want 2 (unchanged)", snap.Generation)
	}
	if snap.State != core.CredentialStateValid {
		t.Errorf("state = %v, want valid", snap.State)
	}
}

func TestRecheckerMatchingGen401(t *testing.T) {
	defer testleaks.Verify(t)

	h := newRecheckHarness(t)
	ctx := context.Background()
	acct := h.addAccount(t)
	ident := core.CoderIdentity{ID: uuid.New(), Username: "testuser"}

	h.store.ReplaceCredential(ctx, core.ReplaceCredentialRequest{
		AccountID: acct.ID, ExpectedGeneration: 0,
		Token: []byte("valid-token"), Identity: ident,
	})

	h.verifier.verifyFn = func(ctx context.Context, token []byte) (core.CoderIdentity, error) {
		return core.CoderIdentity{}, &core.CredentialError{
			Kind: core.CredentialInvalid, HTTPStatus: http.StatusUnauthorized,
			Retryable: true, DetailCode: core.AUTH_CREDENTIAL_UNAUTHORIZED,
		}
	}

	h.rechecker.RecheckAfterFailure(ctx, acct.ID, 1)

	snap, err := h.store.LoadCredential(ctx, acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.State != core.CredentialStateInvalid {
		t.Errorf("state = %v, want invalid", snap.State)
	}
	if snap.Generation != 1 {
		t.Errorf("generation = %d, want 1", snap.Generation)
	}
}

func TestRechecker503NoMark(t *testing.T) {
	defer testleaks.Verify(t)

	h := newRecheckHarness(t)
	ctx := context.Background()
	acct := h.addAccount(t)
	ident := core.CoderIdentity{ID: uuid.New(), Username: "testuser"}

	h.store.ReplaceCredential(ctx, core.ReplaceCredentialRequest{
		AccountID: acct.ID, ExpectedGeneration: 0,
		Token: []byte("valid-token"), Identity: ident,
	})

	h.verifier.verifyFn = func(ctx context.Context, token []byte) (core.CoderIdentity, error) {
		return core.CoderIdentity{}, &core.CredentialError{
			Kind: core.ControlPlaneUnavailable, HTTPStatus: http.StatusServiceUnavailable,
			Retryable: true, DetailCode: core.AUTH_CODER_UNAVAILABLE,
		}
	}

	h.rechecker.RecheckAfterFailure(ctx, acct.ID, 1)

	snap, _ := h.store.LoadCredential(ctx, acct.ID)
	if snap.State != core.CredentialStateValid {
		t.Errorf("state = %v, want valid", snap.State)
	}
}

func TestRecheckerGenChangedNoHTTP(t *testing.T) {
	defer testleaks.Verify(t)

	h := newRecheckHarness(t)
	ctx := context.Background()
	acct := h.addAccount(t)
	ident := core.CoderIdentity{ID: uuid.New(), Username: "testuser"}

	h.store.ReplaceCredential(ctx, core.ReplaceCredentialRequest{
		AccountID: acct.ID, ExpectedGeneration: 0,
		Token: []byte("token-gen1"), Identity: ident,
	})
	h.store.ReplaceCredential(ctx, core.ReplaceCredentialRequest{
		AccountID: acct.ID, ExpectedGeneration: 1,
		Token: []byte("token-gen2"), Identity: ident,
	})

	var callCount int32
	h.verifier.verifyFn = func(ctx context.Context, token []byte) (core.CoderIdentity, error) {
		atomic.AddInt32(&callCount, 1)
		t.Error("Verify should NOT be called when generation changed")
		return core.CoderIdentity{}, errors.New("unexpected")
	}

	h.rechecker.RecheckAfterFailure(ctx, acct.ID, 1)

	if atomic.LoadInt32(&callCount) != 0 {
		t.Errorf("HTTP call count = %d, want 0", callCount)
	}
}

func TestRecheckerMissingNoHTTP(t *testing.T) {
	defer testleaks.Verify(t)

	h := newRecheckHarness(t)
	ctx := context.Background()
	acct := h.addAccount(t)

	var callCount int32
	h.verifier.verifyFn = func(ctx context.Context, token []byte) (core.CoderIdentity, error) {
		atomic.AddInt32(&callCount, 1)
		t.Error("Verify should NOT be called for missing credential")
		return core.CoderIdentity{}, errors.New("unexpected")
	}

	h.rechecker.RecheckAfterFailure(ctx, acct.ID, 0)

	if atomic.LoadInt32(&callCount) != 0 {
		t.Errorf("HTTP call count = %d, want 0", callCount)
	}
}
