package coderapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/HamStudy/coder-ssh-gateway/internal/coderapi"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

func TestNewHTTPClientDefaults(t *testing.T) {
	c, err := coderapi.NewHTTPClient(coderapi.Options{})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if c.Timeout != 10*time.Second {
		t.Fatalf("default timeout = %v, want 10s", c.Timeout)
	}
}

func TestNewHTTPClientBadKeyPair(t *testing.T) {
	_, err := coderapi.NewHTTPClient(coderapi.Options{
		ClientCertificate: []byte("garbage"),
		ClientKey:         []byte("garbage"),
	})
	if err == nil {
		t.Fatal("expected error for invalid client certificate/key")
	}
}

func TestHTTPClientRedirectFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/", http.StatusFound)
	}))
	defer srv.Close()

	c, err := coderapi.NewHTTPClient(coderapi.Options{})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected redirect to fail, got nil error")
	}
	var ce *core.CredentialError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *core.CredentialError, got %T: %v", err, err)
	}
	if ce.Kind != core.ControlPlaneIncompatible {
		t.Fatalf("kind = %q, want %q", ce.Kind, core.ControlPlaneIncompatible)
	}
}
