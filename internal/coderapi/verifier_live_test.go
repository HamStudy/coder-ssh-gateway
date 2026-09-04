//go:build live

package coderapi_test

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/taxilian/coder-ssh-gateway/internal/coderapi"
	"github.com/taxilian/coder-ssh-gateway/internal/core"
)

func TestLiveVerify(t *testing.T) {
	token := os.Getenv("CODER_LIVE_TOKEN")
	if token == "" {
		t.Skip("CODER_LIVE_TOKEN unset")
	}
	u, err := url.Parse("https://example.test")
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	dep := core.Deployment{ID: uuid.New(), CoderURL: u}

	v, err := coderapi.New(dep, coderapi.Options{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	id, err := v.Verify(ctx, []byte(token))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Username != "taxilian" {
		t.Fatalf("username = %q, want taxilian", id.Username)
	}
	if id.ID == uuid.Nil {
		t.Fatal("id is zero")
	}

	_, err = v.Verify(ctx, []byte("definitely-not-a-valid-token"))
	ce := requireKind(t, err, core.CredentialInvalid)
	if ce.DetailCode != core.AUTH_CREDENTIAL_UNAUTHORIZED {
		t.Fatalf("detail = %q, want %q", ce.DetailCode, core.AUTH_CREDENTIAL_UNAUTHORIZED)
	}
}
