package core_test

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/google/uuid"
)

func TestCredentialState(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		tests := []struct {
			state core.CredentialState
			want  string
		}{
			{core.CredentialStateMissing, "missing"},
			{core.CredentialStateUnknown, "unknown"},
			{core.CredentialStateValid, "valid"},
			{core.CredentialStateInvalid, "invalid"},
		}
		for _, tt := range tests {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("CredentialState.String() = %v, want %v", got, tt.want)
			}
		}
	})

	t.Run("Parse", func(t *testing.T) {
		tests := []struct {
			input   string
			want    core.CredentialState
			wantErr bool
		}{
			{"missing", core.CredentialStateMissing, false},
			{"unknown", core.CredentialStateUnknown, false},
			{"valid", core.CredentialStateValid, false},
			{"invalid", core.CredentialStateInvalid, false},
			{"INVALID", core.CredentialStateInvalid, false},
			{"garbage", core.CredentialStateInvalid, true},
			{"", core.CredentialStateInvalid, true},
		}
		for _, tt := range tests {
			got, err := core.ParseCredentialState(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCredentialState(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				continue
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseCredentialState(%q) = %v, want %v", tt.input, got, tt.want)
			}
		}
	})
}

func TestCredentialErrorKind_Renewable(t *testing.T) {
	tests := []struct {
		kind          core.CredentialErrorKind
		wantRenewable bool
	}{
		// Only missing and invalid are renewable
		{core.CredentialMissing, true},
		{core.CredentialInvalid, true},
		{core.CredentialForbidden, false},
		{core.CredentialWrongIdentity, false},
		{core.CredentialMalformedReply, false},
		{core.ControlPlaneUnavailable, false},
		{core.ControlPlaneIncompatible, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			if got := tt.kind.Renewable(); got != tt.wantRenewable {
				t.Errorf("CredentialErrorKind.Renewable() = %v, want %v", got, tt.wantRenewable)
			}
		})
	}
}

func TestKindOf(t *testing.T) {
	t.Run("extracts kind from CredentialError", func(t *testing.T) {
		err := &core.CredentialError{
			Kind: core.CredentialInvalid,
		}
		if got := core.KindOf(err); got != core.CredentialInvalid {
			t.Errorf("KindOf() = %v, want %v", got, core.CredentialInvalid)
		}
	})

	t.Run("returns empty for non-credential error", func(t *testing.T) {
		err := errors.New("some other error")
		if got := core.KindOf(err); got != "" {
			t.Errorf("KindOf() = %v, want empty string", got)
		}
	})

	t.Run("unwraps cause chain", func(t *testing.T) {
		cause := &core.CredentialError{Kind: core.ControlPlaneUnavailable}
		err := &core.CredentialError{Kind: core.CredentialInvalid, Cause: cause}
		if got := core.KindOf(err); got != core.CredentialInvalid {
			t.Errorf("KindOf() = %v, want %v", got, core.CredentialInvalid)
		}
	})
}

func TestCredentialError_Error_DoesNotLeak(t *testing.T) {
	// Error() must NEVER include token or body content
	tokenLike := errors.New("token=abc123-secret-token")
	err := &core.CredentialError{
		Kind:       core.CredentialInvalid,
		HTTPStatus: 401,
		Retryable:  true,
		DetailCode: "AUTH_CREDENTIAL_UNAUTHORIZED",
		Cause:      tokenLike,
	}

	got := err.Error()

	// Must not contain token-like content
	if contains(got, "abc123") || contains(got, "secret-token") || contains(got, "token") {
		t.Errorf("Error() contains token content: %q", got)
	}

	// Must contain kind
	if !contains(got, string(core.CredentialInvalid)) {
		t.Errorf("Error() = %q, should contain kind %q", got, core.CredentialInvalid)
	}
}

func TestCredentialError_Error_Format(t *testing.T) {
	tests := []struct {
		name string
		err  core.CredentialError
		want string
	}{
		{
			name: "kind only",
			err: core.CredentialError{
				Kind: core.CredentialMissing,
			},
			want: "missing",
		},
		{
			name: "kind with detail code",
			err: core.CredentialError{
				Kind:       core.CredentialForbidden,
				DetailCode: "AUTH_CREDENTIAL_FORBIDDEN",
			},
			want: "forbidden (AUTH_CREDENTIAL_FORBIDDEN)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("CredentialError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCredentialError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &core.CredentialError{
		Kind:  core.CredentialInvalid,
		Cause: cause,
	}

	if got := err.Unwrap(); got != cause {
		t.Errorf("CredentialError.Unwrap() = %v, want %v", got, cause)
	}
}

func TestAccount(t *testing.T) {
	id := uuid.New()
	deploymentID := uuid.New()
	userID := uuid.New()

	account := core.Account{
		ID:               id,
		DeploymentID:     deploymentID,
		Label:            "test-account",
		CoderUserID:      &userID,
		CachedUsername:   "testuser",
		BindOnFirstToken: true,
		Enabled:          true,
	}

	if account.ID != id {
		t.Errorf("Account.ID = %v, want %v", account.ID, id)
	}
	if account.DeploymentID != deploymentID {
		t.Errorf("Account.DeploymentID = %v, want %v", account.DeploymentID, deploymentID)
	}
	if account.Label != "test-account" {
		t.Errorf("Account.Label = %v, want %v", account.Label, "test-account")
	}
	if account.CoderUserID == nil || *account.CoderUserID != userID {
		t.Errorf("Account.CoderUserID = %v, want %v", account.CoderUserID, userID)
	}
	if account.CachedUsername != "testuser" {
		t.Errorf("Account.CachedUsername = %v, want %v", account.CachedUsername, "testuser")
	}
	if !account.BindOnFirstToken {
		t.Error("Account.BindOnFirstToken = false, want true")
	}
	if !account.Enabled {
		t.Error("Account.Enabled = false, want true")
	}
}

func TestSSHKeyRecord(t *testing.T) {
	id := uuid.New()
	accountID := uuid.New()

	lastUsed := int64(1234567890)

	key := core.SSHKeyRecord{
		ID:           id,
		AccountID:    accountID,
		Fingerprint:  "SHA256:abc123",
		Algorithm:    "ssh-ed25519",
		Label:        "laptop key",
		Enabled:      true,
		CreatedAtMs:  1234000000,
		LastUsedAtMs: &lastUsed,
	}

	if key.ID != id {
		t.Errorf("SSHKeyRecord.ID = %v, want %v", key.ID, id)
	}
	if key.AccountID != accountID {
		t.Errorf("SSHKeyRecord.AccountID = %v, want %v", key.AccountID, accountID)
	}
	if key.Fingerprint != "SHA256:abc123" {
		t.Errorf("SSHKeyRecord.Fingerprint = %v, want %v", key.Fingerprint, "SHA256:abc123")
	}
	if key.Algorithm != "ssh-ed25519" {
		t.Errorf("SSHKeyRecord.Algorithm = %v, want %v", key.Algorithm, "ssh-ed25519")
	}
	if !key.Enabled {
		t.Error("SSHKeyRecord.Enabled = false, want true")
	}
	if key.Label != "laptop key" {
		t.Errorf("SSHKeyRecord.Label = %v, want %v", key.Label, "laptop key")
	}
	if key.CreatedAtMs != 1234000000 {
		t.Errorf("SSHKeyRecord.CreatedAtMs = %v, want 1234000000", key.CreatedAtMs)
	}
	if key.LastUsedAtMs == nil || *key.LastUsedAtMs != lastUsed {
		t.Errorf("SSHKeyRecord.LastUsedAtMs = %v, want %d", key.LastUsedAtMs, lastUsed)
	}

	var neverUsed core.SSHKeyRecord
	if neverUsed.LastUsedAtMs != nil {
		t.Error("zero-value SSHKeyRecord.LastUsedAtMs = non-nil, want nil (never used)")
	}
}

func TestCredentialSnapshot(t *testing.T) {
	accountID := uuid.New()
	now := time.Now()

	snapshot := core.CredentialSnapshot{
		AccountID:       accountID,
		Generation:      42,
		State:           core.CredentialStateValid,
		Token:           []byte("token-bytes"),
		LastValidatedAt: now,
	}

	if snapshot.AccountID != accountID {
		t.Errorf("CredentialSnapshot.AccountID = %v, want %v", snapshot.AccountID, accountID)
	}
	if snapshot.Generation != 42 {
		t.Errorf("CredentialSnapshot.Generation = %v, want %v", snapshot.Generation, 42)
	}
	if snapshot.State != core.CredentialStateValid {
		t.Errorf("CredentialSnapshot.State = %v, want %v", snapshot.State, core.CredentialStateValid)
	}
	if string(snapshot.Token) != "token-bytes" {
		t.Errorf("CredentialSnapshot.Token = %v, want %v", snapshot.Token, []byte("token-bytes"))
	}
	if !snapshot.LastValidatedAt.Equal(now) {
		t.Errorf("CredentialSnapshot.LastValidatedAt = %v, want %v", snapshot.LastValidatedAt, now)
	}
}

func TestDeployment(t *testing.T) {
	id := uuid.New()
	coderURL, _ := url.Parse("https://coder.example.com")

	deployment := core.Deployment{
		ID:           id,
		CoderURL:     coderURL,
		CoderBinary:  "/usr/local/bin/coder",
		GlobalConfig: "/var/lib/coder",
		WorkingDir:   "/var/empty",
		Autostart:    true,
		WaitMode:     "auto",
	}

	if deployment.ID != id {
		t.Errorf("Deployment.ID = %v, want %v", deployment.ID, id)
	}
	if deployment.CoderURL.String() != "https://coder.example.com" {
		t.Errorf("Deployment.CoderURL = %v, want %v", deployment.CoderURL.String(), "https://coder.example.com")
	}
	if deployment.CoderBinary != "/usr/local/bin/coder" {
		t.Errorf("Deployment.CoderBinary = %v, want %v", deployment.CoderBinary, "/usr/local/bin/coder")
	}
	if deployment.Autostart != true {
		t.Error("Deployment.Autostart = false, want true")
	}
	if deployment.WaitMode != "auto" {
		t.Errorf("Deployment.WaitMode = %v, want %v", deployment.WaitMode, "auto")
	}
}

func TestRoute(t *testing.T) {
	route := core.Route{
		RequestedHost: "dev",
		RequestedPort: 22,
		WorkspaceHost: "dev",
		DisplayTarget: "dev",
	}

	if route.RequestedHost != "dev" {
		t.Errorf("Route.RequestedHost = %v, want %v", route.RequestedHost, "dev")
	}
	if route.RequestedPort != 22 {
		t.Errorf("Route.RequestedPort = %v, want %v", route.RequestedPort, 22)
	}
	if route.WorkspaceHost != "dev" {
		t.Errorf("Route.WorkspaceHost = %v, want %v", route.WorkspaceHost, "dev")
	}
	if route.DisplayTarget != "dev" {
		t.Errorf("Route.DisplayTarget = %v, want %v", route.DisplayTarget, "dev")
	}
}

func TestCoderIdentity(t *testing.T) {
	id := uuid.New()

	identity := core.CoderIdentity{
		ID:       id,
		Username: "testuser",
		Status:   "active",
	}

	if identity.ID != id {
		t.Errorf("CoderIdentity.ID = %v, want %v", identity.ID, id)
	}
	if identity.Username != "testuser" {
		t.Errorf("CoderIdentity.Username = %v, want %v", identity.Username, "testuser")
	}
	if identity.Status != "active" {
		t.Errorf("CoderIdentity.Status = %v, want %v", identity.Status, "active")
	}
}

func TestReplaceCredentialRequest(t *testing.T) {
	accountID := uuid.New()
	identity := core.CoderIdentity{
		ID:       uuid.New(),
		Username: "testuser",
		Status:   "active",
	}

	req := core.ReplaceCredentialRequest{
		AccountID:          accountID,
		ExpectedGeneration: 5,
		Token:              []byte("new-token"),
		Identity:           identity,
	}

	if req.AccountID != accountID {
		t.Errorf("ReplaceCredentialRequest.AccountID = %v, want %v", req.AccountID, accountID)
	}
	if req.ExpectedGeneration != 5 {
		t.Errorf("ReplaceCredentialRequest.ExpectedGeneration = %v, want %v", req.ExpectedGeneration, 5)
	}
	if string(req.Token) != "new-token" {
		t.Errorf("ReplaceCredentialRequest.Token = %v, want %v", req.Token, []byte("new-token"))
	}
	if req.Identity.Username != "testuser" {
		t.Errorf("ReplaceCredentialRequest.Identity.Username = %v, want %v", req.Identity.Username, "testuser")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
