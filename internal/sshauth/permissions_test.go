package sshauth_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
	"golang.org/x/crypto/ssh"
)

func TestCandidatePermissions(t *testing.T) {
	accountID := uuid.New()
	keyID := uuid.New()

	perms := sshauth.CandidatePermissions(accountID, keyID)

	ext := perms.Extensions
	if ext[sshauth.PermissionMode] != string(sshauth.ModeCandidate) {
		t.Errorf("mode = %q, want %q", ext["gateway.mode"], string(sshauth.ModeCandidate))
	}
	if ext[sshauth.PermissionAccountID] != accountID.String() {
		t.Errorf("account_id = %q, want %q", ext["gateway.account_id"], accountID.String())
	}
	if ext[sshauth.PermissionSSHKeyID] != keyID.String() {
		t.Errorf("ssh_key_id = %q, want %q", ext["gateway.ssh_key_id"], keyID.String())
	}
}

func TestFinalTransportPermissions(t *testing.T) {
	accountID := uuid.New()
	deploymentID := uuid.New()
	keyID := uuid.New()
	generation := int64(42)

	perms := sshauth.FinalTransportPermissions(accountID, deploymentID, keyID, generation, false)

	ext := perms.Extensions
	if ext["gateway.mode"] != string(sshauth.ModeTransport) {
		t.Errorf("mode = %q, want %q", ext["gateway.mode"], string(sshauth.ModeTransport))
	}
	if ext["gateway.account_id"] != accountID.String() {
		t.Errorf("account_id = %q, want %q", ext["gateway.account_id"], accountID.String())
	}
	if ext["gateway.deployment_id"] != deploymentID.String() {
		t.Errorf("deployment_id = %q, want %q", ext["gateway.deployment_id"], deploymentID.String())
	}
	if ext["gateway.ssh_key_id"] != keyID.String() {
		t.Errorf("ssh_key_id = %q, want %q", ext["gateway.ssh_key_id"], keyID.String())
	}
	if ext["gateway.credential_generation"] != "42" {
		t.Errorf("credential_generation = %q, want %q", ext["gateway.credential_generation"], "42")
	}
	if ext["gateway.must_reconnect"] != "false" {
		t.Errorf("must_reconnect = %q, want %q", ext["gateway.must_reconnect"], "false")
	}
}

func TestFinalMaintenancePermissions(t *testing.T) {
	accountID := uuid.New()
	keyID := uuid.New()

	perms := sshauth.FinalMaintenancePermissions(accountID, keyID)

	ext := perms.Extensions
	if ext["gateway.mode"] != string(sshauth.ModeMaintenance) {
		t.Errorf("mode = %q, want %q", ext["gateway.mode"], string(sshauth.ModeMaintenance))
	}
	if ext["gateway.account_id"] != accountID.String() {
		t.Errorf("account_id = %q, want %q", ext["gateway.account_id"], accountID.String())
	}
	if ext["gateway.ssh_key_id"] != keyID.String() {
		t.Errorf("ssh_key_id = %q, want %q", ext["gateway.ssh_key_id"], keyID.String())
	}
}

func TestParseFinalPermissions_RoundTrip(t *testing.T) {
	accountID := uuid.New()
	deploymentID := uuid.New()
	keyID := uuid.New()
	generation := int64(99)

	built := sshauth.FinalTransportPermissions(accountID, deploymentID, keyID, generation, true)

	parsed, err := sshauth.ParseFinalPermissions(built)
	if err != nil {
		t.Fatalf("ParseFinalPermissions() error = %v", err)
	}

	if parsed.Mode != sshauth.ModeTransport {
		t.Errorf("Mode = %v, want %v", parsed.Mode, sshauth.ModeTransport)
	}
	if parsed.AccountID != accountID {
		t.Errorf("AccountID = %v, want %v", parsed.AccountID, accountID)
	}
	if parsed.DeploymentID != deploymentID {
		t.Errorf("DeploymentID = %v, want %v", parsed.DeploymentID, deploymentID)
	}
	if parsed.SSHKeyID != keyID {
		t.Errorf("SSHKeyID = %v, want %v", parsed.SSHKeyID, keyID)
	}
	if parsed.CredentialGeneration != generation {
		t.Errorf("CredentialGeneration = %v, want %v", parsed.CredentialGeneration, generation)
	}
	if !parsed.MustReconnect {
		t.Error("MustReconnect = false, want true")
	}
}

func TestParseCandidatePermissions(t *testing.T) {
	accountID := uuid.New()
	keyID := uuid.New()

	built := sshauth.CandidatePermissions(accountID, keyID)

	parsed, err := sshauth.ParseCandidatePermissions(built)
	if err != nil {
		t.Fatalf("ParseCandidatePermissions() error = %v", err)
	}

	if parsed.Mode != sshauth.ModeCandidate {
		t.Errorf("Mode = %v, want %v", parsed.Mode, sshauth.ModeCandidate)
	}
	if parsed.AccountID != accountID {
		t.Errorf("AccountID = %v, want %v", parsed.AccountID, accountID)
	}
	if parsed.SSHKeyID != keyID {
		t.Errorf("SSHKeyID = %v, want %v", parsed.SSHKeyID, keyID)
	}
}

func TestParsePermissions_RejectsMalformed(t *testing.T) {
	tests := []struct {
		name    string
		perms   *ssh.Permissions
		wantErr string
	}{
		{
			name: "non-integer generation",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					"gateway.mode":                  "transport",
					"gateway.account_id":            uuid.New().String(),
					"gateway.deployment_id":         uuid.New().String(),
					"gateway.ssh_key_id":            uuid.New().String(),
					"gateway.credential_generation": "not-a-number",
				},
			},
			wantErr: "credential_generation",
		},
		{
			name: "negative generation",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					"gateway.mode":                  "transport",
					"gateway.account_id":            uuid.New().String(),
					"gateway.deployment_id":         uuid.New().String(),
					"gateway.ssh_key_id":            uuid.New().String(),
					"gateway.credential_generation": "-1",
				},
			},
			wantErr: "credential_generation",
		},
		{
			name: "unknown mode",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					"gateway.mode":       "invalid-mode",
					"gateway.account_id": uuid.New().String(),
					"gateway.ssh_key_id": uuid.New().String(),
				},
			},
			wantErr: "mode",
		},
		{
			name: "empty account_id",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					"gateway.mode":       "transport",
					"gateway.account_id": "",
					"gateway.ssh_key_id": uuid.New().String(),
				},
			},
			wantErr: "account_id",
		},
		{
			name: "invalid account_id uuid",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					"gateway.mode":       "transport",
					"gateway.account_id": "not-a-uuid",
					"gateway.ssh_key_id": uuid.New().String(),
				},
			},
			wantErr: "account_id",
		},
		{
			name: "zero account_id",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					"gateway.mode":       "transport",
					"gateway.account_id": uuid.Nil.String(),
					"gateway.ssh_key_id": uuid.New().String(),
				},
			},
			wantErr: "account_id",
		},
		{
			name: "zero ssh_key_id",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					"gateway.mode":       "transport",
					"gateway.account_id": uuid.New().String(),
					"gateway.ssh_key_id": uuid.Nil.String(),
				},
			},
			wantErr: "ssh_key_id",
		},
		{
			name: "malformed must_reconnect",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					"gateway.mode":                  "transport",
					"gateway.account_id":            uuid.New().String(),
					"gateway.deployment_id":         uuid.New().String(),
					"gateway.ssh_key_id":            uuid.New().String(),
					"gateway.credential_generation": "1",
					"gateway.must_reconnect":        "yes",
				},
			},
			wantErr: "must_reconnect",
		},
		{
			name: "transport without deployment_id",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					"gateway.mode":       "transport",
					"gateway.account_id": uuid.New().String(),
					"gateway.ssh_key_id": uuid.New().String(),
				},
			},
			wantErr: "deployment_id",
		},
		{
			name: "zero deployment_id",
			perms: &ssh.Permissions{
				Extensions: map[string]string{
					"gateway.mode":          "transport",
					"gateway.account_id":    uuid.New().String(),
					"gateway.deployment_id": uuid.Nil.String(),
					"gateway.ssh_key_id":    uuid.New().String(),
				},
			},
			wantErr: "deployment_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sshauth.ParseFinalPermissions(tt.perms)
			if err == nil {
				t.Fatal("ParseFinalPermissions() expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParsePermissions_RejectsTampered(t *testing.T) {
	t.Run("missing critical key", func(t *testing.T) {
		perms := &ssh.Permissions{
			Extensions: map[string]string{
				"gateway.mode":       "transport",
				"gateway.account_id": uuid.New().String(),
			},
		}
		_, err := sshauth.ParseFinalPermissions(perms)
		if err == nil {
			t.Fatal("expected error for missing ssh_key_id")
		}
	})

	t.Run("extra unknown key", func(t *testing.T) {
		accountID := uuid.New()
		deploymentID := uuid.New()
		keyID := uuid.New()
		perms := sshauth.FinalTransportPermissions(accountID, deploymentID, keyID, 1, false)
		perms.Extensions["gateway.extra_field"] = "disallowed"
		_, err := sshauth.ParseFinalPermissions(perms)
		if err == nil {
			t.Fatal("expected error for extra unknown key")
		}
	})
}

func TestModeConstants(t *testing.T) {
	if sshauth.ModeCandidate != "candidate" {
		t.Errorf("ModeCandidate = %q, want %q", sshauth.ModeCandidate, "candidate")
	}
	if sshauth.ModeTransport != "transport" {
		t.Errorf("ModeTransport = %q, want %q", sshauth.ModeTransport, "transport")
	}
	if sshauth.ModeMaintenance != "maintenance" {
		t.Errorf("ModeMaintenance = %q, want %q", sshauth.ModeMaintenance, "maintenance")
	}
}

func TestParseFinalPermissions_MaintenanceWithoutDeploymentID(t *testing.T) {
	perms := &ssh.Permissions{
		Extensions: map[string]string{
			"gateway.mode":       "maintenance",
			"gateway.account_id": uuid.New().String(),
			"gateway.ssh_key_id": uuid.New().String(),
		},
	}
	parsed, err := sshauth.ParseFinalPermissions(perms)
	if err != nil {
		t.Fatalf("ParseFinalPermissions() error = %v (maintenance mode should allow missing deployment_id)", err)
	}
	if parsed.Mode != sshauth.ModeMaintenance {
		t.Errorf("Mode = %v, want %v", parsed.Mode, sshauth.ModeMaintenance)
	}
	if parsed.DeploymentID != (uuid.UUID{}) {
		t.Errorf("DeploymentID = %v, want zero UUID for maintenance without deployment_id", parsed.DeploymentID)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
