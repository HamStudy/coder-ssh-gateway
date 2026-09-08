package sshauth_test

import (
	"errors"
	"testing"

	"github.com/HamStudy/coder-ssh-gateway/internal/sshauth"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// keymgmtCandidateExt returns the valid wire form of a keymanagement
// candidate as ParseCandidatePermissions must accept it.
func keymgmtCandidateExt() map[string]string {
	return map[string]string{
		sshauth.PermissionMode:      sshauth.ModeKeyManagement,
		sshauth.PermissionAccountID: uuid.New().String(),
		sshauth.PermissionSSHKeyID:  uuid.New().String(),
	}
}

// keymgmtFinalExt returns the valid wire form of keymanagement final
// permissions as ParseFinalPermissions must accept it.
func keymgmtFinalExt() map[string]string {
	return map[string]string{
		sshauth.PermissionMode:                 sshauth.ModeKeyManagement,
		sshauth.PermissionAccountID:            uuid.New().String(),
		sshauth.PermissionDeploymentID:         uuid.New().String(),
		sshauth.PermissionSSHKeyID:             uuid.New().String(),
		sshauth.PermissionCredentialGeneration: "0",
		sshauth.PermissionMustReconnect:        "false",
	}
}

func withExt(base map[string]string, key, value string) map[string]string {
	base[key] = value
	return base
}

func withoutExt(base map[string]string, key string) map[string]string {
	delete(base, key)
	return base
}

func assertExtensionKeys(t *testing.T, ext map[string]string, want ...string) {
	t.Helper()
	if len(ext) != len(want) {
		t.Fatalf("extension count = %d, want %d (%v)", len(ext), len(want), ext)
	}
	for _, key := range want {
		if _, ok := ext[key]; !ok {
			t.Fatalf("extension %q missing from %v", key, ext)
		}
	}
}

func TestPermissionsKeyManagementWire(t *testing.T) {
	accountID := uuid.New()
	deploymentID := uuid.New()
	keyID := uuid.New()

	t.Run("candidate encode parse round trip", func(t *testing.T) {
		built := sshauth.KeyManagementCandidatePermissions(accountID, keyID)

		assertExtensionKeys(t, built.Extensions,
			sshauth.PermissionMode, sshauth.PermissionAccountID, sshauth.PermissionSSHKeyID)
		if built.Extensions[sshauth.PermissionMode] != sshauth.ModeKeyManagement {
			t.Errorf("mode = %q, want %q", built.Extensions[sshauth.PermissionMode], sshauth.ModeKeyManagement)
		}

		parsed, err := sshauth.ParseCandidatePermissions(built)
		if err != nil {
			t.Fatalf("ParseCandidatePermissions() error = %v", err)
		}
		if parsed.Mode != sshauth.ModeKeyManagement {
			t.Errorf("Mode = %q, want %q", parsed.Mode, sshauth.ModeKeyManagement)
		}
		if parsed.AccountID != accountID {
			t.Errorf("AccountID = %v, want %v", parsed.AccountID, accountID)
		}
		if parsed.SSHKeyID != keyID {
			t.Errorf("SSHKeyID = %v, want %v", parsed.SSHKeyID, keyID)
		}
	})

	t.Run("final encode parse round trip", func(t *testing.T) {
		built := sshauth.FinalKeyManagementPermissions(accountID, deploymentID, keyID)

		assertExtensionKeys(t, built.Extensions,
			sshauth.PermissionMode, sshauth.PermissionAccountID, sshauth.PermissionDeploymentID,
			sshauth.PermissionSSHKeyID, sshauth.PermissionCredentialGeneration,
			sshauth.PermissionMustReconnect)
		if got := built.Extensions[sshauth.PermissionCredentialGeneration]; got != "0" {
			t.Errorf("credential_generation wire value = %q, want %q", got, "0")
		}
		if got := built.Extensions[sshauth.PermissionMustReconnect]; got != "false" {
			t.Errorf("must_reconnect wire value = %q, want %q", got, "false")
		}

		parsed, err := sshauth.ParseFinalPermissions(built)
		if err != nil {
			t.Fatalf("ParseFinalPermissions() error = %v", err)
		}
		if parsed.Mode != sshauth.ModeKeyManagement {
			t.Errorf("Mode = %q, want %q", parsed.Mode, sshauth.ModeKeyManagement)
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
		if parsed.CredentialGeneration != 0 {
			t.Errorf("CredentialGeneration = %d, want 0", parsed.CredentialGeneration)
		}
		if parsed.MustReconnect {
			t.Error("MustReconnect = true, want false")
		}
	})
}

// TestPermissionsKeyManagementWire_LegacyModesUnchanged pins the pre-existing
// modes: extending the parsers for keymanagement must not alter how
// workspace, enrollment, and plain candidate permissions parse.
func TestPermissionsKeyManagementWire_LegacyModesUnchanged(t *testing.T) {
	t.Run("plain candidate still parses as candidate", func(t *testing.T) {
		accountID := uuid.New()
		keyID := uuid.New()

		parsed, err := sshauth.ParseCandidatePermissions(sshauth.CandidatePermissions(accountID, keyID))
		if err != nil {
			t.Fatalf("ParseCandidatePermissions() error = %v", err)
		}
		if parsed.Mode != sshauth.ModeCandidate {
			t.Errorf("Mode = %q, want %q", parsed.Mode, sshauth.ModeCandidate)
		}
	})

	t.Run("workspace final still parses as workspace", func(t *testing.T) {
		parsed, err := sshauth.ParseFinalPermissions(
			sshauth.FinalWorkspacePermissions(uuid.New(), uuid.New(), uuid.New(), 7))
		if err != nil {
			t.Fatalf("ParseFinalPermissions() error = %v", err)
		}
		if parsed.Mode != sshauth.ModeWorkspace {
			t.Errorf("Mode = %q, want %q", parsed.Mode, sshauth.ModeWorkspace)
		}
		if parsed.MustReconnect {
			t.Error("MustReconnect = true, want false")
		}
	})

	t.Run("enrollment final still flags must reconnect", func(t *testing.T) {
		parsed, err := sshauth.ParseFinalPermissions(
			sshauth.FinalEnrollmentPermissions(uuid.New(), uuid.New(), uuid.New(), 3))
		if err != nil {
			t.Fatalf("ParseFinalPermissions() error = %v", err)
		}
		if !parsed.MustReconnect {
			t.Error("MustReconnect = false, want true")
		}
	})

	t.Run("enrollment candidate parser untouched", func(t *testing.T) {
		digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

		parsed, err := sshauth.ParseEnrollmentCandidatePermissions(
			sshauth.EnrollmentCandidatePermissions(digest))
		if err != nil {
			t.Fatalf("ParseEnrollmentCandidatePermissions() error = %v", err)
		}
		if parsed.KeyDigest != digest {
			t.Errorf("KeyDigest = %q, want %q", parsed.KeyDigest, digest)
		}

		if _, err := sshauth.ParseCandidatePermissions(
			sshauth.EnrollmentCandidatePermissions(digest)); !errors.Is(err, sshauth.ErrInvalidMode) {
			t.Errorf("ParseCandidatePermissions(enrollment) error = %v, want ErrInvalidMode", err)
		}
	})
}

// TestPermissionsKeyManagementWire_Malformed asserts every malformed wire
// shape rejects with the existing sentinel errors via errors.Is.
func TestPermissionsKeyManagementWire_Malformed(t *testing.T) {
	tests := []struct {
		name    string
		final   bool // true: ParseFinalPermissions, false: ParseCandidatePermissions
		ext     map[string]string
		wantErr error
	}{
		// Candidate parser.
		{name: "candidate wrong mode workspace", final: false,
			ext:     withExt(keymgmtCandidateExt(), sshauth.PermissionMode, sshauth.ModeWorkspace),
			wantErr: sshauth.ErrInvalidMode},
		{name: "candidate wrong mode enrollment", final: false,
			ext:     withExt(keymgmtCandidateExt(), sshauth.PermissionMode, sshauth.ModeEnrollment),
			wantErr: sshauth.ErrInvalidMode},
		{name: "candidate unknown mode string", final: false,
			ext:     withExt(keymgmtCandidateExt(), sshauth.PermissionMode, "bogus"),
			wantErr: sshauth.ErrInvalidMode},
		{name: "candidate missing mode", final: false,
			ext:     withoutExt(keymgmtCandidateExt(), sshauth.PermissionMode),
			wantErr: sshauth.ErrInvalidMode},
		{name: "candidate zero account id", final: false,
			ext:     withExt(keymgmtCandidateExt(), sshauth.PermissionAccountID, uuid.Nil.String()),
			wantErr: sshauth.ErrZeroAccountID},
		{name: "candidate missing account id", final: false,
			ext:     withoutExt(keymgmtCandidateExt(), sshauth.PermissionAccountID),
			wantErr: sshauth.ErrMissingAccountID},
		{name: "candidate invalid account id", final: false,
			ext:     withExt(keymgmtCandidateExt(), sshauth.PermissionAccountID, "not-a-uuid"),
			wantErr: sshauth.ErrInvalidAccountID},
		{name: "candidate zero ssh key id", final: false,
			ext:     withExt(keymgmtCandidateExt(), sshauth.PermissionSSHKeyID, uuid.Nil.String()),
			wantErr: sshauth.ErrZeroSSHKeyID},
		{name: "candidate missing ssh key id", final: false,
			ext:     withoutExt(keymgmtCandidateExt(), sshauth.PermissionSSHKeyID),
			wantErr: sshauth.ErrMissingSSHKeyID},
		{name: "candidate unknown extension key", final: false,
			ext:     withExt(keymgmtCandidateExt(), "gateway.extra_field", "disallowed"),
			wantErr: sshauth.ErrUnknownExtension},

		// Final parser.
		{name: "final rejects candidate mode", final: true,
			ext:     withExt(keymgmtFinalExt(), sshauth.PermissionMode, sshauth.ModeCandidate),
			wantErr: sshauth.ErrInvalidMode},
		{name: "final rejects enrollment mode", final: true,
			ext:     withExt(keymgmtFinalExt(), sshauth.PermissionMode, sshauth.ModeEnrollment),
			wantErr: sshauth.ErrInvalidMode},
		{name: "final unknown mode string", final: true,
			ext:     withExt(keymgmtFinalExt(), sshauth.PermissionMode, "bogus"),
			wantErr: sshauth.ErrInvalidMode},
		{name: "final zero account id", final: true,
			ext:     withExt(keymgmtFinalExt(), sshauth.PermissionAccountID, uuid.Nil.String()),
			wantErr: sshauth.ErrZeroAccountID},
		{name: "final invalid account id", final: true,
			ext:     withExt(keymgmtFinalExt(), sshauth.PermissionAccountID, "not-a-uuid"),
			wantErr: sshauth.ErrInvalidAccountID},
		{name: "final zero ssh key id", final: true,
			ext:     withExt(keymgmtFinalExt(), sshauth.PermissionSSHKeyID, uuid.Nil.String()),
			wantErr: sshauth.ErrZeroSSHKeyID},
		{name: "final zero deployment id", final: true,
			ext:     withExt(keymgmtFinalExt(), sshauth.PermissionDeploymentID, uuid.Nil.String()),
			wantErr: sshauth.ErrZeroDeploymentID},
		{name: "final invalid deployment id", final: true,
			ext:     withExt(keymgmtFinalExt(), sshauth.PermissionDeploymentID, "not-a-uuid"),
			wantErr: sshauth.ErrInvalidDeploymentID},
		{name: "final keymanagement requires deployment id", final: true,
			ext:     withoutExt(keymgmtFinalExt(), sshauth.PermissionDeploymentID),
			wantErr: sshauth.ErrMissingDeploymentID},
		{name: "final negative generation", final: true,
			ext:     withExt(keymgmtFinalExt(), sshauth.PermissionCredentialGeneration, "-1"),
			wantErr: sshauth.ErrNegativeGeneration},
		{name: "final unparsable generation", final: true,
			ext:     withExt(keymgmtFinalExt(), sshauth.PermissionCredentialGeneration, "not-a-number"),
			wantErr: sshauth.ErrInvalidGeneration},
		{name: "final unparsable must reconnect", final: true,
			ext:     withExt(keymgmtFinalExt(), sshauth.PermissionMustReconnect, "yes"),
			wantErr: sshauth.ErrInvalidMustReconnect},
		{name: "final unknown extension key", final: true,
			ext:     withExt(keymgmtFinalExt(), "gateway.extra_field", "disallowed"),
			wantErr: sshauth.ErrUnknownExtension},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := &ssh.Permissions{Extensions: tt.ext}
			var err error
			if tt.final {
				_, err = sshauth.ParseFinalPermissions(perms)
			} else {
				_, err = sshauth.ParseCandidatePermissions(perms)
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want sentinel %v", err, tt.wantErr)
			}
		})
	}

	t.Run("nil permissions reject", func(t *testing.T) {
		if _, err := sshauth.ParseFinalPermissions(nil); !errors.Is(err, sshauth.ErrMissingAccountID) {
			t.Errorf("ParseFinalPermissions(nil) error = %v, want ErrMissingAccountID", err)
		}
		if _, err := sshauth.ParseCandidatePermissions(nil); !errors.Is(err, sshauth.ErrMissingAccountID) {
			t.Errorf("ParseCandidatePermissions(nil) error = %v, want ErrMissingAccountID", err)
		}
	})
}
