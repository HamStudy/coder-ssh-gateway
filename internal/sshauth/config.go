package sshauth

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

// KeyLookupStore is the narrow store subset the auth callbacks need (§25.2,
// §25.3). *store.Store satisfies it.
type KeyLookupStore interface {
	LookupByPublicKey(ctx context.Context, deploymentID uuid.UUID, key ssh.PublicKey) (core.Account, core.SSHKeyRecord, error)
	LoadCredential(ctx context.Context, accountID uuid.UUID) (core.CredentialSnapshot, error)
}

// CachedTokenVerifier is the narrow verifier subset the verified-key
// callback needs. *coderapi.CachedVerifier satisfies it.
type CachedTokenVerifier interface {
	VerifyCached(ctx context.Context, accountID uuid.UUID, generation int64, token []byte) (core.CoderIdentity, error)
}

// AuthConfig carries the dependencies and policy knobs for the SSH auth
// callbacks. BuildCallbacks fails closed when the config is invalid.
type AuthConfig struct {
	// DeploymentID scopes key lookup and credential verification to one
	// Coder deployment.
	DeploymentID uuid.UUID
	// CoderURL is the deployment base URL; only used to render the
	// /cli-auth renewal banner (§13.3). May be nil in tests that never
	// reach the renewal path.
	CoderURL *url.URL
	// RenewalAuthTimeout extends the raw connection deadline when the
	// verified-key callback enters the renewal path (§13.5). Zero disables
	// the extension (the connection owner keeps its own deadline).
	// Renewal.RenewalTimeout overrides this when set.
	RenewalAuthTimeout time.Duration

	// Renewal carries the §13 credential-renewal continuation dependencies.
	// Nil keeps the placeholder (always-reject) continuation callbacks.
	Renewal *RenewalConfig

	// EnrollmentUser is the outer username that triggers self-enrollment
	// (CD-2, default "login"). It is active only when Enrollment is non-nil
	// and Enabled; Enrollment.User overrides it when set.
	EnrollmentUser string
	// Enrollment carries the CD-2 self-enrollment continuation
	// dependencies. Nil or Disabled makes the enrollment username behave
	// exactly like any unknown username (§35).
	Enrollment *EnrollmentConfig

	// KeyManagementUser is the outer username that triggers the
	// account-scoped key-management UI (default "login-admin"). It is
	// active only when KeyManagement is non-nil and Enabled; unlike
	// enrollment there is no nested override — the app layer resolves the
	// effective username (YAML/env precedence) into this field.
	KeyManagementUser string
	// KeyManagement arms the key-management username. Nil or Disabled
	// makes the username behave exactly like any unknown username (§35).
	KeyManagement *KeyManagementEnabled

	Store    KeyLookupStore
	Verifier CachedTokenVerifier
	Audit    audit.Logger
	// Logger receives debug-level internal diagnostics (candidate-seen,
	// rejection reasons). Nil selects slog.Default().
	Logger *slog.Logger
}

// KeyManagementEnabled arms the key-management username on AuthConfig. It
// deliberately carries no dependencies: the key-management path authenticates
// an already-enrolled key and consults neither the stored credential nor the
// Coder control plane.
type KeyManagementEnabled struct {
	Enabled bool
}

// validate enforces fail-closed construction: any missing dependency makes
// every callback reject.
func (c AuthConfig) validate() error {
	if c.DeploymentID == uuid.Nil {
		return errors.New("sshauth: deployment ID is required")
	}
	if c.Store == nil || c.Verifier == nil {
		return errors.New("sshauth: store and verifier are required")
	}
	if c.Enrollment != nil && c.Enrollment.Enabled {
		user := c.enrollmentUser()
		if user == "" {
			return errors.New("sshauth: enabled enrollment requires an enrollment username")
		}
		if c.Enrollment.Verifier == nil || c.Enrollment.Store == nil {
			return errors.New("sshauth: enabled enrollment requires verifier and store")
		}
	}
	if c.KeyManagement != nil && c.KeyManagement.Enabled {
		if c.keysUser() == "" {
			return errors.New("sshauth: enabled key management requires a username")
		}
		// Defense-in-depth on top of config.Validate: two armed special
		// usernames must never collide (the candidate-stage branches route
		// on the username alone).
		if c.enrollmentEnabled() && c.keysUser() == c.enrollmentUser() {
			return errors.New("sshauth: enrollment and key management usernames must differ when both are enabled")
		}
	}
	return nil
}

// enrollmentUser resolves the enrollment trigger username:
// Enrollment.User wins over AuthConfig.EnrollmentUser.
func (c AuthConfig) enrollmentUser() string {
	if c.Enrollment != nil && c.Enrollment.User != "" {
		return c.Enrollment.User
	}
	return c.EnrollmentUser
}

// enrollmentEnabled reports whether the enrollment user is armed.
func (c AuthConfig) enrollmentEnabled() bool {
	return c.Enrollment != nil && c.Enrollment.Enabled && c.enrollmentUser() != ""
}

// keysUser resolves the key-management trigger username. Unlike enrollment
// there is no nested override: the app layer resolves the effective username
// into KeyManagementUser.
func (c AuthConfig) keysUser() string {
	return c.KeyManagementUser
}

// keysEnabled reports whether the key-management user is armed.
func (c AuthConfig) keysEnabled() bool {
	return c.KeyManagement != nil && c.KeyManagement.Enabled && c.keysUser() != ""
}

func (c AuthConfig) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

// BuildCallbacks returns the per-connection PublicKeyCallback and
// VerifiedPublicKeyCallback closures (§9.3, §9.4). Install them on a shallow
// copy of the immutable base ssh.ServerConfig together with
// PreAuthConnCallback: state.SetPreAuthConn.
//
// When cfg is invalid both callbacks reject every attempt (fail closed).
func BuildCallbacks(cfg AuthConfig, state *ConnState) (
	publicKey func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error),
	verifiedKey func(ssh.ConnMetadata, ssh.PublicKey, *ssh.Permissions, string) (*ssh.Permissions, error),
) {
	cfgErr := cfg.validate()
	publicKey = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		return cfg.publicKeyCallback(state, cfgErr, meta, key)
	}
	verifiedKey = func(meta ssh.ConnMetadata, key ssh.PublicKey, candidate *ssh.Permissions, sigAlg string) (*ssh.Permissions, error) {
		return cfg.verifiedPublicKeyCallback(state, cfgErr, meta, key, candidate, sigAlg)
	}
	return publicKey, verifiedKey
}
