package sshauth

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/audit"
	"github.com/taxilian/coder-ssh-gateway/internal/core"
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
	// TransportUser is the outer username for workspace transport (§8.1,
	// default "coder").
	TransportUser string
	// MaintenanceUser is the outer username for credential maintenance
	// (§8.1, default "auth").
	MaintenanceUser string
	// AllowSSHCertificates permits *ssh.Certificate keys (§10.3; default
	// false — MVP rejects certificates).
	AllowSSHCertificates bool
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
	RenewalAuthTimeout time.Duration

	Store    KeyLookupStore
	Verifier CachedTokenVerifier
	Audit    audit.Logger
	// Logger receives debug-level internal diagnostics (candidate-seen,
	// rejection reasons). Nil selects slog.Default().
	Logger *slog.Logger
}

// validate enforces fail-closed construction: any missing dependency makes
// every callback reject.
func (c AuthConfig) validate() error {
	if c.TransportUser == "" || c.MaintenanceUser == "" {
		return errors.New("sshauth: transport and maintenance usernames are required")
	}
	if c.TransportUser == c.MaintenanceUser {
		return errors.New("sshauth: transport and maintenance usernames must differ")
	}
	if c.DeploymentID == uuid.Nil {
		return errors.New("sshauth: deployment ID is required")
	}
	if c.Store == nil || c.Verifier == nil {
		return errors.New("sshauth: store and verifier are required")
	}
	return nil
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
