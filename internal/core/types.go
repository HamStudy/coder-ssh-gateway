package core

import (
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Account struct {
	ID               uuid.UUID
	DeploymentID     uuid.UUID
	Label            string
	CoderUserID      *uuid.UUID
	CachedUsername   string
	BindOnFirstToken bool
	Enabled          bool
}

type SSHKeyRecord struct {
	ID          uuid.UUID
	AccountID   uuid.UUID
	Fingerprint string
	Algorithm   string
	Enabled     bool
}

type CredentialSnapshot struct {
	AccountID       uuid.UUID
	Generation      int64
	State           CredentialState
	Token           []byte
	LastValidatedAt time.Time
}

type CredentialState string

const (
	CredentialStateMissing CredentialState = "missing"
	CredentialStateUnknown CredentialState = "unknown"
	CredentialStateValid   CredentialState = "valid"
	CredentialStateInvalid CredentialState = "invalid"
)

func (s CredentialState) String() string {
	return string(s)
}

func ParseCredentialState(v string) (CredentialState, error) {
	switch strings.ToLower(v) {
	case "missing":
		return CredentialStateMissing, nil
	case "unknown":
		return CredentialStateUnknown, nil
	case "valid":
		return CredentialStateValid, nil
	case "invalid":
		return CredentialStateInvalid, nil
	default:
		return CredentialStateInvalid, ErrInvalidCredentialState
	}
}

// DeploymentTLS holds client TLS configuration for the coder binary.
type DeploymentTLS struct {
	CAFile   string
	CertFile string
	KeyFile  string
}

// DeploymentNetwork holds network proxy configuration.
type DeploymentNetwork struct {
	Proxy   string
	NoProxy string
	// DisableNetworkTelemetry controls the CODER_DISABLE_NETWORK_TELEMETRY env var.
	DisableNetworkTelemetry bool
}

type Deployment struct {
	ID           uuid.UUID
	CoderURL     *url.URL
	TargetSuffix string
	CoderBinary  string
	GlobalConfig string
	WorkingDir   string
	Autostart    bool
	WaitMode     string
	TLS          DeploymentTLS
	Network      DeploymentNetwork
}

type Route struct {
	RequestedHost  string
	RequestedPort  uint32
	WorkspaceHost  string
	DisplayTarget  string
}

type CoderIdentity struct {
	ID       uuid.UUID
	Username string
	Status   string
}

type ReplaceCredentialRequest struct {
	AccountID          uuid.UUID
	ExpectedGeneration int64
	Token              []byte
	Identity           CoderIdentity
}
