package sshauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

const (
	PermissionMode                 = "gateway.mode"
	PermissionAccountID            = "gateway.account_id"
	PermissionDeploymentID         = "gateway.deployment_id"
	PermissionSSHKeyID             = "gateway.ssh_key_id"
	PermissionCredentialGeneration = "gateway.credential_generation"
	PermissionMustReconnect        = "gateway.must_reconnect"
	// PermissionEnrollmentKeyDigest carries the sha256 hex digest of the
	// proven public key through the enrollment candidate stage (CD-2). No
	// account/key UUIDs exist yet at that point.
	PermissionEnrollmentKeyDigest = "gateway.enrollment_key_digest"
)

const (
	ModeCandidate = "candidate"
	ModeTransport = "transport"
	// ModeWorkspace is an authenticated direct workspace session. Its target
	// comes from the outer SSH username and is parsed only after key proof.
	ModeWorkspace = "workspace"
	// ModeEnrollment marks candidate permissions for the login@ self-
	// enrollment flow (CD-2): the key is not (yet) linked to any account.
	ModeEnrollment = "enrollment"
)

type CandidatePerms struct {
	Mode      string
	AccountID uuid.UUID
	SSHKeyID  uuid.UUID
}

type FinalPerms struct {
	Mode                 string
	AccountID            uuid.UUID
	DeploymentID         uuid.UUID
	SSHKeyID             uuid.UUID
	CredentialGeneration int64
	MustReconnect        bool
}

// EnrollmentCandidatePerms is the parsed form of enrollment-mode candidate
// permissions: the proven key's digest and nothing else.
type EnrollmentCandidatePerms struct {
	Mode      string
	KeyDigest string
}

func CandidatePermissions(accountID, keyID uuid.UUID) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			PermissionMode:      ModeCandidate,
			PermissionAccountID: accountID.String(),
			PermissionSSHKeyID:  keyID.String(),
		},
	}
}

// EnrollmentCandidatePermissions builds candidate permissions for the login@
// self-enrollment flow: mode=enrollment plus the proven key's digest. There
// are deliberately no account/key UUIDs — they do not exist yet.
func EnrollmentCandidatePermissions(keyDigestHex string) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			PermissionMode:                ModeEnrollment,
			PermissionEnrollmentKeyDigest: keyDigestHex,
		},
	}
}

// FinalWorkspacePermissions records an authenticated workspace-session mode.
// The route itself is intentionally not copied into Permissions: it remains
// the SSH username and is parsed after authentication by the server.
func FinalWorkspacePermissions(accountID, deploymentID, keyID uuid.UUID, generation int64) *ssh.Permissions {
	return finalWorkspacePermissions(ModeWorkspace, accountID, deploymentID, keyID, generation, false)
}

// FinalEnrollmentPermissions authenticates a completed enrollment. The
// connection has no workspace target (the outer username was the
// enrollment name), so it is flagged for immediate close (§13.6) instead
// of entering the channel dispatch.
func FinalEnrollmentPermissions(accountID, deploymentID, keyID uuid.UUID, generation int64) *ssh.Permissions {
	return finalWorkspacePermissions(ModeWorkspace, accountID, deploymentID, keyID, generation, true)
}

func finalWorkspacePermissions(mode string, accountID, deploymentID, keyID uuid.UUID, generation int64, mustReconnect bool) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			PermissionMode:                 mode,
			PermissionAccountID:            accountID.String(),
			PermissionDeploymentID:         deploymentID.String(),
			PermissionSSHKeyID:             keyID.String(),
			PermissionCredentialGeneration: strconv.FormatInt(generation, 10),
			PermissionMustReconnect:        strconv.FormatBool(mustReconnect),
		},
	}
}

var (
	ErrInvalidMode          = errors.New("invalid gateway mode")
	ErrMissingAccountID     = errors.New("missing account_id")
	ErrInvalidAccountID     = errors.New("invalid account_id")
	ErrZeroAccountID        = errors.New("account_id is zero")
	ErrMissingDeploymentID  = errors.New("missing deployment_id")
	ErrInvalidDeploymentID  = errors.New("invalid deployment_id")
	ErrZeroDeploymentID     = errors.New("deployment_id is zero")
	ErrMissingSSHKeyID      = errors.New("missing ssh_key_id")
	ErrInvalidSSHKeyID      = errors.New("invalid ssh_key_id")
	ErrZeroSSHKeyID         = errors.New("ssh_key_id is zero")
	ErrMissingGeneration    = errors.New("missing credential_generation")
	ErrInvalidGeneration    = errors.New("invalid credential_generation")
	ErrNegativeGeneration   = errors.New("credential_generation is negative")
	ErrInvalidMustReconnect = errors.New("invalid must_reconnect")
	ErrUnknownExtension     = errors.New("unknown extension key")

	ErrMissingEnrollmentKeyDigest = errors.New("missing enrollment_key_digest")
	ErrInvalidEnrollmentKeyDigest = errors.New("invalid enrollment_key_digest")
)

func ParseFinalPermissions(perms *ssh.Permissions) (FinalPerms, error) {
	if perms == nil || perms.Extensions == nil {
		return FinalPerms{}, ErrMissingAccountID
	}

	ext := perms.Extensions

	mode := ext[PermissionMode]
	if mode != ModeWorkspace {
		return FinalPerms{}, fmt.Errorf("%w: %q", ErrInvalidMode, mode)
	}

	accountIDStr := ext[PermissionAccountID]
	if accountIDStr == "" {
		return FinalPerms{}, ErrMissingAccountID
	}
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		return FinalPerms{}, fmt.Errorf("%w: %q", ErrInvalidAccountID, accountIDStr)
	}
	if accountID == uuid.Nil {
		return FinalPerms{}, ErrZeroAccountID
	}

	sshKeyIDStr := ext[PermissionSSHKeyID]
	if sshKeyIDStr == "" {
		return FinalPerms{}, ErrMissingSSHKeyID
	}
	sshKeyID, err := uuid.Parse(sshKeyIDStr)
	if err != nil {
		return FinalPerms{}, fmt.Errorf("%w: %q", ErrInvalidSSHKeyID, sshKeyIDStr)
	}
	if sshKeyID == uuid.Nil {
		return FinalPerms{}, ErrZeroSSHKeyID
	}

	var deploymentID uuid.UUID
	if didStr := ext[PermissionDeploymentID]; didStr != "" {
		if deploymentID, err = uuid.Parse(didStr); err != nil {
			return FinalPerms{}, fmt.Errorf("%w: %q", ErrInvalidDeploymentID, didStr)
		}
		if deploymentID == uuid.Nil {
			return FinalPerms{}, ErrZeroDeploymentID
		}
	} else if mode == ModeTransport || mode == ModeWorkspace {
		return FinalPerms{}, ErrMissingDeploymentID
	}

	var generation int64
	genStr := ext[PermissionCredentialGeneration]
	if genStr != "" {
		generation, err = strconv.ParseInt(genStr, 10, 64)
		if err != nil {
			return FinalPerms{}, fmt.Errorf("%w: %q", ErrInvalidGeneration, genStr)
		}
		if generation < 0 {
			return FinalPerms{}, ErrNegativeGeneration
		}
	}

	var mustReconnect bool
	mrStr := ext[PermissionMustReconnect]
	if mrStr != "" {
		mustReconnect, err = strconv.ParseBool(mrStr)
		if err != nil {
			return FinalPerms{}, fmt.Errorf("%w: %q", ErrInvalidMustReconnect, mrStr)
		}
	}

	for key := range ext {
		switch key {
		case PermissionMode, PermissionAccountID, PermissionDeploymentID,
			PermissionSSHKeyID, PermissionCredentialGeneration, PermissionMustReconnect:
		default:
			return FinalPerms{}, fmt.Errorf("%w: %q", ErrUnknownExtension, key)
		}
	}

	return FinalPerms{
		Mode:                 mode,
		AccountID:            accountID,
		DeploymentID:         deploymentID,
		SSHKeyID:             sshKeyID,
		CredentialGeneration: generation,
		MustReconnect:        mustReconnect,
	}, nil
}

func ParseCandidatePermissions(perms *ssh.Permissions) (CandidatePerms, error) {
	if perms == nil || perms.Extensions == nil {
		return CandidatePerms{}, ErrMissingAccountID
	}

	ext := perms.Extensions

	mode := ext[PermissionMode]
	if mode != ModeCandidate {
		return CandidatePerms{}, fmt.Errorf("%w: %q", ErrInvalidMode, mode)
	}

	accountIDStr := ext[PermissionAccountID]
	if accountIDStr == "" {
		return CandidatePerms{}, ErrMissingAccountID
	}
	accountID, err := uuid.Parse(accountIDStr)
	if err != nil {
		return CandidatePerms{}, fmt.Errorf("%w: %q", ErrInvalidAccountID, accountIDStr)
	}
	if accountID == uuid.Nil {
		return CandidatePerms{}, ErrZeroAccountID
	}

	sshKeyIDStr := ext[PermissionSSHKeyID]
	if sshKeyIDStr == "" {
		return CandidatePerms{}, ErrMissingSSHKeyID
	}
	sshKeyID, err := uuid.Parse(sshKeyIDStr)
	if err != nil {
		return CandidatePerms{}, fmt.Errorf("%w: %q", ErrInvalidSSHKeyID, sshKeyIDStr)
	}
	if sshKeyID == uuid.Nil {
		return CandidatePerms{}, ErrZeroSSHKeyID
	}

	for key := range ext {
		switch key {
		case PermissionMode, PermissionAccountID, PermissionSSHKeyID:
		default:
			return CandidatePerms{}, fmt.Errorf("%w: %q", ErrUnknownExtension, key)
		}
	}

	return CandidatePerms{
		Mode:      mode,
		AccountID: accountID,
		SSHKeyID:  sshKeyID,
	}, nil
}

// ParseEnrollmentCandidatePermissions validates enrollment-mode candidate
// permissions: exactly mode + a 64-char lowercase-hex sha256 digest, no
// other extensions.
func ParseEnrollmentCandidatePermissions(perms *ssh.Permissions) (EnrollmentCandidatePerms, error) {
	if perms == nil || perms.Extensions == nil {
		return EnrollmentCandidatePerms{}, ErrMissingEnrollmentKeyDigest
	}

	ext := perms.Extensions

	mode := ext[PermissionMode]
	if mode != ModeEnrollment {
		return EnrollmentCandidatePerms{}, fmt.Errorf("%w: %q", ErrInvalidMode, mode)
	}

	digest := ext[PermissionEnrollmentKeyDigest]
	if digest == "" {
		return EnrollmentCandidatePerms{}, ErrMissingEnrollmentKeyDigest
	}
	if len(digest) != sha256.Size*2 || digest != strings.ToLower(digest) {
		return EnrollmentCandidatePerms{}, fmt.Errorf("%w: %q", ErrInvalidEnrollmentKeyDigest, digest)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return EnrollmentCandidatePerms{}, fmt.Errorf("%w: %q", ErrInvalidEnrollmentKeyDigest, digest)
	}

	for key := range ext {
		switch key {
		case PermissionMode, PermissionEnrollmentKeyDigest:
		default:
			return EnrollmentCandidatePerms{}, fmt.Errorf("%w: %q", ErrUnknownExtension, key)
		}
	}

	return EnrollmentCandidatePerms{Mode: mode, KeyDigest: digest}, nil
}
