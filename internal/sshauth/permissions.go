package sshauth

import (
	"errors"
	"fmt"
	"strconv"

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
)

const (
	ModeCandidate   = "candidate"
	ModeTransport   = "transport"
	ModeMaintenance = "maintenance"
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

func CandidatePermissions(accountID, keyID uuid.UUID) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			PermissionMode:      ModeCandidate,
			PermissionAccountID: accountID.String(),
			PermissionSSHKeyID:  keyID.String(),
		},
	}
}

func FinalTransportPermissions(accountID, keyID uuid.UUID, generation int64, mustReconnect bool) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			PermissionMode:                  ModeTransport,
			PermissionAccountID:             accountID.String(),
			PermissionSSHKeyID:              keyID.String(),
			PermissionCredentialGeneration:   strconv.FormatInt(generation, 10),
			PermissionMustReconnect:         strconv.FormatBool(mustReconnect),
		},
	}
}

func FinalMaintenancePermissions(accountID, keyID uuid.UUID) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			PermissionMode:      ModeMaintenance,
			PermissionAccountID: accountID.String(),
			PermissionSSHKeyID:  keyID.String(),
		},
	}
}

var (
	ErrInvalidMode            = errors.New("invalid gateway mode")
	ErrMissingAccountID       = errors.New("missing account_id")
	ErrInvalidAccountID       = errors.New("invalid account_id")
	ErrZeroAccountID          = errors.New("account_id is zero")
	ErrMissingSSHKeyID        = errors.New("missing ssh_key_id")
	ErrInvalidSSHKeyID        = errors.New("invalid ssh_key_id")
	ErrZeroSSHKeyID           = errors.New("ssh_key_id is zero")
	ErrMissingGeneration      = errors.New("missing credential_generation")
	ErrInvalidGeneration      = errors.New("invalid credential_generation")
	ErrNegativeGeneration     = errors.New("credential_generation is negative")
	ErrInvalidMustReconnect   = errors.New("invalid must_reconnect")
	ErrUnknownExtension       = errors.New("unknown extension key")
)

func ParseFinalPermissions(perms *ssh.Permissions) (FinalPerms, error) {
	if perms == nil || perms.Extensions == nil {
		return FinalPerms{}, ErrMissingAccountID
	}

	ext := perms.Extensions

	mode := ext[PermissionMode]
	if mode != ModeTransport && mode != ModeMaintenance {
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
			return FinalPerms{}, fmt.Errorf("invalid deployment_id: %w", err)
		}
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
