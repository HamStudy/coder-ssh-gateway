package core

import (
	"errors"
	"fmt"
)

type CredentialErrorKind string

const (
	CredentialMissing        CredentialErrorKind = "missing"
	CredentialInvalid       CredentialErrorKind = "invalid"
	CredentialForbidden     CredentialErrorKind = "forbidden"
	CredentialWrongIdentity CredentialErrorKind = "wrong_identity"
	CredentialMalformedReply CredentialErrorKind = "malformed_reply"
	ControlPlaneUnavailable  CredentialErrorKind = "control_plane_unavailable"
	ControlPlaneIncompatible CredentialErrorKind = "control_plane_incompatible"
)

func (k CredentialErrorKind) Renewable() bool {
	return k == CredentialMissing || k == CredentialInvalid
}

type CredentialError struct {
	Kind       CredentialErrorKind
	HTTPStatus int
	Retryable  bool
	DetailCode string
	Cause      error
}

func (e *CredentialError) Error() string {
	if e.DetailCode != "" {
		return fmt.Sprintf("%s (%s)", e.Kind, e.DetailCode)
	}
	return string(e.Kind)
}

func (e *CredentialError) Unwrap() error {
	return e.Cause
}

func KindOf(err error) CredentialErrorKind {
	var ce *CredentialError
	if errors.As(err, &ce) {
		return ce.Kind
	}
	return ""
}

var ErrInvalidCredentialState = errors.New("invalid credential state")
