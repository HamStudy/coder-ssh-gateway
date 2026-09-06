package coderapi

import (
	"errors"
	"fmt"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

// errRedirect signals a refused redirect (fail-closed per §11.2/§11.4).
var errRedirect = errors.New("redirects refused")

// redirectError is the typed fail-closed error returned by CheckRedirect.
func redirectError() *core.CredentialError {
	return credErr(core.ControlPlaneIncompatible, 0, false,
		core.AUTH_CODER_INCOMPATIBLE+":redirect", errRedirect)
}

func credErr(kind core.CredentialErrorKind, httpStatus int, retryable bool, detail string, cause error) *core.CredentialError {
	return &core.CredentialError{
		Kind:       kind,
		HTTPStatus: httpStatus,
		Retryable:  retryable,
		DetailCode: detail,
		Cause:      cause,
	}
}

func classifyStatus(status int) *core.CredentialError {
	switch {
	case status == 401:
		return credErr(core.CredentialInvalid, status, false, core.AUTH_CREDENTIAL_UNAUTHORIZED, nil)
	case status == 403:
		return credErr(core.CredentialForbidden, status, false, core.AUTH_CREDENTIAL_FORBIDDEN, nil)
	case status == 404:
		return credErr(core.ControlPlaneIncompatible, status, false, core.AUTH_CODER_INCOMPATIBLE, nil)
	case status == 429:
		return credErr(core.ControlPlaneUnavailable, status, true, core.AUTH_CODER_UNAVAILABLE, nil)
	case status >= 500 && status <= 599:
		return credErr(core.ControlPlaneUnavailable, status, true, core.AUTH_CODER_UNAVAILABLE, nil)
	default:
		return credErr(core.ControlPlaneIncompatible, status, false, core.AUTH_CODER_INCOMPATIBLE, nil)
	}
}

// classifyTransport maps request-phase failures per §11.4; body bytes and
// tokens are never embedded in the cause.
func classifyTransport(err error) *core.CredentialError {
	var ce *core.CredentialError
	if errors.As(err, &ce) {
		return ce
	}
	return credErr(core.ControlPlaneUnavailable, 0, true, core.AUTH_CODER_UNAVAILABLE,
		fmt.Errorf("control plane request: %w", err))
}

func malformedReply(httpStatus int, cause error) *core.CredentialError {
	return credErr(core.CredentialMalformedReply, httpStatus, false,
		core.AUTH_CODER_INCOMPATIBLE, cause)
}
