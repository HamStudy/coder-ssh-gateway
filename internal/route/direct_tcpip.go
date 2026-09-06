package route

import (
	"errors"
	"strings"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

// Stable §44 detail codes carried by Error. Aliased from core so the route
// package never redefines the canonical values.
const (
	codeInvalidPayload = core.ROUTE_INVALID_PAYLOAD
	codePortDenied     = core.ROUTE_PORT_DENIED
	codeNameInvalid    = core.ROUTE_NAME_INVALID
)

// Error is the typed routing error. Code is a stable §44 code suitable for
// audit detail_code; Msg is a static, log-safe description that never
// echoes untrusted input bytes.
type Error struct {
	Code string
	Msg  string
}

func newError(code, msg string) *Error {
	return &Error{Code: code, Msg: msg}
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Msg
}

// CodeOf extracts the stable §44 code from a route error, or "" if err is
// not a route error.
func CodeOf(err error) string {
	var re *Error
	if errors.As(err, &re) {
		return re.Code
	}
	return ""
}

// RouteCodec decodes and validates a direct-tcpip target per §17.5. It is
// kept separate from SSH handling so another syntax (e.g. Coder's
// owner--workspace--agent) can be added later without touching
// authentication or process supervision. Route is core.Route.
type RouteCodec interface {
	ParseDirectTCPIP(host string, port uint32) (core.Route, error)
}

var _ RouteCodec = (*Codec)(nil)

// Codec validates bare Coder workspace targets for one deployment.
type Codec struct{}

// NewCodec returns the strict bare-target codec.
func NewCodec() *Codec { return &Codec{} }

// ParseDirectTCPIP validates a direct-tcpip target per §17.4 and returns
// the route per §17.5. The originator fields of the direct-tcpip payload
// are never accepted here and must never be used for authorization.
//
// WorkspaceHost is the normalized bare target passed verbatim to Coder.
// DisplayTarget is a safe loggable form: the strict grammar guarantees
// lowercase ASCII [a-z0-9./-] only.
func (c *Codec) ParseDirectTCPIP(host string, port uint32) (core.Route, error) {
	if port != 22 {
		return core.Route{}, newError(codePortDenied, "target port must be 22")
	}
	route, err := ParseBareTarget(host)
	if err != nil {
		return core.Route{}, err
	}
	route.RequestedPort = port
	return route, nil
}

// ParseBareTarget validates a bare Coder target shared by session-ready and
// direct-tcpip routing. Two families are accepted, mirroring what the Coder
// CLI resolves:
//
//   - dotted: 1-3 strict DNS labels (workspace, workspace.agent,
//     agent.workspace.owner)
//   - slashed: owner/workspace or owner/workspace/agent, each part a strict
//     DNS label (the cross-user form; dots may not be mixed with slashes)
func ParseBareTarget(target string) (core.Route, error) {
	h, err := normalizeHostname(target)
	if err != nil {
		return core.Route{}, err
	}
	if len(h) > maxHostnameBytes {
		return core.Route{}, newError(codeNameInvalid, "target exceeds 253 bytes")
	}
	if strings.Contains(h, "/") {
		parts := strings.Split(h, "/")
		if len(parts) < 2 || len(parts) > 3 {
			return core.Route{}, newError(codeNameInvalid, "owner/workspace target requires 2-3 slash-separated labels")
		}
		for _, part := range parts {
			if !validLabel(part) {
				return core.Route{}, newError(codeNameInvalid, "invalid label in target")
			}
		}
		return core.Route{
			RequestedHost: target,
			WorkspaceHost: h,
			DisplayTarget: h,
		}, nil
	}
	labels := strings.Split(h, ".")
	if len(labels) > maxRouteLabels {
		return core.Route{}, newError(codeNameInvalid, "target requires 1-3 labels")
	}
	for _, label := range labels {
		if !validLabel(label) {
			return core.Route{}, newError(codeNameInvalid, "invalid label in target")
		}
	}
	return core.Route{
		RequestedHost: target,
		WorkspaceHost: h,
		DisplayTarget: h,
	}, nil
}
