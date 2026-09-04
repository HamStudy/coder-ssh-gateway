package route

import (
	"errors"
	"strings"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
)

// Stable §44 detail codes carried by Error. Aliased from core so the route
// package never redefines the canonical values.
const (
	codeInvalidPayload = core.ROUTE_INVALID_PAYLOAD
	codeSuffixDenied   = core.ROUTE_SUFFIX_DENIED
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

// Codec is the hostname-suffix RouteCodec for one deployment.
type Codec struct {
	suffix string
}

// NewCodec validates suffix with the strict label grammar (§17.4) and
// requires at least two labels.
func NewCodec(suffix string) (*Codec, error) {
	s, err := normalizeSuffix(suffix)
	if err != nil {
		return nil, err
	}
	return &Codec{suffix: s}, nil
}

// Suffix returns the normalized configured target suffix.
func (c *Codec) Suffix() string {
	return c.suffix
}

// ParseDirectTCPIP validates a direct-tcpip target per §17.4 and returns
// the route per §17.5. The originator fields of the direct-tcpip payload
// are never accepted here and must never be used for authorization.
//
// WorkspaceHost is the full normalized target passed verbatim to
// `coder ssh --hostname-suffix` (§17.3 — Coder normalizes workspace
// semantics, the gateway does not). DisplayTarget is a safe loggable form:
// the strict grammar guarantees lowercase ASCII [a-z0-9.-] only.
func (c *Codec) ParseDirectTCPIP(host string, port uint32) (core.Route, error) {
	if port != 22 {
		return core.Route{}, newError(codePortDenied, "target port must be 22")
	}
	h, err := normalizeHostname(host)
	if err != nil {
		return core.Route{}, err
	}
	if len(h) > maxHostnameBytes {
		return core.Route{}, newError(codeNameInvalid, "hostname exceeds 253 bytes")
	}
	// Exact suffix match on a DNS-label boundary (§17.4): "xcoder-gateway..."
	// and "...ham.dev.evil.com" must both be denied.
	switch {
	case len(h) > len(c.suffix) && strings.HasSuffix(h, c.suffix) && h[len(h)-len(c.suffix)-1] == '.':
		// ok
	case h == c.suffix:
		return core.Route{}, newError(codeNameInvalid, "no labels before target suffix")
	default:
		return core.Route{}, newError(codeSuffixDenied, "host is not under the configured target suffix")
	}
	labels := strings.Split(h[:len(h)-len(c.suffix)-1], ".")
	if len(labels) > maxRouteLabels {
		return core.Route{}, newError(codeNameInvalid, "requires 1-3 labels before target suffix")
	}
	for _, l := range labels {
		if !validLabel(l) {
			return core.Route{}, newError(codeNameInvalid, "invalid label in target hostname")
		}
	}
	return core.Route{
		RequestedHost: host,
		RequestedPort: port,
		WorkspaceHost: h,
		DisplayTarget: h,
	}, nil
}
