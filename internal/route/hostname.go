// Package route implements strict validation of direct-tcpip targets per
// design §17: the gateway accepts only hostnames under the configured
// target suffix, on port 22, with 1-3 DNS labels before the suffix.
//
// Route forms (§17.2) — labels before the suffix:
//
//	1 label:  workspace                  (current user's workspace)
//	2 labels: workspace.agent            (current user's named agent)
//	3 labels: agent.workspace.owner      (explicit owner/workspace/agent)
//
// There is deliberately no two-label workspace.owner form; Coder interprets
// two dot-separated labels as workspace.agent. The gateway never re-parses
// workspace semantics (§17.3): the full normalized target is passed to
// `coder ssh --hostname-suffix` and Coder performs final normalization.
package route

import (
	"fmt"
	"strings"
)

const (
	maxHostnameBytes = 253
	maxLabelBytes    = 63
	maxRouteLabels   = 3
	minSuffixLabels  = 2
)

// normalizeHostname strips one optional trailing root dot, verifies the
// input is pure ASCII, and lowercases it (§17.4). Unicode is rejected
// outright rather than folded. Empty input (or a lone root dot) is a
// malformed payload, not an invalid name.
func normalizeHostname(host string) (string, error) {
	if host == "" {
		return "", newError(codeInvalidPayload, "empty host")
	}
	h := strings.TrimSuffix(host, ".")
	if h == "" {
		return "", newError(codeInvalidPayload, "empty host after root-dot normalization")
	}
	for i := 0; i < len(h); i++ {
		if h[i] > 0x7f {
			return "", newError(codeNameInvalid, "non-ASCII byte in hostname")
		}
	}
	return strings.ToLower(h), nil
}

// validLabel enforces the §17.4 label grammar
// [a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])? plus the punycode ban. The grammar
// itself rejects leading/trailing hyphens, whitespace, control characters,
// NUL, wildcards, and every non-[a-z0-9-] byte.
func validLabel(label string) bool {
	if len(label) == 0 || len(label) > maxLabelBytes {
		return false
	}
	// Reject punycode (xn--) unless consciously supported later (§17.4).
	if strings.HasPrefix(label, "xn--") {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		b := label[i]
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' {
			continue
		}
		return false
	}
	return true
}

// normalizeSuffix validates a configured target suffix with the same
// grammar as route labels and requires at least two labels (a bare TLD
// would match far too broadly). Used by NewCodec.
func normalizeSuffix(suffix string) (string, error) {
	s, err := normalizeHostname(suffix)
	if err != nil {
		return "", fmt.Errorf("invalid target suffix: %v", err)
	}
	if len(s) > maxHostnameBytes {
		return "", fmt.Errorf("invalid target suffix: exceeds %d bytes", maxHostnameBytes)
	}
	labels := strings.Split(s, ".")
	if len(labels) < minSuffixLabels {
		return "", fmt.Errorf("invalid target suffix %q: requires at least %d labels", s, minSuffixLabels)
	}
	for _, l := range labels {
		if !validLabel(l) {
			return "", fmt.Errorf("invalid target suffix %q: bad label %q", s, l)
		}
	}
	return s, nil
}
