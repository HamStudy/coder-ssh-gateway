// Package route implements strict validation of Coder workspace targets.
//
// Route forms:
//
//	1 label:  workspace                  (current user's workspace)
//	2 labels: workspace.agent            (current user's named agent)
//	3 labels: agent.workspace.owner      (explicit owner/workspace/agent)
//
// There is deliberately no two-label workspace.owner form; Coder interprets
// two dot-separated labels as workspace.agent. The gateway never re-parses
// workspace semantics: the full normalized target is passed directly to
// Coder, which performs final normalization.
package route

import "strings"

const (
	maxHostnameBytes = 253
	maxLabelBytes    = 63
	maxRouteLabels   = 3
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
