package route

import (
	"strings"
	"testing"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
)

// testSuffix is the deployment target suffix used across the route tests.
const testSuffix = "coder-gateway.example.com"

// longSuffix is a 190-byte, 3-label suffix used to reach the 253/254-byte
// whole-hostname boundary (3 labels of 63 bytes + suffix cannot reach 253
// with testSuffix, so a longer suffix is required).
var longSuffix = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 62)

// host253 is a 253-byte hostname (62-byte label + "." + 190-byte suffix).
var host253 = strings.Repeat("d", 62) + "." + longSuffix

// host254 is a 254-byte hostname (63-byte label + "." + 190-byte suffix).
var host254 = strings.Repeat("d", 63) + "." + longSuffix

func mustCodec(t *testing.T, suffix string) *Codec {
	t.Helper()
	c, err := NewCodec(suffix)
	if err != nil {
		t.Fatalf("NewCodec(%q): %v", suffix, err)
	}
	return c
}

// TestParseValidRoutes covers the §38.1 acceptance cases: every valid route
// form must parse and produce a normalized WorkspaceHost per §17.2/§17.4.
func TestParseValidRoutes(t *testing.T) {
	c := mustCodec(t, testSuffix)

	cases := []struct {
		name              string
		host              string
		port              uint32
		wantWorkspaceHost string
	}{
		{
			name:              "valid one-label workspace",
			host:              "dev.coder-gateway.example.com",
			port:              22,
			wantWorkspaceHost: "dev.coder-gateway.example.com",
		},
		{
			name:              "valid workspace.agent",
			host:              "dev.main.coder-gateway.example.com",
			port:              22,
			wantWorkspaceHost: "dev.main.coder-gateway.example.com",
		},
		{
			name:              "valid agent.workspace.owner",
			host:              "main.dev.taxilian.coder-gateway.example.com",
			port:              22,
			wantWorkspaceHost: "main.dev.taxilian.coder-gateway.example.com",
		},
		{
			name:              "upper-case normalization",
			host:              "MAIN.DEV.TAXILIAN.CODER-GATEWAY.HAM.DEV",
			port:              22,
			wantWorkspaceHost: "main.dev.taxilian.coder-gateway.example.com",
		},
		{
			name:              "optional trailing dot",
			host:              "dev.coder-gateway.example.com.",
			port:              22,
			wantWorkspaceHost: "dev.coder-gateway.example.com",
		},
		{
			name:              "exact suffix boundary",
			host:              "a.coder-gateway.example.com",
			port:              22,
			wantWorkspaceHost: "a.coder-gateway.example.com",
		},
		{
			name:              "single-char labels",
			host:              "a.b.c.coder-gateway.example.com",
			port:              22,
			wantWorkspaceHost: "a.b.c.coder-gateway.example.com",
		},
		{
			name:              "digits and internal hyphens",
			host:              "ws-1.ag-ent.0wner9.coder-gateway.example.com",
			port:              22,
			wantWorkspaceHost: "ws-1.ag-ent.0wner9.coder-gateway.example.com",
		},
		{
			name:              "label length 63",
			host:              strings.Repeat("a", 63) + ".coder-gateway.example.com",
			port:              22,
			wantWorkspaceHost: strings.Repeat("a", 63) + ".coder-gateway.example.com",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := c.ParseDirectTCPIP(tc.host, tc.port)
			if err != nil {
				t.Fatalf("ParseDirectTCPIP(%q, %d): %v", tc.host, tc.port, err)
			}
			if r.RequestedHost != tc.host {
				t.Errorf("RequestedHost = %q, want original %q", r.RequestedHost, tc.host)
			}
			if r.RequestedPort != tc.port {
				t.Errorf("RequestedPort = %d, want %d", r.RequestedPort, tc.port)
			}
			if r.WorkspaceHost != tc.wantWorkspaceHost {
				t.Errorf("WorkspaceHost = %q, want %q", r.WorkspaceHost, tc.wantWorkspaceHost)
			}
			// DisplayTarget must be a safe loggable form: the strict
			// grammar guarantees lowercase ASCII [a-z0-9.-] only.
			for i := 0; i < len(r.DisplayTarget); i++ {
				b := r.DisplayTarget[i]
				ok := (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '.' || b == '-'
				if !ok {
					t.Errorf("DisplayTarget %q contains unsafe byte %#x", r.DisplayTarget, b)
				}
			}
		})
	}
}

// TestParseHostLengthBoundary covers §38.1 "host length 253/254" using a
// suffix long enough to actually reach the whole-hostname limit.
func TestParseHostLengthBoundary(t *testing.T) {
	c := mustCodec(t, longSuffix)

	t.Run("host length 253 accepted", func(t *testing.T) {
		if len(host253) != 253 {
			t.Fatalf("fixture length = %d, want 253", len(host253))
		}
		r, err := c.ParseDirectTCPIP(host253, 22)
		if err != nil {
			t.Fatalf("ParseDirectTCPIP(253-byte host): %v", err)
		}
		if r.WorkspaceHost != host253 {
			t.Errorf("WorkspaceHost = %q, want %q", r.WorkspaceHost, host253)
		}
	})

	t.Run("host length 254 rejected", func(t *testing.T) {
		if len(host254) != 254 {
			t.Fatalf("fixture length = %d, want 254", len(host254))
		}
		_, err := c.ParseDirectTCPIP(host254, 22)
		if CodeOf(err) != core.ROUTE_NAME_INVALID {
			t.Fatalf("code = %q, want %q (err=%v)", CodeOf(err), core.ROUTE_NAME_INVALID, err)
		}
	})
}

// TestParseRejectRoutes covers every §38.1 rejection bullet and asserts the
// stable §44 detail code carried by the typed error.
func TestParseRejectRoutes(t *testing.T) {
	c := mustCodec(t, testSuffix)

	cases := []struct {
		name     string
		host     string
		port     uint32
		wantCode string
	}{
		// Suffix lookalikes: the suffix string appears but not on a
		// DNS-label boundary, or not at the end of the hostname.
		{"suffix lookalike merged label", "xcoder-gateway.example.com", 22, core.ROUTE_SUFFIX_DENIED},
		{"suffix lookalike under attacker domain", "coder-gateway.example.com.evil.com", 22, core.ROUTE_SUFFIX_DENIED},
		{"suffix lookalike deeper valid tree", "dev.coder-gateway.example.com.evil.com", 22, core.ROUTE_SUFFIX_DENIED},
		{"double trailing root dot", "dev.coder-gateway.example.com..", 22, core.ROUTE_SUFFIX_DENIED},

		// Label-count and label-shape violations.
		{"missing labels before suffix", "coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"empty label interior", "dev..coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"empty label leading", ".dev.coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"too many labels before suffix", "a.b.c.d.coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"label length 64", strings.Repeat("a", 64) + ".coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"leading hyphen", "-dev.coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"trailing hyphen", "dev-.coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"leading dash flag-like value", "--stdio.coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},

		// Character-set violations.
		{"unicode label", "dév.coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"unicode uppercase", "DÉV.coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"punycode label", "xn--nxasmq6b.coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"embedded NUL", "dev\x00.coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"control character", "dev\x01.coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"whitespace", "dev .coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"wildcard", "*.coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},

		// IP literals are never valid workspace targets.
		{"ipv4 literal", "127.0.0.1", 22, core.ROUTE_SUFFIX_DENIED},
		{"ipv4 literal under suffix", "10.0.0.1.coder-gateway.example.com", 22, core.ROUTE_NAME_INVALID},
		{"ipv6 loopback", "::1", 22, core.ROUTE_SUFFIX_DENIED},
		{"ipv6 loopback bracketed", "[::1]", 22, core.ROUTE_SUFFIX_DENIED},

		// Destination ports other than 22.
		{"port zero", "dev.coder-gateway.example.com", 0, core.ROUTE_PORT_DENIED},
		{"port 2222", "dev.coder-gateway.example.com", 2222, core.ROUTE_PORT_DENIED},
		{"port 65535", "dev.coder-gateway.example.com", 65535, core.ROUTE_PORT_DENIED},
		{"port 65536", "dev.coder-gateway.example.com", 65536, core.ROUTE_PORT_DENIED},

		// Malformed payload.
		{"empty host", "", 22, core.ROUTE_INVALID_PAYLOAD},
		{"root dot only", ".", 22, core.ROUTE_INVALID_PAYLOAD},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.ParseDirectTCPIP(tc.host, tc.port)
			if err == nil {
				t.Fatalf("ParseDirectTCPIP(%q, %d): expected error, got nil", tc.host, tc.port)
			}
			if got := CodeOf(err); got != tc.wantCode {
				t.Errorf("code = %q, want %q (err=%v)", got, tc.wantCode, err)
			}
		})
	}
}

// TestParseSuffixNotConfigured verifies that targets under a suffix the
// codec was not configured with are denied (§38.1 "suffix not configured").
func TestParseSuffixNotConfigured(t *testing.T) {
	c := mustCodec(t, "other-gateway.example.com")
	_, err := c.ParseDirectTCPIP("dev.coder-gateway.example.com", 22)
	if CodeOf(err) != core.ROUTE_SUFFIX_DENIED {
		t.Fatalf("code = %q, want %q (err=%v)", CodeOf(err), core.ROUTE_SUFFIX_DENIED, err)
	}
}

// TestNewCodecValidation verifies the constructor validates the suffix with
// the same strict grammar and requires at least two labels.
func TestNewCodecValidation(t *testing.T) {
	t.Run("valid suffix", func(t *testing.T) {
		c, err := NewCodec("coder-gateway.example.com")
		if err != nil {
			t.Fatalf("NewCodec: %v", err)
		}
		if c.Suffix() != "coder-gateway.example.com" {
			t.Errorf("Suffix() = %q", c.Suffix())
		}
	})

	t.Run("uppercase suffix normalized", func(t *testing.T) {
		c, err := NewCodec("CODER-GATEWAY.HAM.DEV")
		if err != nil {
			t.Fatalf("NewCodec: %v", err)
		}
		if c.Suffix() != "coder-gateway.example.com" {
			t.Errorf("Suffix() = %q, want lowercase", c.Suffix())
		}
	})

	t.Run("trailing dot stripped", func(t *testing.T) {
		c, err := NewCodec("coder-gateway.example.com.")
		if err != nil {
			t.Fatalf("NewCodec: %v", err)
		}
		if c.Suffix() != "coder-gateway.example.com" {
			t.Errorf("Suffix() = %q", c.Suffix())
		}
	})

	invalid := []struct {
		name   string
		suffix string
	}{
		{"empty", ""},
		{"single label", "localhost"},
		{"leading hyphen label", "-bad.example.com"},
		{"trailing hyphen label", "bad-.example.com"},
		{"empty label", "coder..example.com"},
		{"label too long", strings.Repeat("a", 64) + ".example.com"},
		{"unicode", "dév.example.com"},
		{"punycode", "xn--nxasmq6b.example.com"},
		{"wildcard", "*.example.com"},
		{"too long", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63)},
	}
	for _, tc := range invalid {
		t.Run("reject "+tc.name, func(t *testing.T) {
			if _, err := NewCodec(tc.suffix); err == nil {
				t.Fatalf("NewCodec(%q): expected error, got nil", tc.suffix)
			}
		})
	}
}
