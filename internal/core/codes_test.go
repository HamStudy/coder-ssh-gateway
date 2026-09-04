package core_test

import (
	"strings"
	"testing"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
)

func TestDetailCodes(t *testing.T) {
	codes := []string{
		core.AUTH_UNKNOWN_KEY,
		core.AUTH_ACCOUNT_DISABLED,
		core.AUTH_CREDENTIAL_MISSING,
		core.AUTH_CREDENTIAL_UNAUTHORIZED,
		core.AUTH_CREDENTIAL_FORBIDDEN,
		core.AUTH_WRONG_CODER_IDENTITY,
		core.AUTH_CODER_UNAVAILABLE,
		core.AUTH_CODER_INCOMPATIBLE,
		core.ROUTE_INVALID_PAYLOAD,
		core.ROUTE_SUFFIX_DENIED,
		core.ROUTE_PORT_DENIED,
		core.ROUTE_NAME_INVALID,
		core.TUNNEL_LIMIT_REACHED,
		core.TUNNEL_PROCESS_START_FAILED,
		core.TUNNEL_START_TIMEOUT,
		core.TUNNEL_CODER_EXITED,
		core.TUNNEL_STREAM_FAILED,
		core.TUNNEL_CANCELLED,
		core.STORE_UNAVAILABLE,
		core.STORE_GENERATION_CONFLICT,
		core.CRYPTO_KEY_UNAVAILABLE,
		core.CRYPTO_DECRYPT_FAILED,
	}

	seen := make(map[string]bool)
	for _, code := range codes {
		if code == "" {
			t.Error("empty detail code found")
			continue
		}
		if seen[code] {
			t.Errorf("duplicate detail code: %q", code)
		}
		seen[code] = true
	}

	if len(codes) != 22 {
		t.Errorf("expected 22 detail codes, got %d", len(codes))
	}
}

func TestDetailCodeValues(t *testing.T) {
	tests := []struct {
		code    string
		pattern string
	}{
		{core.AUTH_UNKNOWN_KEY, "AUTH_"},
		{core.AUTH_ACCOUNT_DISABLED, "AUTH_"},
		{core.AUTH_CREDENTIAL_MISSING, "AUTH_"},
		{core.AUTH_CREDENTIAL_UNAUTHORIZED, "AUTH_"},
		{core.AUTH_CREDENTIAL_FORBIDDEN, "AUTH_"},
		{core.AUTH_WRONG_CODER_IDENTITY, "AUTH_"},
		{core.AUTH_CODER_UNAVAILABLE, "AUTH_"},
		{core.AUTH_CODER_INCOMPATIBLE, "AUTH_"},
		{core.ROUTE_INVALID_PAYLOAD, "ROUTE_"},
		{core.ROUTE_SUFFIX_DENIED, "ROUTE_"},
		{core.ROUTE_PORT_DENIED, "ROUTE_"},
		{core.ROUTE_NAME_INVALID, "ROUTE_"},
		{core.TUNNEL_LIMIT_REACHED, "TUNNEL_"},
		{core.TUNNEL_PROCESS_START_FAILED, "TUNNEL_"},
		{core.TUNNEL_START_TIMEOUT, "TUNNEL_"},
		{core.TUNNEL_CODER_EXITED, "TUNNEL_"},
		{core.TUNNEL_STREAM_FAILED, "TUNNEL_"},
		{core.TUNNEL_CANCELLED, "TUNNEL_"},
		{core.STORE_UNAVAILABLE, "STORE_"},
		{core.STORE_GENERATION_CONFLICT, "STORE_"},
		{core.CRYPTO_KEY_UNAVAILABLE, "CRYPTO_"},
		{core.CRYPTO_DECRYPT_FAILED, "CRYPTO_"},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			if len(tt.code) < 4 {
				t.Errorf("code %q too short", tt.code)
			}
			if !strings.HasPrefix(tt.code, tt.pattern) {
				t.Errorf("code %q doesn't start with %q", tt.code, tt.pattern)
			}
		})
	}
}
