package route

import (
	"regexp"
	"strings"
	"testing"
)

// safeHostRE matches the only charset a successfully parsed WorkspaceHost
// may contain, per §17.4.
var safeHostRE = regexp.MustCompile(`^[a-z0-9.-]+$`)

// FuzzParseDirectTCPIP fuzzes the route codec. Invariants on success:
//   - the accepted port is exactly 22;
//   - WorkspaceHost contains only lowercase ASCII [a-z0-9.-];
//   - WorkspaceHost ends with the configured suffix on a DNS-label boundary.
//
// The CI fuzz-smoke job runs this target for 30s; keep the seed corpus rich
// (it covers every §38.1 route-parser bullet).
func FuzzParseDirectTCPIP(f *testing.F) {
	seeds := []struct {
		host string
		port uint32
	}{
		// Valid forms (§17.2).
		{"dev.coder-gateway.example.com", 22},
		{"dev.main.coder-gateway.example.com", 22},
		{"main.dev.taxilian.coder-gateway.example.com", 22},
		{"MAIN.DEV.TAXILIAN.CODER-GATEWAY.HAM.DEV", 22},
		{"dev.coder-gateway.example.com.", 22},
		{"a.coder-gateway.example.com", 22},
		{"ws-1.ag-ent.0wner9.coder-gateway.example.com", 22},
		{strings.Repeat("a", 63) + ".coder-gateway.example.com", 22},
		// Suffix lookalikes.
		{"xcoder-gateway.example.com", 22},
		{"coder-gateway.example.com.evil.com", 22},
		{"dev.coder-gateway.example.com..", 22},
		// Label violations.
		{"coder-gateway.example.com", 22},
		{"dev..coder-gateway.example.com", 22},
		{".dev.coder-gateway.example.com", 22},
		{"a.b.c.d.coder-gateway.example.com", 22},
		{strings.Repeat("a", 64) + ".coder-gateway.example.com", 22},
		{"-dev.coder-gateway.example.com", 22},
		{"dev-.coder-gateway.example.com", 22},
		{"--stdio.coder-gateway.example.com", 22},
		// Charset violations.
		{"dév.coder-gateway.example.com", 22},
		{"xn--nxasmq6b.coder-gateway.example.com", 22},
		{"dev\x00.coder-gateway.example.com", 22},
		{"dev\x01.coder-gateway.example.com", 22},
		{"dev .coder-gateway.example.com", 22},
		{"*.coder-gateway.example.com", 22},
		// IP literals.
		{"127.0.0.1", 22},
		{"10.0.0.1.coder-gateway.example.com", 22},
		{"::1", 22},
		{"[::1]", 22},
		// Ports.
		{"dev.coder-gateway.example.com", 0},
		{"dev.coder-gateway.example.com", 2222},
		{"dev.coder-gateway.example.com", 65535},
		{"dev.coder-gateway.example.com", 65536},
		// Malformed payloads.
		{"", 22},
		{".", 22},
		{"..", 0},
	}
	for _, s := range seeds {
		f.Add(s.host, s.port)
	}

	c, err := NewCodec(testSuffix)
	if err != nil {
		f.Fatalf("NewCodec: %v", err)
	}

	f.Fuzz(func(t *testing.T, host string, port uint32) {
		r, err := c.ParseDirectTCPIP(host, port)
		if err != nil {
			return
		}
		if r.RequestedPort != 22 {
			t.Fatalf("accepted port %d, want 22", r.RequestedPort)
		}
		if !safeHostRE.MatchString(r.WorkspaceHost) {
			t.Fatalf("WorkspaceHost %q outside safe charset", r.WorkspaceHost)
		}
		if len(r.WorkspaceHost) <= len(testSuffix) ||
			!strings.HasSuffix(r.WorkspaceHost, testSuffix) ||
			r.WorkspaceHost[len(r.WorkspaceHost)-len(testSuffix)-1] != '.' {
			t.Fatalf("WorkspaceHost %q does not end with suffix on a label boundary", r.WorkspaceHost)
		}
	})
}
