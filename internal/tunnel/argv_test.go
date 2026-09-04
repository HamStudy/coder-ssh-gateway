package tunnel_test

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/tunnel"
)

var targetGrammar = regexp.MustCompile(`^[a-z0-9.-]+$`)

func testDeployment(t *testing.T) core.Deployment {
	t.Helper()
	u, err := url.Parse("https://coder.example.com")
	if err != nil {
		t.Fatalf("parse coder URL: %v", err)
	}
	return core.Deployment{
		ID:           uuid.New(),
		CoderURL:     u,
		TargetSuffix: "coder-gateway.example.com",
		CoderBinary:  "/usr/local/bin/coder",
		GlobalConfig: "/var/lib/coder-ssh-gateway/coder-config",
		WorkingDir:   "/var/empty/coder-ssh-gateway",
		Autostart:    true,
		WaitMode:     "auto",
	}
}

func testRoute(host string) core.Route {
	return core.Route{
		RequestedHost: host,
		RequestedPort: 22,
		WorkspaceHost: host,
		DisplayTarget: host + ":22",
	}
}

// TestBuildArgv pins the EXACT §18.2 process form: element order, the
// --wait=<mode> encoding, and the conditional --disable-autostart flag.
func TestBuildArgv(t *testing.T) {
	tests := []struct {
		name      string
		autostart bool
		waitMode  string
		target    string
		want      []string
	}{
		{
			name:      "autostart on, wait auto",
			autostart: true,
			waitMode:  "auto",
			target:    "examtools-docs.coder-gateway.example.com",
			want: []string{
				"--global-config", "/var/lib/coder-ssh-gateway/coder-config",
				"ssh",
				"--stdio",
				"--hostname-suffix", "coder-gateway.example.com",
				"--wait=auto",
				"examtools-docs.coder-gateway.example.com",
			},
		},
		{
			name:      "autostart off, wait yes",
			autostart: false,
			waitMode:  "yes",
			target:    "general.coder-gateway.example.com",
			want: []string{
				"--global-config", "/var/lib/coder-ssh-gateway/coder-config",
				"ssh",
				"--stdio",
				"--hostname-suffix", "coder-gateway.example.com",
				"--wait=yes",
				"--disable-autostart=true",
				"general.coder-gateway.example.com",
			},
		},
		{
			name:      "autostart on, wait no",
			autostart: true,
			waitMode:  "no",
			target:    "w.coder-gateway.example.com",
			want: []string{
				"--global-config", "/var/lib/coder-ssh-gateway/coder-config",
				"ssh",
				"--stdio",
				"--hostname-suffix", "coder-gateway.example.com",
				"--wait=no",
				"w.coder-gateway.example.com",
			},
		},
		{
			name:      "autostart off, wait auto",
			autostart: false,
			waitMode:  "auto",
			target:    "w.coder-gateway.example.com",
			want: []string{
				"--global-config", "/var/lib/coder-ssh-gateway/coder-config",
				"ssh",
				"--stdio",
				"--hostname-suffix", "coder-gateway.example.com",
				"--wait=auto",
				"--disable-autostart=true",
				"w.coder-gateway.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := testDeployment(t)
			dep.Autostart = tt.autostart
			dep.WaitMode = tt.waitMode
			got := tunnel.BuildArgv(dep, testRoute(tt.target))
			if len(got) != len(tt.want) {
				t.Fatalf("argv length: got %d (%v), want %d (%v)", len(got), got, len(tt.want), tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("argv[%d]: got %q, want %q (full argv %v)", i, got[i], tt.want[i], got)
				}
			}

			// Belt-and-suspenders: the final positional is the workspace
			// target and must satisfy the T6 strict hostname grammar so a
			// client can never smuggle a flag into argv (§18.2).
			target := got[len(got)-1]
			if !targetGrammar.MatchString(target) {
				t.Fatalf("target %q violates ^[a-z0-9.-]+$", target)
			}
		})
	}
}

// TestBuildArgvNeverContainsToken: argv construction has no access to the
// credential at all; assert a marker token appears in no element even when
// every deployment/route field is populated (§18.3).
func TestBuildArgvNeverContainsToken(t *testing.T) {
	const marker = "marker-token-9f8e7d6c5b4a"
	dep := testDeployment(t)
	argv := tunnel.BuildArgv(dep, testRoute("w.coder-gateway.example.com"))
	for i, a := range argv {
		if strings.Contains(a, marker) {
			t.Fatalf("marker token present in argv[%d]=%q", i, a)
		}
	}
}
