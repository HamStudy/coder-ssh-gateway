package route

import (
	"strings"
	"testing"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

func TestParseBareTarget(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"workspace", "workspace", "workspace"},
		{"workspace agent", "workspace.agent", "workspace.agent"},
		{"agent workspace owner", "agent.workspace.owner", "agent.workspace.owner"},
		{"normalizes uppercase", "AGENT.Workspace.Owner", "agent.workspace.owner"},
		{"strips trailing root dot", "workspace.", "workspace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route, err := ParseBareTarget(tt.in)
			if err != nil {
				t.Fatalf("ParseBareTarget(%q): %v", tt.in, err)
			}
			if route.RequestedHost != tt.in || route.WorkspaceHost != tt.want || route.DisplayTarget != tt.want {
				t.Errorf("route = %+v, want original %q and target %q", route, tt.in, tt.want)
			}
		})
	}
}

func TestParseBareTargetRejectsInvalidDestinations(t *testing.T) {
	tests := []struct {
		name string
		in   string
		code string
	}{
		{"empty", "", core.ROUTE_INVALID_PAYLOAD},
		{"root dot", ".", core.ROUTE_INVALID_PAYLOAD},
		{"too many labels", "a.b.c.d", core.ROUTE_NAME_INVALID},
		{"empty label", "workspace..agent", core.ROUTE_NAME_INVALID},
		{"leading hyphen", "-workspace", core.ROUTE_NAME_INVALID},
		{"trailing hyphen", "workspace-", core.ROUTE_NAME_INVALID},
		{"punycode", "xn--workspace", core.ROUTE_NAME_INVALID},
		{"unicode", "wörkspace", core.ROUTE_NAME_INVALID},
		{"whitespace", "workspace agent", core.ROUTE_NAME_INVALID},
		{"wildcard", "*.workspace", core.ROUTE_NAME_INVALID},
		{"ipv4", "192.0.2.1", core.ROUTE_NAME_INVALID},
		{"ipv6", "2001:db8::1", core.ROUTE_NAME_INVALID},
		{"oversized label", strings.Repeat("a", 64), core.ROUTE_NAME_INVALID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBareTarget(tt.in)
			if got := CodeOf(err); got != tt.code {
				t.Errorf("CodeOf(%v) = %q, want %q", err, got, tt.code)
			}
		})
	}
}

func TestParseDirectTCPIPRequiresPort22(t *testing.T) {
	codec := NewCodec()
	for _, port := range []uint32{0, 2222, 65535, 65536} {
		if _, err := codec.ParseDirectTCPIP("workspace", port); CodeOf(err) != core.ROUTE_PORT_DENIED {
			t.Errorf("port %d: %v", port, err)
		}
	}
	if route, err := codec.ParseDirectTCPIP("agent.workspace.owner", 22); err != nil || route.RequestedPort != 22 {
		t.Errorf("valid direct-tcpip route = %+v, err = %v", route, err)
	}
}
