package route

import (
	"regexp"
	"testing"
)

// Independent restatements of the accepted grammar (ParseBareTarget's
// contract): dotted 1-3 labels, or slashed 2-3 labels, never mixed.
var (
	safeDottedRE = regexp.MustCompile(`^[a-z0-9-]+(?:\.[a-z0-9-]+){0,2}$`)
	safeSlashedRE = regexp.MustCompile(`^[a-z0-9-]+(?:/[a-z0-9-]+){1,2}$`)
)

func FuzzParseDirectTCPIP(f *testing.F) {
	for _, seed := range []struct {
		host string
		port uint32
	}{
		{"workspace", 22}, {"workspace.agent", 22}, {"agent.workspace.owner", 22},
		{"owner/workspace", 22}, {"owner/workspace/agent", 22},
		{"192.0.2.1", 22}, {"a.b.c.d", 22}, {"workspace..agent", 22},
		{"a.b/c", 22}, {"a//b", 22}, {"a/", 22}, {"/a", 22},
		{"xn--workspace", 22}, {"workspace", 2222}, {"", 22},
	} {
		f.Add(seed.host, seed.port)
	}
	codec := NewCodec()
	f.Fuzz(func(t *testing.T, host string, port uint32) {
		route, err := codec.ParseDirectTCPIP(host, port)
		if err != nil {
			return
		}
		if route.RequestedPort != 22 ||
			(!safeDottedRE.MatchString(route.WorkspaceHost) && !safeSlashedRE.MatchString(route.WorkspaceHost)) {
			t.Fatalf("accepted invalid route %+v", route)
		}
	})
}
