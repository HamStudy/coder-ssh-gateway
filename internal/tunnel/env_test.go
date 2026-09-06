package tunnel_test

import (
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/tunnel"
)

func testDeploymentEnv(t *testing.T) core.Deployment {
	t.Helper()
	u, err := url.Parse("https://coder.example.com")
	if err != nil {
		t.Fatalf("parse coder URL: %v", err)
	}
	return core.Deployment{
		ID:           uuid.New(),
		CoderURL:     u,
		CoderBinary:  "/usr/local/bin/coder",
		GlobalConfig: "/var/lib/coder-ssh-gateway/coder-config",
		WorkingDir:   "/var/empty/coder-ssh-gateway",
		Autostart:    true,
		WaitMode:     "auto",
	}
}

func extractKeys(env []string) []string {
	keys := make([]string, 0, len(env))
	for _, e := range env {
		if idx := strings.Index(e, "="); idx >= 0 {
			keys = append(keys, e[:idx])
		}
	}
	return keys
}

func TestBuildEnvAllowlistKeys(t *testing.T) {
	dep := testDeploymentEnv(t)
	token := []byte("test-token-abc123")
	env := tunnel.BuildEnv(dep, token)

	keys := extractKeys(env)
	sort.Strings(keys)

	wantKeys := []string{
		"CODER_DISABLE_NETWORK_TELEMETRY",
		"CODER_NO_FEATURE_WARNING",
		"CODER_NO_VERSION_WARNING",
		"CODER_SESSION_TOKEN",
		"CODER_URL",
		"HOME",
		"PATH",
		"TMPDIR",
	}
	sort.Strings(wantKeys)

	if len(keys) != len(wantKeys) {
		t.Fatalf("env key count: got %d (%v), want %d (%v)", len(keys), keys, len(wantKeys), wantKeys)
	}
	for i := range wantKeys {
		if keys[i] != wantKeys[i] {
			t.Fatalf("env key[%d]: got %q, want %q", i, keys[i], wantKeys[i])
		}
	}
}

func TestBuildEnvAllowlistKeysWithTLS(t *testing.T) {
	dep := testDeploymentEnv(t)
	dep.TLS = core.DeploymentTLS{
		CAFile:   "/tmp/ca.crt",
		CertFile: "/tmp/cert.crt",
		KeyFile:  "/tmp/key.pem",
	}
	token := []byte("test-token-abc123")
	env := tunnel.BuildEnv(dep, token)

	keys := extractKeys(env)
	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}

	wantTLSKeys := []string{"CODER_CLIENT_TLS_CA_FILE", "CODER_CLIENT_TLS_CERT_FILE", "CODER_CLIENT_TLS_KEY_FILE"}
	for _, k := range wantTLSKeys {
		if !keySet[k] {
			t.Errorf("expected TLS key %q in env", k)
		}
	}
}

func TestBuildEnvAllowlistKeysWithNetwork(t *testing.T) {
	dep := testDeploymentEnv(t)
	dep.Network = core.DeploymentNetwork{
		Proxy:   "http://proxy.example.com:8080",
		NoProxy: "localhost,*.local",
	}
	token := []byte("test-token-abc123")
	env := tunnel.BuildEnv(dep, token)

	keys := extractKeys(env)
	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}

	wantNetKeys := []string{"HTTPS_PROXY", "NO_PROXY"}
	for _, k := range wantNetKeys {
		if !keySet[k] {
			t.Errorf("expected network key %q in env", k)
		}
	}
}

func TestBuildEnvNoOSEnvironLeakage(t *testing.T) {
	dep := testDeploymentEnv(t)
	token := []byte("test-token-abc123")

	t.Setenv("SOME_POISON_VAR", "should-not-appear")
	t.Setenv("ANOTHER_BAD", "also-bad")
	t.Setenv("PATH", "/poison/path")
	t.Setenv("HOME", "/poison/home")

	env := tunnel.BuildEnv(dep, token)

	keys := extractKeys(env)
	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}

	if keySet["SOME_POISON_VAR"] {
		t.Error("poison var SOME_POISON_VAR found in env")
	}
	if keySet["ANOTHER_BAD"] {
		t.Error("poison var ANOTHER_BAD found in env")
	}
}
