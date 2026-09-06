package app_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/app"
	"github.com/HamStudy/coder-ssh-gateway/internal/config"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
)

func TestInitCreatesLayout(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	stateArg := filepath.Join(root, "unused", "..", "state")
	code, out, errOut := runCLI(t, "", "--state-dir", stateArg, "init", "coder.example.com")
	if code != 0 {
		t.Fatalf("init: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}

	verBytes, err := os.ReadFile(filepath.Join(dir, "VERSION"))
	if err != nil || string(verBytes) != "1\n" {
		t.Fatalf("VERSION = %q, err %v", verBytes, err)
	}
	for _, d := range []string{"deployments", "accounts", "keys", "credentials", "audit", "secrets"} {
		fi, err := os.Stat(filepath.Join(dir, d))
		if err != nil || !fi.IsDir() {
			t.Fatalf("dir %s: %v", d, err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("dir %s mode = %04o, want 0700", d, fi.Mode().Perm())
		}
	}

	hostKey := config.DefaultHostKeyPath(dir)
	assertSecretFile(t, hostKey)
	pemBytes, _ := os.ReadFile(hostKey)
	if _, err := ssh.ParseRawPrivateKey(pemBytes); err != nil {
		t.Fatalf("host key not parseable: %v", err)
	}

	encKey := config.DefaultEncryptionKeyPath(dir)
	assertSecretFile(t, encKey)
	if fi, _ := os.Stat(encKey); fi.Size() != 32 {
		t.Errorf("encryption key size = %d, want 32", fi.Size())
	}

	cfgBytes, err := os.ReadFile(config.DefaultConfigPath(dir))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	for _, want := range []string{"https://coder.example.com", "BACK UP"} {
		if !strings.Contains(string(cfgBytes), want) {
			t.Errorf("starter config missing %q", want)
		}
	}
	configText := string(cfgBytes)
	for _, want := range []string{
		"- secrets/ssh_host_ed25519_key",
		"v1: secrets/credential-key-v1",
		"coder_global_config: coder-config",
		"working_directory: run",
	} {
		if !strings.Contains(configText, want) {
			t.Errorf("starter config missing relative path %q", want)
		}
	}
	if strings.Contains(configText, "\n  dir:") {
		t.Error("starter config must not repeat state.dir")
	}
	if strings.Contains(configText, "design section") || strings.Contains(configText, "(section ") {
		t.Error("starter config contains an internal design-section reference")
	}

	cfg, err := config.Parse(config.DefaultConfigPath(dir))
	if err != nil {
		t.Fatalf("parse generated config: %v", err)
	}
	wantPaths := map[string]string{
		"state.dir":                      dir,
		"ssh.host_keys":                  hostKey,
		"encryption.keys.v1":             encKey,
		"deployment.coder_global_config": filepath.Join(dir, "coder-config"),
		"deployment.working_directory":   filepath.Join(dir, "run"),
	}
	gotPaths := map[string]string{
		"state.dir":                      cfg.State.Dir,
		"ssh.host_keys":                  cfg.SSH.HostKeys[0],
		"encryption.keys.v1":             cfg.Encryption.Keys["v1"],
		"deployment.coder_global_config": cfg.Deployment.CoderGlobalConfig,
		"deployment.working_directory":   cfg.Deployment.WorkingDirectory,
	}
	for field, want := range wantPaths {
		if got := gotPaths[field]; got != want {
			t.Errorf("%s = %q, want initialized path %q", field, got, want)
		}
		if _, err := os.Stat(want); err != nil {
			t.Errorf("%s initialized path %q: %v", field, want, err)
		}
	}

	if !strings.Contains(out, "BACK UP") {
		t.Errorf("init output missing backup warning: %q", out)
	}
	if !strings.Contains(out, "SHA256:") {
		t.Errorf("init output missing host key fingerprint: %q", out)
	}
	if !strings.Contains(out, "doctor") {
		t.Errorf("init output missing next steps: %q", out)
	}

	// init must not hold the flock after returning.
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open after init: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}
}

func TestInitReportsDeploymentSeedFailure(t *testing.T) {
	dir := t.TempDir()
	if code, out, errOut := runCLI(t, "", "--state-dir", dir, "init", "coder.example.com"); code != 0 {
		t.Fatalf("initial init: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}

	deploymentPath := filepath.Join(dir, "deployments", app.DeploymentUUID("primary").String()+".json")
	if err := os.Remove(deploymentPath); err != nil {
		t.Fatalf("remove deployment record: %v", err)
	}
	if err := os.Mkdir(deploymentPath, 0o700); err != nil {
		t.Fatalf("create deployment record directory: %v", err)
	}

	code, _, errOut := runCLI(t, "", "--state-dir", dir, "init", "coder.example.com")
	if code == 0 {
		t.Fatalf("init succeeded after deployment seed failure; stderr: %s", errOut)
	}
	if !strings.Contains(errOut, "seeding deployment from config") {
		t.Errorf("error should identify deployment seeding: %q", errOut)
	}

	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open after failed init: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close after failed init: %v", err)
	}
}

func TestRelativeInitThenDoctorAndConfigOnlyStartup(t *testing.T) {
	root := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	stateArg := filepath.Join("nested", "..", "state")
	code, out, errOut := runCLI(t, "", "--state-dir", stateArg, "init", "coder.example.com")
	if code != 0 {
		t.Fatalf("relative init: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	stateDir := filepath.Join(root, "state")
	configPath := config.DefaultConfigPath(stateDir)
	cs := newCoderStub(t, true)
	caPath := filepath.Join(stateDir, "ca.pem")
	if err := os.WriteFile(caPath, []byte(cs.tlsCAPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(raw), "coder_url: https://coder.example.com", "coder_url: "+cs.url(), 1)
	updated = strings.Replace(updated, "coder_binary: /usr/local/bin/coder", "coder_binary: /bin/true", 1)
	updated = strings.Replace(updated, "  # tls:\n", "  tls:\n    ca_file: ca.pem\n", 1)
	updated = strings.Replace(updated, "address: \":2222\"", "address: \"127.0.0.1:0\"", 1)
	updated += "\nobservability:\n  metrics_address: 127.0.0.1:0\n  health_address: 127.0.0.1:0\n"
	if err := os.WriteFile(configPath, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}

	if code, out, errOut := runCLI(t, "", "--state-dir", stateArg, "doctor"); code != 0 {
		t.Fatalf("relative doctor: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	relConfigPath := filepath.Join("state", "config.yaml")
	if code, out, errOut := runCLI(t, "", "--config", relConfigPath, "doctor"); code != 0 {
		t.Fatalf("config-only doctor: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var serveOut, serveErr bytes.Buffer
	if code := app.Run(ctx, []string{"--config", relConfigPath, "serve"}, nil, &serveOut, &serveErr); code != 0 {
		t.Fatalf("config-only serve startup: exit %d\nstdout: %s\nstderr: %s", code, serveOut.String(), serveErr.String())
	}
}

func assertSecretFile(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("%s mode = %04o, want 0600", path, fi.Mode().Perm())
	}
}

func TestInitIdempotent(t *testing.T) {
	dir := t.TempDir()
	if code, out, errOut := runCLI(t, "", "--state-dir", dir, "init", "coder.example.com"); code != 0 {
		t.Fatalf("first init: %d %s %s", code, out, errOut)
	}
	hostKey := config.DefaultHostKeyPath(dir)
	before, _ := os.ReadFile(hostKey)

	code, out, errOut := runCLI(t, "", "--state-dir", dir, "init", "coder.example.com")
	if code != 0 {
		t.Fatalf("second init: %d %s %s", code, out, errOut)
	}
	after, _ := os.ReadFile(hostKey)
	if string(before) != string(after) {
		t.Fatal("second init overwrote the host key without --force")
	}
	if !strings.Contains(out, "kept existing") {
		t.Errorf("second init output missing 'kept existing': %q", out)
	}
}

func TestInitNoOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	if code, _, _ := runCLI(t, "", "--state-dir", dir, "init", "coder.example.com"); code != 0 {
		t.Fatalf("init failed")
	}
	hostKey := config.DefaultHostKeyPath(dir)
	garbage := []byte("GARBAGE-NOT-A-KEY")
	if err := os.WriteFile(hostKey, garbage, 0o600); err != nil {
		t.Fatal(err)
	}

	if code, _, _ := runCLI(t, "", "--state-dir", dir, "init", "coder.example.com"); code != 0 {
		t.Fatalf("init without force failed")
	}
	if b, _ := os.ReadFile(hostKey); string(b) != string(garbage) {
		t.Fatal("init without --force overwrote the host key")
	}

	// --force without the confirmation word aborts and leaves the file alone.
	code, _, errOut := runCLI(t, "no\n", "--state-dir", dir, "init", "--force", "coder.example.com")
	if code == 0 {
		t.Fatal("init --force without confirmation succeeded")
	}
	if !strings.Contains(errOut, "not confirmed") {
		t.Errorf("missing confirmation-abort message: %q", errOut)
	}
	if b, _ := os.ReadFile(hostKey); string(b) != string(garbage) {
		t.Fatal("unconfirmed --force overwrote the host key")
	}

	// --force with "overwrite" replaces the garbage with a valid key.
	code, out, _ := runCLI(t, "overwrite\noverwrite\noverwrite\n", "--state-dir", dir, "init", "--force", "coder.example.com")
	if code != 0 {
		t.Fatalf("confirmed --force init failed: %s", out)
	}
	b, _ := os.ReadFile(hostKey)
	if _, err := ssh.ParseRawPrivateKey(b); err != nil {
		t.Fatalf("overwritten host key not parseable: %v", err)
	}
	assertSecretFile(t, hostKey)
}

func TestInitLeavesExistingSecretIntactWhenOverwriteFails(t *testing.T) {
	dir := t.TempDir()
	if code, _, errOut := runCLI(t, "", "--state-dir", dir, "init", "coder.example.com"); code != 0 {
		t.Fatalf("initial init: %s", errOut)
	}
	configPath := config.DefaultConfigPath(dir)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod state dir read-only: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("restore state dir perms: %v", err)
		}
	})

	code, _, errOut := runCLI(t, "overwrite\noverwrite\noverwrite\n", "--state-dir", dir, "init", "--force", "coder.example.com")
	if code == 0 {
		t.Fatalf("forced init unexpectedly succeeded")
	}
	if !strings.Contains(errOut, "writing starter config") {
		t.Fatalf("expected config write failure, got: %s", errOut)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config after failed overwrite: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed overwrite corrupted the existing config")
	}
}

func TestInitRequiresStateDir(t *testing.T) {
	code, _, errOut := runCLI(t, "", "init", "coder.example.com")
	if code == 0 {
		t.Fatal("init without --state-dir succeeded")
	}
	if !strings.Contains(errOut, "--state-dir") {
		t.Errorf("error should mention --state-dir: %q", errOut)
	}
}

func TestInitRequiresOneValidCoderDomain(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantURL string
	}{
		{name: "bare domain", args: []string{"coder.example.com"}, wantURL: "https://coder.example.com"},
		{name: "domain with port", args: []string{"coder.example.com:8443"}, wantURL: "https://coder.example.com:8443"},
		{name: "no domain", args: nil},
		{name: "multiple domains", args: []string{"coder.example.com", "other.example.com"}},
		{name: "scheme", args: []string{"https://coder.example.com"}},
		{name: "path", args: []string{"coder.example.com/path"}},
		{name: "credentials", args: []string{"user@coder.example.com"}},
		{name: "query", args: []string{"coder.example.com?x=y"}},
		{name: "fragment", args: []string{"coder.example.com#section"}},
		{name: "malformed domain", args: []string{"-coder.example.com"}},
		{name: "invalid port", args: []string{"coder.example.com:70000"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{"--state-dir", dir, "init"}, tt.args...)
			code, _, errOut := runCLI(t, "", args...)
			if tt.wantURL == "" {
				if code != 2 {
					t.Fatalf("init exit = %d, want usage error; stderr: %s", code, errOut)
				}
				if !strings.Contains(errOut, "Coder domain") {
					t.Errorf("error does not explain the Coder domain requirement: %q", errOut)
				}
				return
			}
			if code != 0 {
				t.Fatalf("init exit = %d; stderr: %s", code, errOut)
			}
			configBytes, err := os.ReadFile(config.DefaultConfigPath(dir))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(configBytes), "coder_url: "+tt.wantURL) {
				t.Errorf("generated config does not contain %q:\n%s", tt.wantURL, configBytes)
			}
		})
	}
}

func TestUsageAndVersion(t *testing.T) {
	code, out, _ := runCLI(t, "")
	if code != 2 {
		t.Errorf("no args: exit %d, want 2", code)
	}
	_ = out
	code, out, _ = runCLI(t, "", "version")
	if code != 0 || !strings.Contains(out, "coder-ssh-gateway/") {
		t.Errorf("version: exit %d out %q", code, out)
	}
	code, _, errOut := runCLI(t, "", "bogus")
	if code != 2 || !strings.Contains(errOut, "unknown command") {
		t.Errorf("bogus command: exit %d err %q", code, errOut)
	}
}
