package app_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/config"
	"github.com/taxilian/coder-ssh-gateway/internal/store"
)

func TestInitCreatesLayout(t *testing.T) {
	dir := t.TempDir() + "/state"
	code, out, errOut := runCLI(t, "", "--state-dir", dir, "init")
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
	for _, want := range []string{"example.test", "coder-gateway.example.com", "BACK UP"} {
		if !strings.Contains(string(cfgBytes), want) {
			t.Errorf("starter config missing %q", want)
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
	if code, out, errOut := runCLI(t, "", "--state-dir", dir, "init"); code != 0 {
		t.Fatalf("first init: %d %s %s", code, out, errOut)
	}
	hostKey := config.DefaultHostKeyPath(dir)
	before, _ := os.ReadFile(hostKey)

	code, out, errOut := runCLI(t, "", "--state-dir", dir, "init")
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
	if code, _, _ := runCLI(t, "", "--state-dir", dir, "init"); code != 0 {
		t.Fatalf("init failed")
	}
	hostKey := config.DefaultHostKeyPath(dir)
	garbage := []byte("GARBAGE-NOT-A-KEY")
	if err := os.WriteFile(hostKey, garbage, 0o600); err != nil {
		t.Fatal(err)
	}

	if code, _, _ := runCLI(t, "", "--state-dir", dir, "init"); code != 0 {
		t.Fatalf("init without force failed")
	}
	if b, _ := os.ReadFile(hostKey); string(b) != string(garbage) {
		t.Fatal("init without --force overwrote the host key")
	}

	// --force without the confirmation word aborts and leaves the file alone.
	code, _, errOut := runCLI(t, "no\n", "--state-dir", dir, "init", "--force")
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
	code, out, _ := runCLI(t, "overwrite\noverwrite\noverwrite\n", "--state-dir", dir, "init", "--force")
	if code != 0 {
		t.Fatalf("confirmed --force init failed: %s", out)
	}
	b, _ := os.ReadFile(hostKey)
	if _, err := ssh.ParseRawPrivateKey(b); err != nil {
		t.Fatalf("overwritten host key not parseable: %v", err)
	}
	assertSecretFile(t, hostKey)
}

func TestInitRequiresStateDir(t *testing.T) {
	code, _, errOut := runCLI(t, "", "init")
	if code == 0 {
		t.Fatal("init without --state-dir succeeded")
	}
	if !strings.Contains(errOut, "--state-dir") {
		t.Errorf("error should mention --state-dir: %q", errOut)
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
