package app_test

import (
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/config"
)

// App-level wiring for the key-management username (todo 8): Build arms
// sshauth from the effective key_management config (nil when disabled —
// CD-2 byte-identical unknown rejection), env overrides change the trigger
// username, and doctor validates the special usernames with env overrides
// applied in cmdServe order plus an INFO line naming the armed usernames.

// enrollKeyViaAdmin registers a fresh key on an existing account through
// the admin CLI and returns its signer.
func enrollKeyViaAdmin(t *testing.T, f *cliFixture, accountID, label string) ssh.Signer {
	t.Helper()
	signer, pubPath, _ := genKeyPair(t, f.dir, label+".pub")
	code, out, errOut := runCLI(t, "", "--state-dir", f.dir, "admin", "key", "add",
		"--account", accountID, "--file", pubPath, "--label", label)
	if code != 0 {
		t.Fatalf("admin key add: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	return signer
}

// appendConfig appends a YAML fragment to the fixture config.
func appendConfig(t *testing.T, f *cliFixture, section string) {
	t.Helper()
	raw, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if err := os.WriteFile(f.configPath, append(raw, []byte(section)...), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// dialKeysUI authenticates as user, opens the first session channel,
// starts the shell, quits, and returns the full UI transcript.
func dialKeysUI(t *testing.T, es *enrollmentServer, user string, signer ssh.Signer) (string, error) {
	t.Helper()
	client, err := dialEnrollment(t, es.addr, user, &bannerCapture{}, ssh.PublicKeys(signer))
	if err != nil {
		return "", err
	}
	defer client.Close()

	ch, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		return "", err
	}
	defer ch.Close()
	go ssh.DiscardRequests(requests)
	if ok, err := ch.SendRequest("shell", true, nil); err != nil || !ok {
		t.Fatalf("shell on %s connection: ok=%v err=%v", user, ok, err)
	}
	if _, err := ch.Write([]byte("q\n")); err != nil {
		t.Fatalf("write q: %v", err)
	}
	out, err := io.ReadAll(ch)
	if err != nil {
		t.Fatalf("read UI transcript: %v", err)
	}
	return string(out), nil
}

// Default config: login-admin@ with an enrolled key reaches the
// key-management UI end-to-end through the real Build wiring (keymanagement
// finals; no credential consulted, no coder child spawned).
func TestServeKeyManagementEndToEnd(t *testing.T) {
	f := newCLIFixture(t, false)
	accountID := f.addAccount(t, "keys-ui")
	signer := enrollKeyViaAdmin(t, f, accountID.String(), "laptop")

	es := startEnrollmentServer(t, f, nil)
	defer es.shutdown(t)

	transcript, err := dialKeysUI(t, es, "login-admin", signer)
	if err != nil {
		t.Fatalf("login-admin with enrolled key: %v", err)
	}
	for _, want := range []string{
		"Coder SSH Gateway -- key management for ",
		"Enter a key number to remove it, d to delete your account, r to refresh, q to quit:",
		"Bye.",
	} {
		if !strings.Contains(transcript, want) {
			t.Errorf("UI transcript missing %q; got: %q", want, transcript)
		}
	}
}

// Disabled key management: login-admin@ with an ENROLLED key rejects
// byte-identically to an unknown username (§35 uniformity) and never
// reaches the UI.
func TestServeKeyManagementDisabledUniformReject(t *testing.T) {
	f := newCLIFixture(t, false)
	accountID := f.addAccount(t, "keys-ui")
	signer := enrollKeyViaAdmin(t, f, accountID.String(), "laptop")

	es := startEnrollmentServer(t, f, func(cfg *config.Config) {
		cfg.KeyManagement.Enabled = false
	})
	defer es.shutdown(t)

	rejectText := func(user string) string {
		t.Helper()
		banners := &bannerCapture{}
		client, err := dialEnrollment(t, es.addr, user, banners, ssh.PublicKeys(signer))
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatalf("user %q: expected auth failure", user)
		}
		if strings.Contains(banners.text(), "key management") {
			t.Errorf("user %q: key-management banner leaked: %q", user, banners.text())
		}
		return err.Error()
	}
	unknownRef := rejectText("nosuchuser")
	if got := rejectText("login-admin"); got != unknownRef {
		t.Errorf("disabled login-admin error differs from unknown username:\n  %q\n  %q", got, unknownRef)
	}
}

// CSGW_KEY_MANAGEMENT_USER changes the trigger username: the env value
// reaches the UI and the default name rejects like an unknown username.
// The mutate hook applies env overrides in cmdServe order (parse →
// state-dir → env → Build).
func TestServeKeyManagementEnvOverrideUser(t *testing.T) {
	f := newCLIFixture(t, false)
	accountID := f.addAccount(t, "keys-ui")
	signer := enrollKeyViaAdmin(t, f, accountID.String(), "laptop")

	t.Setenv(config.EnvKeyManagementUser, "keysadmin")
	es := startEnrollmentServer(t, f, func(cfg *config.Config) {
		applied, err := config.ApplyEnvOverrides(cfg)
		if err != nil {
			t.Fatalf("apply env overrides: %v", err)
		}
		if len(applied) == 0 {
			t.Fatal("CSGW_KEY_MANAGEMENT_USER was not applied")
		}
	})
	defer es.shutdown(t)

	transcript, err := dialKeysUI(t, es, "keysadmin", signer)
	if err != nil {
		t.Fatalf("keysadmin with enrolled key: %v", err)
	}
	if !strings.Contains(transcript, "Coder SSH Gateway -- key management for ") {
		t.Errorf("UI transcript missing header on env username; got: %q", transcript)
	}

	banners := &bannerCapture{}
	client, err := dialEnrollment(t, es.addr, "login-admin", banners, ssh.PublicKeys(signer))
	if client != nil {
		client.Close()
	}
	if err == nil {
		t.Fatal("default login-admin still triggers after env override")
	}
	unknownRef := func() string {
		banners := &bannerCapture{}
		client, err := dialEnrollment(t, es.addr, "nosuchuser", banners, ssh.PublicKeys(signer))
		if client != nil {
			client.Close()
		}
		if err == nil {
			t.Fatal("unexpected success on unknown username")
		}
		return err.Error()
	}()
	if got := err.Error(); got != unknownRef {
		t.Errorf("overridden-away login-admin error differs from unknown username:\n  %q\n  %q", got, unknownRef)
	}
}

// Colliding special usernames fail serve boot with a field-qualified error
// (cmdServe Validate); the same config must also fail doctor (below).
func TestServeRejectsCollidingSpecialUsernames(t *testing.T) {
	f := newCLIFixture(t, true)
	appendConfig(t, f, "key_management:\n  user: login\n") // enrollment.user defaults to login

	code, _, stderr := runCLI(t, "", "--state-dir", f.dir, "serve")
	if code == 0 {
		t.Fatal("serve accepted colliding special usernames")
	}
	if !strings.Contains(stderr, "enrollment.user and key_management.user must differ") {
		t.Errorf("serve error not field-qualified: %q", stderr)
	}
}

// Defaults: doctor exits 0 and its output names both armed special
// usernames.
func TestDoctorReportsSpecialUsernames(t *testing.T) {
	f := newCLIFixture(t, true)

	code, stdout, stderr := runCLI(t, "", "--state-dir", f.dir, "doctor")
	if code != 0 {
		t.Fatalf("doctor exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	for _, want := range []string{
		"enrollment user: login (armed)",
		"key management user: login-admin (armed)",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("doctor output missing %q:\n%s", want, stdout)
		}
	}
}

// Doctor validates special usernames with env overrides applied before
// Validate (cmdServe ordering): YAML collisions, charset violations, and
// env-induced collisions all fail with a field-qualified message.
func TestDoctorValidatesSpecialUsernames(t *testing.T) {
	tests := []struct {
		name   string
		config string
		env    map[string]string
		want   string
	}{
		{
			name:   "colliding yaml usernames",
			config: "key_management:\n  user: login\n",
			want:   "enrollment.user and key_management.user must differ",
		},
		{
			name:   "charset violation",
			config: "key_management:\n  user: Keys_Admin\n",
			want:   `key_management.user: "Keys_Admin" is not a valid username`,
		},
		{
			name: "env-induced collision",
			env:  map[string]string{config.EnvEnrollmentUser: "login-admin"},
			want: "enrollment.user and key_management.user must differ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newCLIFixture(t, true)
			if tt.config != "" {
				appendConfig(t, f, tt.config)
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			code, stdout, _ := runCLI(t, "", "--state-dir", f.dir, "doctor")
			if code == 0 {
				t.Fatalf("doctor accepted an invalid special-username config:\n%s", stdout)
			}
			if !strings.Contains(stdout, tt.want) {
				t.Errorf("doctor output missing %q:\n%s", tt.want, stdout)
			}
		})
	}
}
