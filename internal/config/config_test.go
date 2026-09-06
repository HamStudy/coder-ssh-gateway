package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, path string, content []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, perm); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

type validEnv struct {
	dir      string
	stateDir string
	hostKey  string
	encKey   string
	coderBin string
}

func newValidEnv(t *testing.T) validEnv {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	env := validEnv{
		dir:      dir,
		stateDir: stateDir,
		hostKey:  filepath.Join(dir, "hostkey"),
		encKey:   filepath.Join(dir, "enckey"),
		coderBin: filepath.Join(dir, "coder"),
	}
	writeFile(t, env.hostKey, []byte("dummy-host-key"), 0o600)
	writeFile(t, env.encKey, []byte("0123456789abcdef0123456789abcdef"), 0o600)
	writeFile(t, env.coderBin, []byte("#!/bin/sh\n"), 0o755)
	return env
}

func (e validEnv) yaml() string {
	return fmt.Sprintf(`version: 1
listen:
  address: ":2222"
ssh:
  host_keys:
    - %s
encryption:
  provider: file
  active_key_id: v1
  keys:
    v1: %s
deployment:
  id: primary
  coder_url: https://coder.example.com
  coder_binary: %s
state:
  dir: %s
`, e.hostKey, e.encKey, e.coderBin, e.stateDir)
}

func (e validEnv) writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	p := filepath.Join(e.dir, "config.yaml")
	writeFile(t, p, []byte(yaml), 0o600)
	return p
}

func validConfig(t *testing.T) (*Config, validEnv) {
	t.Helper()
	env := newValidEnv(t)
	cfg := Default()
	cfg.Listen.Address = ":2222"
	cfg.SSH.HostKeys = []string{env.hostKey}
	cfg.Encryption.Keys = map[string]string{"v1": env.encKey}
	cfg.Encryption.ActiveKeyID = "v1"
	cfg.Deployment.CoderURL = "https://coder.example.com"
	cfg.Deployment.CoderBinary = env.coderBin
	cfg.State.Dir = env.stateDir
	return cfg, env
}

func TestLoadValidAppliesDefaults(t *testing.T) {
	env := newValidEnv(t)
	cfg, err := Load(env.writeConfig(t, env.yaml()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen.Address != ":2222" {
		t.Errorf("listen.address = %q, want :2222", cfg.Listen.Address)
	}
	if cfg.Listen.HandshakeTimeout.Std() != 30*time.Second {
		t.Errorf("handshake_timeout = %v, want 30s", cfg.Listen.HandshakeTimeout)
	}
	if cfg.Deployment.Wait != "auto" {
		t.Errorf("wait = %q, want auto", cfg.Deployment.Wait)
	}
	if cfg.Limits.CoderProcesses != 128 {
		t.Errorf("coder_processes = %d, want 128", cfg.Limits.CoderProcesses)
	}
	if cfg.Limits.StderrBufferBytes != 65536 {
		t.Errorf("stderr_buffer_bytes = %d, want 65536", cfg.Limits.StderrBufferBytes)
	}
	if cfg.Limits.ProcessShutdownGrace.Std() != 5*time.Second {
		t.Errorf("process_shutdown_grace = %v, want 5s", cfg.Limits.ProcessShutdownGrace)
	}
	if cfg.State.AuditRetentionDays != 90 {
		t.Errorf("audit_retention_days = %d, want 90", cfg.State.AuditRetentionDays)
	}
	if cfg.Observability.LogLevel != "info" {
		t.Errorf("log_level = %q, want info", cfg.Observability.LogLevel)
	}
	if cfg.Deployment.CoderURL != "https://coder.example.com" {
		t.Errorf("coder_url = %q", cfg.Deployment.CoderURL)
	}
}

func TestParseValidFixture(t *testing.T) {
	cfg, err := Parse(filepath.Join("..", "..", "testdata", "config", "valid.yaml"))
	if err != nil {
		t.Fatalf("Parse fixture: %v", err)
	}
	if cfg.Deployment.CoderURL != "https://coder.example.com" {
		t.Errorf("fixture coder_url = %q, want https://coder.example.com", cfg.Deployment.CoderURL)
	}
	if cfg.Listen.Address != ":2222" {
		t.Errorf("fixture listen.address = %q, want :2222", cfg.Listen.Address)
	}
	if !cfg.Enrollment.Enabled || cfg.Enrollment.User != "login" ||
		cfg.Enrollment.MaxAttempts != 3 || cfg.Enrollment.Timeout.Std() != 5*time.Minute {
		t.Errorf("fixture enrollment = %+v, want enabled login/3/5m", cfg.Enrollment)
	}

	// Repoint secret/binary/state paths at real temp files, then validate.
	env := newValidEnv(t)
	cfg.SSH.HostKeys = []string{env.hostKey}
	cfg.Encryption.Keys = map[string]string{"v1": env.encKey}
	cfg.Deployment.CoderBinary = env.coderBin
	cfg.State.Dir = env.stateDir
	if err := cfg.Validate(); err != nil {
		t.Fatalf("fixture Validate with real paths: %v", err)
	}
}

func TestParsePathSemantics(t *testing.T) {
	tests := []struct {
		name      string
		stateYAML string
		wantState func(configDir, stateDir string) string
	}{
		{
			name: "config parent is fallback state directory",
			wantState: func(configDir, _ string) string {
				return configDir
			},
		},
		{
			name:      "relative explicit state directory is config relative",
			stateYAML: "state:\n  dir: ../state\n",
			wantState: func(_, stateDir string) string {
				return stateDir
			},
		},
		{
			name: "absolute explicit state directory is preserved",
			wantState: func(_, stateDir string) string {
				return stateDir
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			configDir := filepath.Join(root, "config")
			stateDir := filepath.Join(root, "state")
			if err := os.MkdirAll(configDir, 0o700); err != nil {
				t.Fatal(err)
			}
			stateYAML := tt.stateYAML
			if tt.name == "absolute explicit state directory is preserved" {
				stateYAML = fmt.Sprintf("state:\n  dir: %s\n", stateDir)
			}
			configPath := filepath.Join(configDir, "gateway.yaml")
			yaml := `ssh:
  host_keys: [secrets/host-key]
encryption:
  active_key_id: v1
  keys:
    v1: secrets/encryption-key
deployment:
  coder_binary: bin/coder
  coder_global_config: coder-config
  working_directory: run
  tls:
    ca_file: tls/ca.pem
    client_cert_file: tls/client.pem
    client_key_file: tls/client-key.pem
` + stateYAML
			writeFile(t, configPath, []byte(yaml), 0o600)
			workingDir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			relativeConfigPath, err := filepath.Rel(workingDir, configPath)
			if err != nil {
				t.Fatal(err)
			}

			cfg, err := Parse(relativeConfigPath)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got, want := cfg.State.Dir, tt.wantState(configDir, stateDir); got != want {
				t.Errorf("state.dir = %q, want %q", got, want)
			}
			paths := map[string]string{
				"ssh.host_keys":                   cfg.SSH.HostKeys[0],
				"encryption.keys.v1":              cfg.Encryption.Keys["v1"],
				"deployment.coder_binary":         cfg.Deployment.CoderBinary,
				"deployment.coder_global_config":  cfg.Deployment.CoderGlobalConfig,
				"deployment.working_directory":    cfg.Deployment.WorkingDirectory,
				"deployment.tls.ca_file":          cfg.Deployment.TLS.CAFile,
				"deployment.tls.client_cert_file": cfg.Deployment.TLS.ClientCertFile,
				"deployment.tls.client_key_file":  cfg.Deployment.TLS.ClientKeyFile,
			}
			wantPaths := map[string]string{
				"ssh.host_keys":                   filepath.Join(configDir, "secrets", "host-key"),
				"encryption.keys.v1":              filepath.Join(configDir, "secrets", "encryption-key"),
				"deployment.coder_binary":         filepath.Join(configDir, "bin", "coder"),
				"deployment.coder_global_config":  filepath.Join(configDir, "coder-config"),
				"deployment.working_directory":    filepath.Join(configDir, "run"),
				"deployment.tls.ca_file":          filepath.Join(configDir, "tls", "ca.pem"),
				"deployment.tls.client_cert_file": filepath.Join(configDir, "tls", "client.pem"),
				"deployment.tls.client_key_file":  filepath.Join(configDir, "tls", "client-key.pem"),
			}
			for field, got := range paths {
				if want := wantPaths[field]; got != want {
					t.Errorf("%s = %q, want %q", field, got, want)
				}
			}

			override := filepath.Join(root, "cli-state")
			ApplyStateDir(cfg, override)
			if cfg.State.Dir != override {
				t.Errorf("CLI state override = %q, want %q", cfg.State.Dir, override)
			}
			if cfg.SSH.HostKeys[0] != wantPaths["ssh.host_keys"] || cfg.Encryption.Keys["v1"] != wantPaths["encryption.keys.v1"] {
				t.Error("CLI state override relocated explicit YAML secret paths")
			}
		})
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	env := newValidEnv(t)
	cases := map[string]string{
		"database section":   env.yaml() + "database:\n  driver: sqlite\n",
		"deployments plural": strings.Replace(env.yaml(), "deployment:", "deployments:", 1),
		"bogus top-level":    env.yaml() + "bogus_field: true\n",
		"removed field":      env.yaml() + "deployment:\n  target" + "_suffix: gateway.example.com\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(env.writeConfig(t, yaml))
			if err == nil {
				t.Fatal("expected error for unknown field")
			}
		})
	}
}

func TestLoadRejectsBadDuration(t *testing.T) {
	env := newValidEnv(t)
	yaml := strings.Replace(env.yaml(), `address: ":2222"`,
		"address: \":2222\"\n  handshake_timeout: banana", 1)
	_, err := Load(env.writeConfig(t, yaml))
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
	if !strings.Contains(err.Error(), "banana") {
		t.Errorf("error should name the offending value, got: %v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestEnrollmentSectionParsing(t *testing.T) {
	env := newValidEnv(t)
	cfg, err := Load(env.writeConfig(t, env.yaml()+`enrollment:
  enabled: true
  user: onboard
  max_attempts: 5
  timeout: 2m
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Enrollment.User != "onboard" || cfg.Enrollment.MaxAttempts != 5 ||
		cfg.Enrollment.Timeout.Std() != 2*time.Minute {
		t.Errorf("enrollment = %+v, want onboard/5/2m", cfg.Enrollment)
	}

	// Strict field checking rejects unknown keys inside the section.
	_, err = Load(env.writeConfig(t, env.yaml()+"enrollment:\n  bogus: true\n"))
	if err == nil {
		t.Fatal("expected error for unknown enrollment field")
	}

	// A disabled section parses and validates without the enabled-only knobs.
	disabled, err := Load(env.writeConfig(t, env.yaml()+"enrollment:\n  enabled: false\n"))
	if err != nil {
		t.Fatalf("Load disabled enrollment: %v", err)
	}
	if disabled.Enrollment.Enabled {
		t.Error("enrollment.enabled = true, want false")
	}
}

func TestDefaultValues(t *testing.T) {
	c := Default()
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"listen.address", c.Listen.Address, ":22"},
		{"listen.proxy_protocol", c.Listen.ProxyProtocol, false},
		{"ssh.allow_ssh_certificates", c.SSH.AllowSSHCertificates, false},
		{"state.audit_retention_days", c.State.AuditRetentionDays, 90},
		{"encryption.provider", c.Encryption.Provider, "file"},
		{"deployment.autostart", c.Deployment.Autostart, true},
		{"deployment.wait", c.Deployment.Wait, "auto"},
		{"limits.unauthenticated_connections", c.Limits.UnauthenticatedConnections, 128},
		{"limits.handshakes", c.Limits.Handshakes, 64},
		{"limits.connections_per_ip", c.Limits.ConnectionsPerIP, 16},
		{"limits.connections_per_key", c.Limits.ConnectionsPerKey, 8},
		{"limits.connections_per_account", c.Limits.ConnectionsPerAccount, 8},
		{"limits.channels_per_connection", c.Limits.ChannelsPerConnection, 4},
		{"limits.channels_per_account", c.Limits.ChannelsPerAccount, 8},
		{"limits.coder_api_requests", c.Limits.CoderAPIRequests, 32},
		{"limits.renewal_attempts_per_connection", c.Limits.RenewalAttemptsPerConnection, 3},
		{"limits.renewal_attempts_per_account_per_minute", c.Limits.RenewalAttemptsPerAccountPerMinute, 5},
		{"enrollment.enabled", c.Enrollment.Enabled, true},
		{"enrollment.user", c.Enrollment.User, "login"},
		{"enrollment.max_attempts", c.Enrollment.MaxAttempts, 3},
		{"observability.log_format", c.Observability.LogFormat, "json"},
		{"observability.metrics_address", c.Observability.MetricsAddress, "127.0.0.1:9090"},
		{"observability.health_address", c.Observability.HealthAddress, "127.0.0.1:9091"},
	}
	for _, chk := range checks {
		if chk.got != chk.want {
			t.Errorf("%s = %v, want %v", chk.name, chk.got, chk.want)
		}
	}
	durs := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"listen.handshake_timeout", c.Listen.HandshakeTimeout.Std(), 30 * time.Second},
		{"listen.renewal_auth_timeout", c.Listen.RenewalAuthTimeout.Std(), 5 * time.Minute},
		{"listen.tcp_keepalive", c.Listen.TCPKeepalive.Std(), 30 * time.Second},
		{"deployment.workspace_connect_timeout", c.Deployment.WorkspaceConnectTimeout.Std(), 5 * time.Minute},
		{"deployment.token_validation_timeout", c.Deployment.TokenValidationTimeout.Std(), 10 * time.Second},
		{"deployment.token_validation_cache", c.Deployment.TokenValidationCache.Std(), 15 * time.Second},
		{"enrollment.timeout", c.Enrollment.Timeout.Std(), 5 * time.Minute},
	}
	for _, d := range durs {
		if d.got != d.want {
			t.Errorf("%s = %v, want %v", d.name, d.got, d.want)
		}
	}
}

func TestDefaultPathHelpers(t *testing.T) {
	sd := "/var/lib/coder-ssh-gateway"
	if got := DefaultConfigPath(sd); got != sd+"/config.yaml" {
		t.Errorf("DefaultConfigPath = %q", got)
	}
	if got := DefaultHostKeyPath(sd); got != sd+"/secrets/ssh_host_ed25519_key" {
		t.Errorf("DefaultHostKeyPath = %q", got)
	}
	if got := DefaultEncryptionKeyPath(sd); got != sd+"/secrets/credential-key-v1" {
		t.Errorf("DefaultEncryptionKeyPath = %q", got)
	}
}

func TestApplyStateDir(t *testing.T) {
	env := newValidEnv(t)
	cfg := Default()
	cfg.Deployment.CoderURL = "https://coder.example.com"
	cfg.Deployment.CoderBinary = env.coderBin

	// CLI flag wins: state dir comes from the flag, secret defaults derive from it.
	ApplyStateDir(cfg, env.stateDir)
	if cfg.State.Dir != env.stateDir {
		t.Fatalf("state.dir = %q, want %q", cfg.State.Dir, env.stateDir)
	}
	wantHost := DefaultHostKeyPath(env.stateDir)
	if cfg.SSH.HostKeys[0] != wantHost {
		t.Errorf("host key default = %q, want %q", cfg.SSH.HostKeys[0], wantHost)
	}
	wantKey := DefaultEncryptionKeyPath(env.stateDir)
	if cfg.Encryption.Keys["v1"] != wantKey {
		t.Errorf("encryption key default = %q, want %q", cfg.Encryption.Keys["v1"], wantKey)
	}

	// env: sources are references, not paths — path resolution must leave
	// them untouched or the provider sees a corrupted reference.
	cfgEnv := Default()
	cfgEnv.Deployment.CoderURL = "https://coder.example.com"
	cfgEnv.Encryption.Keys = map[string]string{"v1": "env:CSGW_ENCRYPTION_KEY_V1"}
	resolveRelativePaths(cfgEnv, env.stateDir)
	if got := cfgEnv.Encryption.Keys["v1"]; got != "env:CSGW_ENCRYPTION_KEY_V1" {
		t.Errorf("env source resolved = %q, want untouched", got)
	}

	// Explicit config values are preserved (only empty ones are defaulted).
	cfg2, _ := validConfig(t)
	ApplyStateDir(cfg2, env.stateDir)
	if cfg2.SSH.HostKeys[0] == wantHost {
		t.Error("explicit host key was overwritten by ApplyStateDir")
	}
}

func TestValidate(t *testing.T) {
	type mutator func(t *testing.T, c *Config, env validEnv)
	cases := []struct {
		name    string
		mutate  mutator
		wantErr string
	}{
		{"valid baseline", func(t *testing.T, c *Config, e validEnv) {}, ""},

		{"no host key", func(t *testing.T, c *Config, e validEnv) {
			c.SSH.HostKeys = nil
		}, "ssh.host_keys"},
		{"unreadable host key", func(t *testing.T, c *Config, e validEnv) {
			c.SSH.HostKeys = []string{filepath.Join(e.dir, "missing")}
		}, "ssh.host_keys"},
		{"group-writable host key", func(t *testing.T, c *Config, e validEnv) {
			p := filepath.Join(e.dir, "hk-gw")
			writeFile(t, p, []byte("k"), 0o620)
			c.SSH.HostKeys = []string{p}
		}, "ssh.host_keys"},
		{"world-writable host key", func(t *testing.T, c *Config, e validEnv) {
			p := filepath.Join(e.dir, "hk-ww")
			writeFile(t, p, []byte("k"), 0o602)
			c.SSH.HostKeys = []string{p}
		}, "ssh.host_keys"},
		{"ssh certificates enabled", func(t *testing.T, c *Config, e validEnv) {
			c.SSH.AllowSSHCertificates = true
		}, "ssh.allow_ssh_certificates"},

		{"no encryption key", func(t *testing.T, c *Config, e validEnv) {
			c.Encryption.Keys = nil
		}, "encryption"},
		{"active key id not in keys", func(t *testing.T, c *Config, e validEnv) {
			c.Encryption.ActiveKeyID = "v99"
		}, "encryption.active_key_id"},
		{"empty active key id", func(t *testing.T, c *Config, e validEnv) {
			c.Encryption.ActiveKeyID = ""
		}, "encryption.active_key_id"},
		{"missing encryption key file", func(t *testing.T, c *Config, e validEnv) {
			c.Encryption.Keys = map[string]string{"v1": filepath.Join(e.dir, "missing")}
		}, "encryption.keys"},
		{"world-writable encryption key file", func(t *testing.T, c *Config, e validEnv) {
			p := filepath.Join(e.dir, "ek-ww")
			writeFile(t, p, []byte("k"), 0o606)
			c.Encryption.Keys = map[string]string{"v1": p}
		}, "encryption.keys"},
		{"unsupported provider", func(t *testing.T, c *Config, e validEnv) {
			c.Encryption.Provider = "vault"
		}, "encryption.provider"},

		{"coder_url garbage", func(t *testing.T, c *Config, e validEnv) {
			c.Deployment.CoderURL = "://not-a-url"
		}, "deployment.coder_url"},
		{"coder_url http rejected", func(t *testing.T, c *Config, e validEnv) {
			c.Deployment.CoderURL = "http://coder.example.com"
		}, "deployment.coder_url"},
		{"coder_url empty", func(t *testing.T, c *Config, e validEnv) {
			c.Deployment.CoderURL = ""
		}, "deployment.coder_url"},

		{"wait mode invalid", func(t *testing.T, c *Config, e validEnv) {
			c.Deployment.Wait = "maybe"
		}, "deployment.wait"},

		{"coder_binary missing", func(t *testing.T, c *Config, e validEnv) {
			c.Deployment.CoderBinary = filepath.Join(e.dir, "no-such-binary")
		}, "deployment.coder_binary"},
		{"coder_binary not executable", func(t *testing.T, c *Config, e validEnv) {
			p := filepath.Join(e.dir, "coder-noexec")
			writeFile(t, p, []byte("#!/bin/sh\n"), 0o644)
			c.Deployment.CoderBinary = p
		}, "deployment.coder_binary"},
		{"coder_binary empty", func(t *testing.T, c *Config, e validEnv) {
			c.Deployment.CoderBinary = ""
		}, "deployment.coder_binary"},

		{"zero limit", func(t *testing.T, c *Config, e validEnv) {
			c.Limits.UnauthenticatedConnections = 0
		}, "limits.unauthenticated_connections"},
		{"negative limit", func(t *testing.T, c *Config, e validEnv) {
			c.Limits.ChannelsPerConnection = -1
		}, "limits.channels_per_connection"},
		{"zero stderr buffer", func(t *testing.T, c *Config, e validEnv) {
			c.Limits.StderrBufferBytes = 0
		}, "limits.stderr_buffer_bytes"},

		{"zero handshake timeout", func(t *testing.T, c *Config, e validEnv) {
			c.Listen.HandshakeTimeout = Duration(0)
		}, "listen.handshake_timeout"},
		{"zero workspace connect timeout", func(t *testing.T, c *Config, e validEnv) {
			c.Deployment.WorkspaceConnectTimeout = Duration(0)
		}, "deployment.workspace_connect_timeout"},
		{"zero token validation timeout", func(t *testing.T, c *Config, e validEnv) {
			c.Deployment.TokenValidationTimeout = Duration(0)
		}, "deployment.token_validation_timeout"},
		{"zero process shutdown grace", func(t *testing.T, c *Config, e validEnv) {
			c.Limits.ProcessShutdownGrace = Duration(0)
		}, "limits.process_shutdown_grace"},

		{"state.dir empty", func(t *testing.T, c *Config, e validEnv) {
			c.State.Dir = ""
		}, "state.dir"},
		{"state.dir missing", func(t *testing.T, c *Config, e validEnv) {
			c.State.Dir = filepath.Join(e.dir, "no-such-dir")
		}, "state.dir"},
		{"state.dir not a directory", func(t *testing.T, c *Config, e validEnv) {
			c.State.Dir = e.hostKey
		}, "state.dir"},
		{"state.dir not writable", func(t *testing.T, c *Config, e validEnv) {
			d := filepath.Join(e.dir, "ro-state")
			if err := os.MkdirAll(d, 0o500); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(d, 0o500); err != nil {
				t.Fatal(err)
			}
			c.State.Dir = d
		}, "state.dir"},
		{"zero audit retention", func(t *testing.T, c *Config, e validEnv) {
			c.State.AuditRetentionDays = 0
		}, "state.audit_retention_days"},

		{"enrollment user empty when enabled", func(t *testing.T, c *Config, e validEnv) {
			c.Enrollment.User = ""
		}, "enrollment.user"},
		{"enrollment zero max attempts", func(t *testing.T, c *Config, e validEnv) {
			c.Enrollment.MaxAttempts = 0
		}, "enrollment.max_attempts"},
		{"enrollment negative max attempts", func(t *testing.T, c *Config, e validEnv) {
			c.Enrollment.MaxAttempts = -1
		}, "enrollment.max_attempts"},
		{"enrollment zero timeout", func(t *testing.T, c *Config, e validEnv) {
			c.Enrollment.Timeout = Duration(0)
		}, "enrollment.timeout"},
		{"enrollment disabled tolerates zero knobs", func(t *testing.T, c *Config, e validEnv) {
			c.Enrollment.Enabled = false
			c.Enrollment.User = ""
			c.Enrollment.MaxAttempts = 0
			c.Enrollment.Timeout = Duration(0)
		}, ""},

		{"tls ca file missing", func(t *testing.T, c *Config, e validEnv) {
			c.Deployment.TLS.CAFile = filepath.Join(e.dir, "missing-ca")
		}, "deployment.tls.ca_file"},
		{"tls client key group-writable", func(t *testing.T, c *Config, e validEnv) {
			cert := filepath.Join(e.dir, "client.crt")
			key := filepath.Join(e.dir, "client.key")
			writeFile(t, cert, []byte("cert"), 0o644)
			writeFile(t, key, []byte("key"), 0o620)
			c.Deployment.TLS.ClientCertFile = cert
			c.Deployment.TLS.ClientKeyFile = key
		}, "deployment.tls.client_key_file"},
		{"tls key without cert", func(t *testing.T, c *Config, e validEnv) {
			key := filepath.Join(e.dir, "client.key")
			writeFile(t, key, []byte("key"), 0o600)
			c.Deployment.TLS.ClientKeyFile = key
		}, "deployment.tls"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, env := validConfig(t)
			tc.mutate(t, cfg, env)
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid config, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not name field %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateCollectsMultipleErrors(t *testing.T) {
	cfg, _ := validConfig(t)
	cfg.SSH.HostKeys = nil
	cfg.Deployment.Wait = "bogus"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "ssh.host_keys") || !strings.Contains(err.Error(), "deployment.wait") {
		t.Errorf("expected both field names in joined error, got: %v", err)
	}
}

// Regression: env: key sources are provider references, not files. Load
// must not stat them (a Helm deployment with env-injected keys failed to
// boot because validateEncryption treated the reference as a path).
func TestLoadEnvKeySource(t *testing.T) {
	dir := t.TempDir()
	raw := `ssh:
  host_keys:
    - secrets/ssh_host_ed25519_key
deployment:
  id: primary
  coder_url: https://coder.example.com
  coder_binary: /usr/local/bin/coder
encryption:
  provider: file
  active_key_id: v1
  keys:
    v1: env:CSGW_TEST_LOAD_KEY
`
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets", "ssh_host_ed25519_key"), []byte("host-key"), 0o600); err != nil {
		t.Fatalf("write host key: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load with env: key source: %v", err)
	}
}
