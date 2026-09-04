// Package config loads and validates the gateway YAML configuration (§28).
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration decoded from YAML strings such as "30s" or "5m".
type Duration time.Duration

func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

type Config struct {
	Version       int           `yaml:"version"`
	Listen        Listen        `yaml:"listen"`
	SSH           SSH           `yaml:"ssh"`
	State         State         `yaml:"state"`
	Encryption    Encryption    `yaml:"encryption"`
	Deployment    Deployment    `yaml:"deployment"`
	Limits        Limits        `yaml:"limits"`
	Maintenance   Maintenance   `yaml:"maintenance"`
	Enrollment    Enrollment    `yaml:"enrollment"`
	Observability Observability `yaml:"observability"`
}

type Listen struct {
	Address            string   `yaml:"address"`
	HandshakeTimeout   Duration `yaml:"handshake_timeout"`
	RenewalAuthTimeout Duration `yaml:"renewal_auth_timeout"`
	TCPKeepalive       Duration `yaml:"tcp_keepalive"`
	ProxyProtocol      bool     `yaml:"proxy_protocol"`
}

type SSH struct {
	TransportUser        string   `yaml:"transport_user"`
	MaintenanceUser      string   `yaml:"maintenance_user"`
	ServerVersion        string   `yaml:"server_version"`
	HostKeys             []string `yaml:"host_keys"`
	AllowSSHCertificates bool     `yaml:"allow_ssh_certificates"`
}

type State struct {
	Dir                string `yaml:"dir"`
	AuditRetentionDays int    `yaml:"audit_retention_days"`
}

type Encryption struct {
	Provider    string            `yaml:"provider"`
	ActiveKeyID string            `yaml:"active_key_id"`
	Keys        map[string]string `yaml:"keys"`
}

type Deployment struct {
	ID                      string   `yaml:"id"`
	CoderURL                string   `yaml:"coder_url"`
	TargetSuffix            string   `yaml:"target_suffix"`
	CoderBinary             string   `yaml:"coder_binary"`
	CoderGlobalConfig       string   `yaml:"coder_global_config"`
	WorkingDirectory        string   `yaml:"working_directory"`
	Autostart               bool     `yaml:"autostart"`
	Wait                    string   `yaml:"wait"`
	WorkspaceConnectTimeout Duration `yaml:"workspace_connect_timeout"`
	TokenValidationTimeout  Duration `yaml:"token_validation_timeout"`
	TokenValidationCache    Duration `yaml:"token_validation_cache"`
	TLS                     TLS      `yaml:"tls"`
	Network                 Network  `yaml:"network"`
}

type TLS struct {
	CAFile         string `yaml:"ca_file"`
	ClientCertFile string `yaml:"client_cert_file"`
	ClientKeyFile  string `yaml:"client_key_file"`
}

type Network struct {
	DisableCoderTelemetry bool   `yaml:"disable_coder_telemetry"`
	HTTPSProxy            string `yaml:"https_proxy"`
	NoProxy               string `yaml:"no_proxy"`
}

type Limits struct {
	UnauthenticatedConnections         int      `yaml:"unauthenticated_connections"`
	Handshakes                         int      `yaml:"handshakes"`
	ConnectionsPerIP                   int      `yaml:"connections_per_ip"`
	ConnectionsPerKey                  int      `yaml:"connections_per_key"`
	ConnectionsPerAccount              int      `yaml:"connections_per_account"`
	ChannelsPerConnection              int      `yaml:"channels_per_connection"`
	ChannelsPerAccount                 int      `yaml:"channels_per_account"`
	CoderProcesses                     int      `yaml:"coder_processes"`
	CoderAPIRequests                   int      `yaml:"coder_api_requests"`
	RenewalAttemptsPerConnection       int      `yaml:"renewal_attempts_per_connection"`
	RenewalAttemptsPerAccountPerMinute int      `yaml:"renewal_attempts_per_account_per_minute"`
	ProcessShutdownGrace               Duration `yaml:"process_shutdown_grace"`
	StderrBufferBytes                  int      `yaml:"stderr_buffer_bytes"`
}

type Maintenance struct {
	Enabled                           bool     `yaml:"enabled"`
	SessionTimeout                    Duration `yaml:"session_timeout"`
	InputTimeout                      Duration `yaml:"input_timeout"`
	BindOnFirstTokenRequiresAdminFlag bool     `yaml:"bind_on_first_token_requires_admin_flag"`
}

// Enrollment configures the CD-2 init@ token-anchored self-enrollment flow.
// Enabled by default: self-configuration is the primary onboarding path.
type Enrollment struct {
	// Enabled arms the enrollment user. False makes the enrollment
	// username behave exactly like any unknown username (§35).
	Enabled bool `yaml:"enabled"`
	// User is the outer SSH username that triggers enrollment
	// (default "init"). It must differ from the transport and
	// maintenance usernames.
	User string `yaml:"user"`
	// MaxAttempts bounds candidate token attempts per enrollment
	// connection (mirrors limits.renewal_attempts_per_connection).
	MaxAttempts int `yaml:"max_attempts"`
	// Timeout extends the connection deadline while enrollment waits for
	// a token (mirrors listen.renewal_auth_timeout).
	Timeout Duration `yaml:"timeout"`
}

type Observability struct {
	LogFormat      string `yaml:"log_format"`
	LogLevel       string `yaml:"log_level"`
	MetricsAddress string `yaml:"metrics_address"`
	HealthAddress  string `yaml:"health_address"`
}

// Default returns a Config with the §20/§28 example values. Secrets and
// state.dir are left empty: supply them via YAML or ApplyStateDir.
func Default() *Config {
	return &Config{
		Version: 1,
		Listen: Listen{
			Address:            ":22",
			HandshakeTimeout:   Duration(30 * time.Second),
			RenewalAuthTimeout: Duration(5 * time.Minute),
			TCPKeepalive:       Duration(30 * time.Second),
			ProxyProtocol:      false,
		},
		SSH: SSH{
			TransportUser:        "coder",
			MaintenanceUser:      "auth",
			ServerVersion:        "SSH-2.0-CoderSSHGW_0.1",
			AllowSSHCertificates: false,
		},
		State: State{
			AuditRetentionDays: 90,
		},
		Encryption: Encryption{
			Provider: "file",
		},
		Deployment: Deployment{
			ID:                      "primary",
			CoderBinary:             "/usr/local/bin/coder",
			CoderGlobalConfig:       "/var/lib/coder-ssh-gateway/coder-config",
			WorkingDirectory:        "/var/empty/coder-ssh-gateway",
			Autostart:               true,
			Wait:                    "auto",
			WorkspaceConnectTimeout: Duration(5 * time.Minute),
			TokenValidationTimeout:  Duration(10 * time.Second),
			TokenValidationCache:    Duration(15 * time.Second),
			Network: Network{
				DisableCoderTelemetry: true,
			},
		},
		Limits: Limits{
			UnauthenticatedConnections:         128,
			Handshakes:                         64,
			ConnectionsPerIP:                   16,
			ConnectionsPerKey:                  8,
			ConnectionsPerAccount:              8,
			ChannelsPerConnection:              4,
			ChannelsPerAccount:                 8,
			CoderProcesses:                     128,
			CoderAPIRequests:                   32,
			RenewalAttemptsPerConnection:       3,
			RenewalAttemptsPerAccountPerMinute: 5,
			ProcessShutdownGrace:               Duration(5 * time.Second),
			StderrBufferBytes:                  65536,
		},
		Maintenance: Maintenance{
			Enabled:                           true,
			SessionTimeout:                    Duration(5 * time.Minute),
			InputTimeout:                      Duration(2 * time.Minute),
			BindOnFirstTokenRequiresAdminFlag: true,
		},
		Enrollment: Enrollment{
			Enabled:     true,
			User:        "init",
			MaxAttempts: 3,
			Timeout:     Duration(5 * time.Minute),
		},
		Observability: Observability{
			LogFormat:      "json",
			LogLevel:       "info",
			MetricsAddress: "127.0.0.1:9090",
			HealthAddress:  "127.0.0.1:9091",
		},
	}
}

// Parse reads path into a Config over Default() values with strict field
// checking. Relative paths inside the file are resolved against the config
// file's directory. Parse does not validate; call Validate or use Load.
func Parse(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	resolveRelativePaths(cfg, filepath.Dir(path))
	return cfg, nil
}

// Load parses path and validates the result for startup.
func Load(path string) (*Config, error) {
	cfg, err := Parse(path)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

func DefaultConfigPath(stateDir string) string {
	return filepath.Join(stateDir, "config.yaml")
}

func DefaultHostKeyPath(stateDir string) string {
	return filepath.Join(stateDir, "secrets", "ssh_host_ed25519_key")
}

func DefaultEncryptionKeyPath(stateDir string) string {
	return filepath.Join(stateDir, "secrets", "credential-key-v1")
}

// ApplyStateDir implements "--state-dir wins": a non-empty stateDir overrides
// state.dir from the config file, and any unset secret paths default to the
// conventional locations under the state directory. Explicit config values
// are never overwritten.
func ApplyStateDir(cfg *Config, stateDir string) {
	if stateDir != "" {
		cfg.State.Dir = stateDir
	}
	if len(cfg.SSH.HostKeys) == 0 && cfg.State.Dir != "" {
		cfg.SSH.HostKeys = []string{DefaultHostKeyPath(cfg.State.Dir)}
	}
	if len(cfg.Encryption.Keys) == 0 && cfg.State.Dir != "" {
		cfg.Encryption.Keys = map[string]string{"v1": DefaultEncryptionKeyPath(cfg.State.Dir)}
		if cfg.Encryption.ActiveKeyID == "" {
			cfg.Encryption.ActiveKeyID = "v1"
		}
	}
}

func resolveRelativePaths(cfg *Config, base string) {
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	for i, k := range cfg.SSH.HostKeys {
		cfg.SSH.HostKeys[i] = resolve(k)
	}
	for id, k := range cfg.Encryption.Keys {
		cfg.Encryption.Keys[id] = resolve(k)
	}
	cfg.State.Dir = resolve(cfg.State.Dir)
	cfg.Deployment.CoderBinary = resolve(cfg.Deployment.CoderBinary)
	cfg.Deployment.CoderGlobalConfig = resolve(cfg.Deployment.CoderGlobalConfig)
	cfg.Deployment.WorkingDirectory = resolve(cfg.Deployment.WorkingDirectory)
	cfg.Deployment.TLS.CAFile = resolve(cfg.Deployment.TLS.CAFile)
	cfg.Deployment.TLS.ClientCertFile = resolve(cfg.Deployment.TLS.ClientCertFile)
	cfg.Deployment.TLS.ClientKeyFile = resolve(cfg.Deployment.TLS.ClientKeyFile)
}
