package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
)

var validWaitModes = map[string]bool{"yes": true, "no": true, "auto": true}

// Validate checks the fail-startup conditions of §28.1 (adapted for the
// flat-file store) plus the state-dir checks. All violations are collected
// and returned as one joined error naming each offending field.
func (c *Config) Validate() error {
	var errs []error

	c.validateBindAddresses(&errs)
	c.validateSSH(&errs)
	c.validateState(&errs)
	c.validateEncryption(&errs)
	c.validateDeployment(&errs)
	c.validateLimits(&errs)
	c.validateMaintenance(&errs)
	c.validateEnrollment(&errs)

	return errors.Join(errs...)
}

func (c *Config) validateBindAddresses(errs *[]error) {
	addresses := []struct {
		field    string
		value    string
		optional bool
	}{
		{"listen.address", c.Listen.Address, false},
		{"observability.metrics_address", c.Observability.MetricsAddress, true},
		{"observability.health_address", c.Observability.HealthAddress, true},
	}
	for _, address := range addresses {
		if address.optional && address.value == "" {
			continue
		}
		if err := checkListenAddress(address.value); err != nil {
			*errs = append(*errs, fmt.Errorf("%s: %w", address.field, err))
		}
	}
}

func (c *Config) validateSSH(errs *[]error) {
	if c.SSH.AllowSSHCertificates {
		*errs = append(*errs, errors.New("ssh.allow_ssh_certificates: true is unsupported; SSH certificates are always rejected"))
	}
	if len(c.SSH.HostKeys) == 0 {
		*errs = append(*errs, errors.New("ssh.host_keys: at least one host key is required"))
	}
	for _, k := range c.SSH.HostKeys {
		checkSecretFile(errs, "ssh.host_keys", k)
	}
}

func (c *Config) validateState(errs *[]error) {
	if c.State.Dir == "" {
		*errs = append(*errs, errors.New("state.dir: required (set in config or pass --state-dir)"))
	} else {
		fi, err := os.Stat(c.State.Dir)
		switch {
		case err != nil:
			*errs = append(*errs, fmt.Errorf("state.dir: %s: %v", c.State.Dir, err))
		case !fi.IsDir():
			*errs = append(*errs, fmt.Errorf("state.dir: %s is not a directory", c.State.Dir))
		default:
			probe, err := os.CreateTemp(c.State.Dir, ".write-probe-*")
			if err != nil {
				*errs = append(*errs, fmt.Errorf("state.dir: %s is not writable: %v", c.State.Dir, err))
			} else {
				_ = probe.Close()
				_ = os.Remove(probe.Name())
			}
		}
	}
	if c.State.AuditRetentionDays <= 0 {
		*errs = append(*errs, fmt.Errorf("state.audit_retention_days: must be positive, got %d", c.State.AuditRetentionDays))
	}
}

func (c *Config) validateEncryption(errs *[]error) {
	if c.Encryption.Provider != "file" {
		*errs = append(*errs, fmt.Errorf("encryption.provider: unsupported provider %q (only \"file\")", c.Encryption.Provider))
	}
	if len(c.Encryption.Keys) == 0 {
		*errs = append(*errs, errors.New("encryption.keys: at least one encryption key is required"))
	}
	if c.Encryption.ActiveKeyID == "" {
		*errs = append(*errs, errors.New("encryption.active_key_id: required"))
	} else if _, ok := c.Encryption.Keys[c.Encryption.ActiveKeyID]; !ok && len(c.Encryption.Keys) > 0 {
		*errs = append(*errs, fmt.Errorf("encryption.active_key_id: %q not found in encryption.keys", c.Encryption.ActiveKeyID))
	}
	for id, path := range c.Encryption.Keys {
		checkSecretFile(errs, "encryption.keys."+id, path)
	}
}

func (c *Config) validateDeployment(errs *[]error) {
	u, err := url.Parse(c.Deployment.CoderURL)
	if c.Deployment.CoderURL == "" || err != nil || u.Host == "" {
		*errs = append(*errs, fmt.Errorf("deployment.coder_url: invalid URL %q", c.Deployment.CoderURL))
	} else if u.Scheme != "https" {
		*errs = append(*errs, fmt.Errorf("deployment.coder_url: must be HTTPS, got scheme %q", u.Scheme))
	}

	if !validWaitModes[c.Deployment.Wait] {
		*errs = append(*errs, fmt.Errorf("deployment.wait: must be yes|no|auto, got %q", c.Deployment.Wait))
	}

	if c.Deployment.CoderBinary == "" {
		*errs = append(*errs, errors.New("deployment.coder_binary: required"))
	} else if fi, err := os.Stat(c.Deployment.CoderBinary); err != nil {
		*errs = append(*errs, fmt.Errorf("deployment.coder_binary: %s: %v", c.Deployment.CoderBinary, err))
	} else if fi.IsDir() || fi.Mode().Perm()&0o111 == 0 {
		*errs = append(*errs, fmt.Errorf("deployment.coder_binary: %s is not executable", c.Deployment.CoderBinary))
	}

	for field, d := range map[string]Duration{
		"deployment.workspace_connect_timeout": c.Deployment.WorkspaceConnectTimeout,
		"deployment.token_validation_timeout":  c.Deployment.TokenValidationTimeout,
		"deployment.token_validation_cache":    c.Deployment.TokenValidationCache,
	} {
		if d <= 0 {
			*errs = append(*errs, fmt.Errorf("%s: must be positive, got %v", field, d.Std()))
		}
	}

	tls := c.Deployment.TLS
	if tls.CAFile != "" {
		checkReadableFile(errs, "deployment.tls.ca_file", tls.CAFile)
	}
	if tls.ClientKeyFile != "" && tls.ClientCertFile == "" {
		*errs = append(*errs, errors.New("deployment.tls: client_key_file requires client_cert_file"))
	}
	if tls.ClientCertFile != "" {
		checkReadableFile(errs, "deployment.tls.client_cert_file", tls.ClientCertFile)
	}
	if tls.ClientKeyFile != "" {
		checkSecretFile(errs, "deployment.tls.client_key_file", tls.ClientKeyFile)
	}
}

func (c *Config) validateLimits(errs *[]error) {
	ints := map[string]int{
		"limits.unauthenticated_connections":             c.Limits.UnauthenticatedConnections,
		"limits.handshakes":                              c.Limits.Handshakes,
		"limits.connections_per_ip":                      c.Limits.ConnectionsPerIP,
		"limits.connections_per_key":                     c.Limits.ConnectionsPerKey,
		"limits.connections_per_account":                 c.Limits.ConnectionsPerAccount,
		"limits.channels_per_connection":                 c.Limits.ChannelsPerConnection,
		"limits.channels_per_account":                    c.Limits.ChannelsPerAccount,
		"limits.coder_processes":                         c.Limits.CoderProcesses,
		"limits.coder_api_requests":                      c.Limits.CoderAPIRequests,
		"limits.renewal_attempts_per_connection":         c.Limits.RenewalAttemptsPerConnection,
		"limits.renewal_attempts_per_account_per_minute": c.Limits.RenewalAttemptsPerAccountPerMinute,
		"limits.stderr_buffer_bytes":                     c.Limits.StderrBufferBytes,
	}
	for field, v := range ints {
		if v <= 0 {
			*errs = append(*errs, fmt.Errorf("%s: must be positive, got %d", field, v))
		}
	}
	if c.Limits.ProcessShutdownGrace <= 0 {
		*errs = append(*errs, fmt.Errorf("limits.process_shutdown_grace: must be positive, got %v", c.Limits.ProcessShutdownGrace.Std()))
	}
	if c.Listen.HandshakeTimeout <= 0 {
		*errs = append(*errs, fmt.Errorf("listen.handshake_timeout: must be positive, got %v", c.Listen.HandshakeTimeout.Std()))
	}
	if c.Listen.RenewalAuthTimeout <= 0 {
		*errs = append(*errs, fmt.Errorf("listen.renewal_auth_timeout: must be positive, got %v", c.Listen.RenewalAuthTimeout.Std()))
	}
	if c.Listen.TCPKeepalive <= 0 {
		*errs = append(*errs, fmt.Errorf("listen.tcp_keepalive: must be positive, got %v", c.Listen.TCPKeepalive.Std()))
	}
}

func (c *Config) validateMaintenance(errs *[]error) {
	if c.Maintenance.SessionTimeout <= 0 {
		*errs = append(*errs, fmt.Errorf("maintenance.session_timeout: must be positive, got %v", c.Maintenance.SessionTimeout.Std()))
	}
	if c.Maintenance.InputTimeout <= 0 {
		*errs = append(*errs, fmt.Errorf("maintenance.input_timeout: must be positive, got %v", c.Maintenance.InputTimeout.Std()))
	}
}

func (c *Config) validateEnrollment(errs *[]error) {
	if !c.Enrollment.Enabled {
		return
	}
	if c.Enrollment.User == "" {
		*errs = append(*errs, errors.New("enrollment.user: required when enrollment is enabled"))
	} else if c.Enrollment.User == c.SSH.TransportUser || c.Enrollment.User == c.SSH.MaintenanceUser {
		*errs = append(*errs, fmt.Errorf("enrollment.user: %q collides with the transport or maintenance username", c.Enrollment.User))
	}
	if c.Enrollment.MaxAttempts <= 0 {
		*errs = append(*errs, fmt.Errorf("enrollment.max_attempts: must be positive, got %d", c.Enrollment.MaxAttempts))
	}
	if c.Enrollment.Timeout <= 0 {
		*errs = append(*errs, fmt.Errorf("enrollment.timeout: must be positive, got %v", c.Enrollment.Timeout.Std()))
	}
}

// checkSecretFile requires the file to exist, be a regular file, and not be
// writable by group or world (§28.1).
func checkSecretFile(errs *[]error, field, path string) {
	fi, ok := checkReadableFile(errs, field, path)
	if !ok {
		return
	}
	if fi.Mode().Perm()&0o022 != 0 {
		*errs = append(*errs, fmt.Errorf("%s: %s is group/world-writable (mode %04o); chmod 0600", field, path, fi.Mode().Perm()))
	}
}

func checkReadableFile(errs *[]error, field, path string) (os.FileInfo, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %s: %v", field, path, err))
		return nil, false
	}
	if !fi.Mode().IsRegular() {
		*errs = append(*errs, fmt.Errorf("%s: %s is not a regular file", field, path))
		return nil, false
	}
	return fi, true
}
