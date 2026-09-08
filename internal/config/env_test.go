package config

import (
	"strings"
	"testing"
)

func TestApplyEnvOverrides(t *testing.T) {
	t.Run("all three applied over config values", func(t *testing.T) {
		t.Setenv(EnvListenAddress, "0.0.0.0:2222")
		t.Setenv(EnvMetricsAddress, ":19090")
		t.Setenv(EnvHealthAddress, "[::]:19091")
		cfg := Default()
		cfg.Listen.Address = "127.0.0.1:22"
		cfg.Observability.MetricsAddress = "127.0.0.1:9090"
		cfg.Observability.HealthAddress = "127.0.0.1:9091"

		applied, err := ApplyEnvOverrides(cfg)
		if err != nil {
			t.Fatalf("ApplyEnvOverrides: %v", err)
		}
		if cfg.Listen.Address != "0.0.0.0:2222" {
			t.Errorf("listen.address = %q, want 0.0.0.0:2222", cfg.Listen.Address)
		}
		if cfg.Observability.MetricsAddress != ":19090" {
			t.Errorf("metrics_address = %q, want :19090", cfg.Observability.MetricsAddress)
		}
		if cfg.Observability.HealthAddress != "[::]:19091" {
			t.Errorf("health_address = %q, want [::]:19091", cfg.Observability.HealthAddress)
		}
		for _, want := range []string{EnvListenAddress, EnvMetricsAddress, EnvHealthAddress} {
			found := false
			for _, a := range applied {
				if a == want {
					found = true
				}
			}
			if !found {
				t.Errorf("applied missing %q (got %v)", want, applied)
			}
		}
	})

	t.Run("absent env keeps config value", func(t *testing.T) {
		cfg := Default()
		cfg.Listen.Address = "127.0.0.1:2222"
		applied, err := ApplyEnvOverrides(cfg)
		if err != nil {
			t.Fatalf("ApplyEnvOverrides: %v", err)
		}
		if len(applied) != 0 {
			t.Errorf("applied = %v, want empty", applied)
		}
		if cfg.Listen.Address != "127.0.0.1:2222" {
			t.Errorf("listen.address = %q, want config value kept", cfg.Listen.Address)
		}
	})

	t.Run("empty env value is ignored", func(t *testing.T) {
		t.Setenv(EnvListenAddress, "")
		cfg := Default()
		applied, err := ApplyEnvOverrides(cfg)
		if err != nil {
			t.Fatalf("ApplyEnvOverrides: %v", err)
		}
		if len(applied) != 0 {
			t.Errorf("applied = %v, want empty", applied)
		}
		if cfg.Listen.Address != ":22" {
			t.Errorf("listen.address = %q, want default :22", cfg.Listen.Address)
		}
	})

	t.Run("accepted wildcard forms", func(t *testing.T) {
		for _, addr := range []string{":9090", "0.0.0.0:9090", "[::]:9090", "127.0.0.1:9090", "example.internal:9090"} {
			t.Setenv(EnvListenAddress, addr)
			cfg := Default()
			if _, err := ApplyEnvOverrides(cfg); err != nil {
				t.Errorf("address %q rejected: %v", addr, err)
			}
			if cfg.Listen.Address != addr {
				t.Errorf("listen.address = %q, want %q", cfg.Listen.Address, addr)
			}
		}
	})

	t.Run("invalid values rejected naming the env var", func(t *testing.T) {
		cases := []struct {
			env   string
			value string
		}{
			{EnvListenAddress, ":abc"},
			{EnvListenAddress, "host"},
			{EnvListenAddress, "host:65536"},
			{EnvListenAddress, "host:-1"},
			{EnvListenAddress, "a:b:c"},
			{EnvMetricsAddress, ":notaport"},
			{EnvHealthAddress, "127.0.0.1:0x"},
		}
		for _, tc := range cases {
			t.Run(tc.env+"="+tc.value, func(t *testing.T) {
				t.Setenv(tc.env, tc.value)
				cfg := Default()
				before := cfg.Listen.Address
				applied, err := ApplyEnvOverrides(cfg)
				if err == nil {
					t.Fatalf("want error, got nil (applied %v)", applied)
				}
				if !strings.Contains(err.Error(), tc.env) {
					t.Errorf("error %q does not name the env var", err)
				}
				if cfg.Listen.Address != before {
					t.Errorf("config mutated despite error")
				}
			})
		}
	})

	t.Run("port zero accepted (ephemeral bind)", func(t *testing.T) {
		t.Setenv(EnvMetricsAddress, "127.0.0.1:0")
		cfg := Default()
		if _, err := ApplyEnvOverrides(cfg); err != nil {
			t.Fatalf("ApplyEnvOverrides: %v", err)
		}
		if cfg.Observability.MetricsAddress != "127.0.0.1:0" {
			t.Errorf("metrics_address = %q, want 127.0.0.1:0", cfg.Observability.MetricsAddress)
		}
	})
}

// TestApplyEnvOverridesUsernames pins the username override contract:
// values are plain usernames (never host:port), env beats YAML, empty
// skips, and username semantics (charset, collision) belong to Validate,
// not to the env layer.
func TestApplyEnvOverridesUsernames(t *testing.T) {
	t.Run("both usernames applied over config values", func(t *testing.T) {
		t.Setenv(EnvEnrollmentUser, "signin")
		t.Setenv(EnvKeyManagementUser, "ops")
		cfg := Default()
		cfg.Enrollment.User = "login"
		cfg.KeyManagement.User = "login-admin"

		applied, err := ApplyEnvOverrides(cfg)
		if err != nil {
			t.Fatalf("ApplyEnvOverrides: %v", err)
		}
		if cfg.Enrollment.User != "signin" {
			t.Errorf("enrollment.user = %q, want signin (env beats config)", cfg.Enrollment.User)
		}
		if cfg.KeyManagement.User != "ops" {
			t.Errorf("key_management.user = %q, want ops (env beats config)", cfg.KeyManagement.User)
		}
		for _, want := range []string{EnvEnrollmentUser, EnvKeyManagementUser} {
			found := false
			for _, a := range applied {
				if a == want {
					found = true
				}
			}
			if !found {
				t.Errorf("applied missing %q (got %v)", want, applied)
			}
		}
	})

	t.Run("empty env value is ignored", func(t *testing.T) {
		t.Setenv(EnvKeyManagementUser, "")
		cfg := Default()
		applied, err := ApplyEnvOverrides(cfg)
		if err != nil {
			t.Fatalf("ApplyEnvOverrides: %v", err)
		}
		if len(applied) != 0 {
			t.Errorf("applied = %v, want empty", applied)
		}
		if cfg.KeyManagement.User != "login-admin" {
			t.Errorf("key_management.user = %q, want default login-admin", cfg.KeyManagement.User)
		}
	})

	t.Run("username values are not address-checked", func(t *testing.T) {
		for _, name := range []string{"a", "ops", "keys-lead", strings.Repeat("k", 63)} {
			t.Setenv(EnvKeyManagementUser, name)
			cfg := Default()
			if _, err := ApplyEnvOverrides(cfg); err != nil {
				t.Errorf("username %q rejected: %v", name, err)
			}
			if cfg.KeyManagement.User != name {
				t.Errorf("key_management.user = %q, want %q", cfg.KeyManagement.User, name)
			}
		}
	})

	t.Run("env-induced collision fails Validate not ApplyEnvOverrides", func(t *testing.T) {
		t.Setenv(EnvEnrollmentUser, "login-admin")
		cfg, _ := validConfig(t)
		if _, err := ApplyEnvOverrides(cfg); err != nil {
			t.Fatalf("ApplyEnvOverrides: %v (collision must surface in Validate)", err)
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected collision error from Validate, got nil")
		}
		if !strings.Contains(err.Error(), "enrollment.user and key_management.user must differ") {
			t.Errorf("error %q does not name the collision", err)
		}
	})

	t.Run("invalid charset via env caught by Validate", func(t *testing.T) {
		t.Setenv(EnvKeyManagementUser, "a b")
		cfg, _ := validConfig(t)
		if _, err := ApplyEnvOverrides(cfg); err != nil {
			t.Fatalf("ApplyEnvOverrides: %v (charset must surface in Validate)", err)
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected charset error from Validate, got nil")
		}
		if !strings.Contains(err.Error(), "key_management.user") {
			t.Errorf("error %q does not name key_management.user", err)
		}
	})
}

// TestValidateAcceptsWildcardAddresses proves container-style binds
// (0.0.0.0 / empty host) are not rejected by startup validation for any of
// the three bind addresses.
func TestValidateAcceptsWildcardAddresses(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:9090", ":9090"} {
		cfg, _ := validConfig(t)
		cfg.Listen.Address = addr
		cfg.Observability.MetricsAddress = addr
		cfg.Observability.HealthAddress = addr
		if err := cfg.Validate(); err != nil {
			t.Errorf("address %q: Validate: %v", addr, err)
		}
	}
}

func TestValidateRejectsInvalidBindAddresses(t *testing.T) {
	tests := []struct {
		name  string
		field string
		set   func(*Config)
	}{
		{"listen", "listen.address", func(cfg *Config) { cfg.Listen.Address = ":bad" }},
		{"metrics", "observability.metrics_address", func(cfg *Config) { cfg.Observability.MetricsAddress = "missing-port" }},
		{"health", "observability.health_address", func(cfg *Config) { cfg.Observability.HealthAddress = "127.0.0.1:65536" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, _ := validConfig(t)
			tt.set(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.field) {
				t.Errorf("Validate error %q does not identify %s", err, tt.field)
			}
		})
	}
}

func TestValidateAllowsDisabledOptionalBindAddresses(t *testing.T) {
	cfg, _ := validConfig(t)
	cfg.Observability.MetricsAddress = ""
	cfg.Observability.HealthAddress = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate with disabled optional listeners: %v", err)
	}
}
