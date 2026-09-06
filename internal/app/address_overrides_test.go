package app

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/taxilian/coder-ssh-gateway/internal/config"
)

func TestBindAddressPrecedence(t *testing.T) {
	tests := []struct {
		name        string
		config      [3]string
		env         [3]string
		flags       []string
		want        [3]string
		wantApplied []string
	}{
		{
			name: "defaults when no higher layer is present",
			want: [3]string{":22", "127.0.0.1:9090", "127.0.0.1:9091"},
		},
		{
			name:   "config overrides defaults",
			config: [3]string{"127.0.0.1:1222", "127.0.0.1:19090", "127.0.0.1:19091"},
			want:   [3]string{"127.0.0.1:1222", "127.0.0.1:19090", "127.0.0.1:19091"},
		},
		{
			name:   "environment overrides config",
			config: [3]string{"127.0.0.1:1222", "127.0.0.1:19090", "127.0.0.1:19091"},
			env:    [3]string{"0.0.0.0:2222", ":29090", "[::]:29091"},
			want:   [3]string{"0.0.0.0:2222", ":29090", "[::]:29091"},
		},
		{
			name:   "flags override environment",
			config: [3]string{"127.0.0.1:1222", "127.0.0.1:19090", "127.0.0.1:19091"},
			env:    [3]string{"127.0.0.1:2222", "127.0.0.1:29090", "127.0.0.1:29091"},
			flags: []string{
				"--listen-address", "0.0.0.0:3222",
				"--metrics-address=:39090",
				"--health-address", "[::]:39091",
			},
			want:        [3]string{"0.0.0.0:3222", ":39090", "[::]:39091"},
			wantApplied: []string{"listen.address", "observability.metrics_address", "observability.health_address"},
		},
		{
			name:        "partial flag override preserves lower-layer winners",
			config:      [3]string{"127.0.0.1:1222", "127.0.0.1:19090", "127.0.0.1:19091"},
			env:         [3]string{"127.0.0.1:2222", "127.0.0.1:29090", "127.0.0.1:29091"},
			flags:       []string{"--metrics-address", "0.0.0.0:39090"},
			want:        [3]string{"127.0.0.1:2222", "0.0.0.0:39090", "127.0.0.1:29091"},
			wantApplied: []string{"observability.metrics_address"},
		},
		{
			name:   "empty environment values do not override config",
			config: [3]string{"127.0.0.1:1222", "127.0.0.1:19090", "127.0.0.1:19091"},
			env:    [3]string{"", "", ""},
			want:   [3]string{"127.0.0.1:1222", "127.0.0.1:19090", "127.0.0.1:19091"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			if tt.config[0] != "" {
				cfg.Listen.Address = tt.config[0]
				cfg.Observability.MetricsAddress = tt.config[1]
				cfg.Observability.HealthAddress = tt.config[2]
			}
			t.Setenv(config.EnvListenAddress, tt.env[0])
			t.Setenv(config.EnvMetricsAddress, tt.env[1])
			t.Setenv(config.EnvHealthAddress, tt.env[2])
			if _, err := config.ApplyEnvOverrides(cfg); err != nil {
				t.Fatalf("ApplyEnvOverrides: %v", err)
			}

			c := &cli{}
			rest, err := c.parseGlobalFlags(append(tt.flags, "serve"))
			if err != nil {
				t.Fatalf("parseGlobalFlags: %v", err)
			}
			if !reflect.DeepEqual(rest, []string{"serve"}) {
				t.Fatalf("remaining args = %v, want [serve]", rest)
			}
			applied := c.applyBindAddressOverrides(cfg)

			got := [3]string{cfg.Listen.Address, cfg.Observability.MetricsAddress, cfg.Observability.HealthAddress}
			if got != tt.want {
				t.Errorf("addresses = %q, want %q", got, tt.want)
			}
			var fields []string
			for _, override := range applied {
				fields = append(fields, override.field)
			}
			if !reflect.DeepEqual(fields, tt.wantApplied) {
				t.Errorf("applied fields = %v, want %v", fields, tt.wantApplied)
			}
		})
	}
}

func TestBindAddressGlobalFlagsRequireValues(t *testing.T) {
	for _, flag := range []string{"--listen-address", "--metrics-address", "--health-address"} {
		t.Run(flag, func(t *testing.T) {
			for _, args := range [][]string{{flag}, {flag + "="}} {
				if _, err := (&cli{}).parseGlobalFlags(args); err == nil {
					t.Errorf("parseGlobalFlags(%v) succeeded, want error", args)
				}
			}
		})
	}
}

func TestLogBindAddressOverrides(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	overrides := []bindAddressOverride{
		{field: "listen.address", value: "0.0.0.0:2222"},
		{field: "observability.metrics_address", value: ":9090"},
		{field: "observability.health_address", value: "[::]:9091"},
	}

	logBindAddressOverrides(logger, overrides)

	logs := output.String()
	for _, override := range overrides {
		for _, want := range []string{
			`"field":"` + override.field + `"`,
			`"source":"flag"`,
			`"value":"` + override.value + `"`,
		} {
			if !strings.Contains(logs, want) {
				t.Errorf("startup logs missing %q:\n%s", want, logs)
			}
		}
	}
}
