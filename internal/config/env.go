package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

// Environment-variable overrides for the bind addresses (12-factor / k8s).
// Precedence everywhere is: CLI flag > env var > config file > default.
const (
	// EnvStateDir resolves the state directory when --state-dir is absent.
	// Precedence: --state-dir flag > CSGW_STATE_DIR > config state.dir.
	EnvStateDir = "CSGW_STATE_DIR"

	EnvListenAddress  = "CSGW_LISTEN_ADDRESS"  // overrides listen.address
	EnvMetricsAddress = "CSGW_METRICS_ADDRESS" // overrides observability.metrics_address
	EnvHealthAddress  = "CSGW_HEALTH_ADDRESS"  // overrides observability.health_address
)

// ApplyEnvOverrides replaces bind addresses in cfg with their CSGW_*
// environment values when set. Each value must be in host:port or :port form
// with a numeric port in 0-65535; an empty host (all interfaces), 0.0.0.0,
// and [::] are accepted (containers bind all interfaces). An unset or empty
// variable leaves the config value untouched. On error the offending env var
// is named and cfg is left unmutated.
//
// Call after Parse + ApplyStateDir and before Validate so validation sees the
// final values. The returned list names the variables that were applied, for
// a startup log line.
func ApplyEnvOverrides(cfg *Config) (applied []string, err error) {
	overrides := []struct {
		env  string
		dest *string
	}{
		{EnvListenAddress, &cfg.Listen.Address},
		{EnvMetricsAddress, &cfg.Observability.MetricsAddress},
		{EnvHealthAddress, &cfg.Observability.HealthAddress},
	}
	var pending []struct {
		dest  *string
		value string
	}
	for _, o := range overrides {
		v, ok := os.LookupEnv(o.env)
		if !ok || v == "" {
			continue
		}
		if err := checkListenAddress(v); err != nil {
			return nil, fmt.Errorf("%s: %w", o.env, err)
		}
		pending = append(pending, struct {
			dest  *string
			value string
		}{o.dest, v})
		applied = append(applied, o.env)
	}
	// Apply only after every value validated, so a bad value never leaves a
	// partially-overridden config.
	for _, p := range pending {
		*p.dest = p.value
	}
	return applied, nil
}

func checkListenAddress(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: must be host:port or :port", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: port %q is not numeric", addr, port)
	}
	if n < 0 || n > 65535 {
		return fmt.Errorf("invalid listen address %q: port %d out of range", addr, n)
	}
	return nil
}
