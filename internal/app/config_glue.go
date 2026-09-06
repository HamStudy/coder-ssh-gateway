package app

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/coderapi"
	"github.com/HamStudy/coder-ssh-gateway/internal/config"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
)

// errStateDirRequired reports that neither --state-dir nor state.dir was set.
var errStateDirRequired = errors.New("state directory required: pass --state-dir or set state.dir in the config file")

// loadConfig parses the config file (--config or <state-dir>/config.yaml)
// and applies the --state-dir override. It does NOT validate: validation is
// serve's startup gate and doctor's job; admin commands must work on a
// partially broken deployment.
func (c *cli) loadConfig() (*config.Config, error) {
	path := c.configPath
	if path == "" {
		if c.stateDir == "" {
			return nil, errors.New("no config file: pass --config or --state-dir")
		}
		path = config.DefaultConfigPath(c.stateDir)
	}
	cfg, err := config.Parse(path)
	if err != nil {
		return nil, err
	}
	config.ApplyStateDir(cfg, c.stateDir)
	if cfg.State.Dir == "" {
		return nil, errStateDirRequired
	}
	return cfg, nil
}

// DeploymentUUID derives the stable store UUID for a configured deployment
// label. The config carries a human string (§28 deployment.id, e.g.
// "primary"); store records key on a UUID. The mapping is deterministic so
// every CLI invocation and the server agree without extra state.
func DeploymentUUID(label string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("coder-ssh-gateway/deployment/"+label))
}

// DeploymentFromConfig maps the §28 deployment config onto the runtime
// core.Deployment consumed by coderapi, sshauth, tunnel, and the store.
func DeploymentFromConfig(cfg *config.Config) (core.Deployment, error) {
	dep := core.Deployment{
		ID:           DeploymentUUID(cfg.Deployment.ID),
		CoderBinary:  cfg.Deployment.CoderBinary,
		GlobalConfig: cfg.Deployment.CoderGlobalConfig,
		WorkingDir:   cfg.Deployment.WorkingDirectory,
		Autostart:    cfg.Deployment.Autostart,
		WaitMode:     cfg.Deployment.Wait,
		TLS: core.DeploymentTLS{
			CAFile:   cfg.Deployment.TLS.CAFile,
			CertFile: cfg.Deployment.TLS.ClientCertFile,
			KeyFile:  cfg.Deployment.TLS.ClientKeyFile,
		},
		Network: core.DeploymentNetwork{
			Proxy:                   cfg.Deployment.Network.HTTPSProxy,
			NoProxy:                 cfg.Deployment.Network.NoProxy,
			DisableNetworkTelemetry: cfg.Deployment.Network.DisableCoderTelemetry,
		},
	}
	if cfg.Deployment.CoderURL != "" {
		u, err := url.Parse(cfg.Deployment.CoderURL)
		if err != nil {
			return core.Deployment{}, fmt.Errorf("deployment.coder_url: %w", err)
		}
		dep.CoderURL = u
	}
	return dep, nil
}

// KeyProviderFromConfig builds the file-based envelope key provider (§22.2)
// from the encryption config.
func KeyProviderFromConfig(cfg *config.Config, logger *slog.Logger) *secretbox.FileKeyProvider {
	return &secretbox.FileKeyProvider{
		Keys:     cfg.Encryption.Keys,
		ActiveID: cfg.Encryption.ActiveKeyID,
		Logger:   logger,
	}
}

// VerifierOptionsFromConfig builds coderapi.Options, loading the optional
// custom CA pool and mTLS client credentials (§11.2).
func VerifierOptionsFromConfig(cfg *config.Config) (coderapi.Options, error) {
	opts := coderapi.Options{Timeout: cfg.Deployment.TokenValidationTimeout.Std()}
	if ca := cfg.Deployment.TLS.CAFile; ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return opts, fmt.Errorf("deployment.tls.ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return opts, fmt.Errorf("deployment.tls.ca_file: %s contains no PEM certificates", ca)
		}
		opts.RootCAs = pool
	}
	tlsCfg := cfg.Deployment.TLS
	if tlsCfg.ClientCertFile != "" && tlsCfg.ClientKeyFile != "" {
		cert, err := os.ReadFile(tlsCfg.ClientCertFile)
		if err != nil {
			return opts, fmt.Errorf("deployment.tls.client_cert_file: %w", err)
		}
		key, err := os.ReadFile(tlsCfg.ClientKeyFile)
		if err != nil {
			return opts, fmt.Errorf("deployment.tls.client_key_file: %w", err)
		}
		opts.ClientCertificate = cert
		opts.ClientKey = key
	}
	return opts, nil
}

// openStore opens the state store, wires the encryption key provider, and
// upserts the configured deployment record. Callers must Close the store;
// the flock is held only for the duration of the command.
func (c *cli) openStore(cfg *config.Config, logger *slog.Logger) (*store.Store, error) {
	st, err := store.Open(cfg.State.Dir)
	if err != nil {
		return nil, err
	}
	st.SetKeyProvider(KeyProviderFromConfig(cfg, logger))
	dep, err := DeploymentFromConfig(cfg)
	if err != nil {
		st.Close()
		return nil, err
	}
	if err := st.EnsureDeployment(dep); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}
