package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/config"
	"github.com/taxilian/coder-ssh-gateway/internal/store"
)

// cmdInit initializes a state directory per §30.1/§22: store layout, Ed25519
// host key, 32-byte credential encryption key (0600 under 0700 secrets/),
// and a starter config. Idempotent; --force still requires confirmation.
func (c *cli) cmdInit(args []string) int {
	fs := c.newFlagSet("init")
	force := fs.Bool("force", false, "overwrite existing secrets/config (asks for confirmation)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(c.stderr, "error: init takes no arguments\n")
		return exitUsage
	}

	dir := c.stateDir
	if dir == "" {
		if cfg, err := c.loadConfig(); err == nil {
			dir = cfg.State.Dir
		}
	}
	if dir == "" {
		fmt.Fprintf(c.stderr, "error: init requires --state-dir (or state.dir in --config)\n")
		return exitUsage
	}

	if err := ensureDir(dir, 0o700); err != nil {
		fmt.Fprintf(c.stderr, "error: state directory: %v\n", err)
		return exitError
	}
	secretsDir := filepath.Join(dir, "secrets")
	if err := ensureDir(secretsDir, 0o700); err != nil {
		fmt.Fprintf(c.stderr, "error: secrets directory: %v\n", err)
		return exitError
	}

	hostKeyPath := config.DefaultHostKeyPath(dir)
	ok := true
	ok = c.initStep(*force, hostKeyPath, "SSH host key", func() ([]byte, error) {
		return generateHostKey()
	}) && ok
	encKeyPath := config.DefaultEncryptionKeyPath(dir)
	ok = c.initStep(*force, encKeyPath, "credential encryption key", func() ([]byte, error) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		return key, nil
	}) && ok
	configPath := config.DefaultConfigPath(dir)
	ok = c.initStep(*force, configPath, "starter config", func() ([]byte, error) {
		return []byte(starterConfig(dir)), nil
	}) && ok
	if !ok {
		return exitError
	}

	// store.Open takes the flock; Close releases it before init returns.
	st, err := store.Open(dir)
	if err != nil {
		fmt.Fprintf(c.stderr, "error: store layout: %v\n", err)
		return exitError
	}
	cfg, cfgErr := config.Parse(configPath)
	if cfgErr == nil {
		config.ApplyStateDir(cfg, c.stateDir)
		if dep, depErr := DeploymentFromConfig(cfg); depErr == nil {
			if err := st.EnsureDeployment(dep); err != nil {
				cfgErr = depErr
			}
		} else {
			cfgErr = depErr
		}
	}
	if err := st.Close(); err != nil {
		fmt.Fprintf(c.stderr, "error: closing store: %v\n", err)
		return exitError
	}
	if cfgErr != nil {
		fmt.Fprintf(c.stderr, "error: seeding deployment from config: %v\n", cfgErr)
		return exitError
	}
	if cfg != nil { // runtime dirs referenced by the starter config
		for _, d := range []string{cfg.Deployment.WorkingDirectory, cfg.Deployment.CoderGlobalConfig} {
			if d != "" {
				if err := ensureDir(d, 0o700); err != nil {
					fmt.Fprintf(c.stderr, "warning: could not create %s: %v\n", d, err)
				}
			}
		}
	}

	c.printInitSummary(dir, hostKeyPath, encKeyPath, configPath)
	return exitOK
}

// initStep writes one init artifact, keeping existing files unless --force
// plus an explicit "overwrite" confirmation (§30.1: never silently replace).
func (c *cli) initStep(force bool, path, what string, gen func() ([]byte, error)) bool {
	_, statErr := os.Stat(path)
	switch {
	case errors.Is(statErr, fs.ErrNotExist):
		data, err := gen()
		if err != nil {
			fmt.Fprintf(c.stderr, "error: generating %s: %v\n", what, err)
			return false
		}
		if err := writeSecretFile(path, data, false); err != nil {
			fmt.Fprintf(c.stderr, "error: writing %s: %v\n", what, err)
			return false
		}
		fmt.Fprintf(c.stdout, "created %s: %s\n", what, path)
		return true
	case statErr != nil:
		fmt.Fprintf(c.stderr, "error: checking %s: %v\n", path, statErr)
		return false
	case !force:
		fmt.Fprintf(c.stdout, "kept existing %s: %s (use --force to overwrite)\n", what, path)
		return true
	default:
		fmt.Fprintf(c.stderr, "%s already exists at %s. Overwrite? Type 'overwrite' to confirm: ", what, path)
		answer, err := c.readLine()
		if err != nil || strings.TrimSpace(answer) != "overwrite" {
			fmt.Fprintf(c.stderr, "error: overwrite not confirmed; %s left unchanged\n", what)
			return false
		}
		data, err := gen()
		if err != nil {
			fmt.Fprintf(c.stderr, "error: generating %s: %v\n", what, err)
			return false
		}
		if err := writeSecretFile(path, data, true); err != nil {
			fmt.Fprintf(c.stderr, "error: writing %s: %v\n", what, err)
			return false
		}
		fmt.Fprintf(c.stdout, "overwrote %s: %s\n", what, path)
		return true
	}
}

// generateHostKey is the Go equivalent of `ssh-keygen -t ed25519 -N ”` (§30.1).
func generateHostKey() ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "coder-ssh-gateway host key")
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// writeSecretFile writes data mode 0600 (explicit chmod, umask-safe).
func writeSecretFile(path string, data []byte, overwrite bool) (err error) {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	if err = f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func ensureDir(path string, perm os.FileMode) error {
	_, statErr := os.Stat(path)
	created := errors.Is(statErr, fs.ErrNotExist)
	if err := os.MkdirAll(path, perm); err != nil {
		return err
	}
	if created {
		if err := os.Chmod(path, perm); err != nil {
			return err
		}
	}
	return nil
}

// printInitSummary prints the §30.1 backup warning, host-key fingerprint,
// and next steps.
func (c *cli) printInitSummary(dir, hostKeyPath, encKeyPath, configPath string) {
	fp := "(unavailable)"
	if pemBytes, err := os.ReadFile(hostKeyPath); err == nil {
		if key, err := ssh.ParseRawPrivateKey(pemBytes); err == nil {
			if signer, err := ssh.NewSignerFromKey(key); err == nil {
				fp = ssh.FingerprintSHA256(signer.PublicKey())
			}
		}
	}
	fmt.Fprintf(c.stdout, `
State directory initialized: %s

  host key:        %s
  fingerprint:     %s
  encryption key:  %s
  config:          %s

IMPORTANT: BACK UP %s NOW.
Losing the encryption key orphans every stored Coder token; losing the host
key changes the gateway identity for all clients. Publish the host-key
fingerprint through a trusted channel.

Next steps:
  1. Review and edit %s
  2. coder-ssh-gateway --state-dir %s doctor
  3. coder-ssh-gateway --state-dir %s admin account add --label "Name" --bind-on-first-token
  4. coder-ssh-gateway --state-dir %s serve
`, dir, hostKeyPath, fp, encKeyPath, configPath, filepath.Join(dir, "secrets"), configPath, dir, dir, dir)
}

// starterConfig returns the commented starter configuration with ham.dev
// defaults. Paths are absolute so the file can be moved without rebasing.
func starterConfig(dir string) string {
	return fmt.Sprintf(`# coder-ssh-gateway configuration (design section 28).
# Written by 'coder-ssh-gateway init'. Edit, then run 'doctor'.
version: 1

listen:
  address: ":2222"              # outer SSH listen address (production typically ":22")
  # handshake_timeout: 30s
  # renewal_auth_timeout: 5m
  # proxy_protocol: false       # enable only behind a PROXY-v1-speaking load balancer

ssh:
  transport_user: coder         # SSH username for workspace transport
  maintenance_user: auth        # SSH username for the credential-maintenance session
  host_keys:
    - %s # BACK UP (section 30.1)

state:
  dir: %s
  audit_retention_days: 90

encryption:
  provider: file
  active_key_id: v1
  keys:
    v1: %s # BACK UP: losing this orphans all stored tokens (section 22)

deployment:
  id: primary
  coder_url: https://example.test
  target_suffix: coder-gateway.example.com
  coder_binary: /usr/local/bin/coder
  coder_global_config: %s
  working_directory: %s
  autostart: true
  wait: auto                    # yes|no|auto
  # tls:
  #   ca_file: /path/to/ca.pem  # custom CA for the Coder deployment
`,
		config.DefaultHostKeyPath(dir),
		dir,
		config.DefaultEncryptionKeyPath(dir),
		filepath.Join(dir, "coder-config"),
		filepath.Join(dir, "run"),
	)
}
