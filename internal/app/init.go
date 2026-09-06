package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/HamStudy/coder-ssh-gateway/internal/config"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
)

// cmdInit initializes a state directory per §30.1/§22: store layout, Ed25519
// host key, 32-byte credential encryption key (0600 under 0700 secrets/),
// and a starter config. Idempotent; --force still requires confirmation.
func (c *cli) cmdInit(args []string) int {
	fs := c.newFlagSet("init")
	force := fs.Bool("force", false, "overwrite existing secrets/config (asks for confirmation)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(c.stderr, "error: init requires exactly one Coder domain argument (for example: coder.example.com)")
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(c.stderr, "error: init requires exactly one Coder domain argument (for example: coder.example.com)\n")
		return exitUsage
	}
	coderURL, err := coderURLFromDomain(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(c.stderr, "error: invalid Coder domain %q: %v\n", fs.Arg(0), err)
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
		return []byte(starterConfig(coderURL)), nil
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
				cfgErr = err
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

func coderURLFromDomain(domain string) (string, error) {
	if domain == "" || strings.TrimSpace(domain) != domain {
		return "", errors.New("must be a non-empty bare DNS domain")
	}
	if strings.Contains(domain, "://") {
		return "", errors.New("must not include a URL scheme")
	}

	u, err := url.Parse("https://" + domain)
	if err != nil {
		return "", fmt.Errorf("parse domain: %w", err)
	}
	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Host == "" {
		return "", errors.New("must be a bare DNS domain, optionally followed by a port")
	}

	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !validDNSDomain(host) {
		return "", errors.New("must be a valid DNS domain")
	}
	port := u.Port()
	if port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", errors.New("port must be between 1 and 65535")
		}
	}
	if port != "" {
		host += ":" + port
	}
	return "https://" + host, nil
}

func validDNSDomain(domain string) bool {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 || len(domain) > 253 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !('a' <= char && char <= 'z') && !('0' <= char && char <= '9') && char != '-' {
				return false
			}
		}
	}
	return true
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
	if !overwrite {
		if _, statErr := os.Stat(path); statErr == nil {
			return fmt.Errorf("create %s: %w", path, fs.ErrExist)
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return statErr
		}
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	tmpPath = ""

	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	return dirFile.Sync()
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

// starterConfig returns a commented configuration for coderURL. State-owned
// paths are relative to the config file.
func starterConfig(coderURL string) string {
	return fmt.Sprintf(`# coder-ssh-gateway configuration.
# Written by 'coder-ssh-gateway init'. Edit, then run 'doctor'.
version: 1

listen:
  address: ":2222"              # outer SSH listen address (production typically ":22")
  # handshake_timeout: 30s
  # renewal_auth_timeout: 5m
  # proxy_protocol: false       # enable only behind a PROXY-v1-speaking load balancer

ssh:
  host_keys:
    - secrets/ssh_host_ed25519_key # BACK UP

state:
  audit_retention_days: 90

encryption:
  provider: file
  active_key_id: v1
  keys:
    v1: secrets/credential-key-v1 # BACK UP: losing this orphans all stored tokens

deployment:
  id: primary
  coder_url: %s
  coder_binary: /usr/local/bin/coder
  coder_global_config: coder-config
  working_directory: run
  autostart: true
  wait: auto                    # yes|no|auto
  # tls:
  #   ca_file: /path/to/ca.pem  # custom CA for the Coder deployment
`, coderURL)
}
