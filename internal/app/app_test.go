package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/app"
	"github.com/taxilian/coder-ssh-gateway/internal/config"
)

// runCLI executes the CLI with captured streams; stdin is fed from a string.
func runCLI(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	code = app.Run(context.Background(), args, strings.NewReader(stdin), &outBuf, &errBuf)
	return code, outBuf.String(), errBuf.String()
}

// coderStub is an httptest Coder control plane: /api/v2/users/me validates
// tokens from a map, /api/v2/buildinfo reports a fixed version.
type coderStub struct {
	srv      *httptest.Server
	tokens   map[string]stubIdentity
	tls      bool
	tlsCAPEM string
}

type stubIdentity struct {
	ID       uuid.UUID
	Username string
}

func newCoderStub(t *testing.T, useTLS bool) *coderStub {
	t.Helper()
	cs := &coderStub{tokens: map[string]stubIdentity{}, tls: useTLS}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/users/me", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("Coder-Session-Token")
		ident, ok := cs.tokens[tok]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"message":"invalid token"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"username":%q,"status":"active"}`, ident.ID.String(), ident.Username)
	})
	mux.HandleFunc("/api/v2/buildinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":"v2.35.2"}`)
	})
	if useTLS {
		cs.srv = httptest.NewTLSServer(mux)
		cert := cs.srv.Certificate()
		cs.tlsCAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	} else {
		cs.srv = httptest.NewServer(mux)
	}
	t.Cleanup(cs.srv.Close)
	return cs
}

func (cs *coderStub) url() string { return cs.srv.URL }

func (cs *coderStub) addToken(token string, id uuid.UUID, username string) {
	cs.tokens[token] = stubIdentity{ID: id, Username: username}
}

// cliFixture is an initialized state dir plus a stub Coder deployment.
type cliFixture struct {
	dir         string
	coder       *coderStub
	coderUserID uuid.UUID
	configPath  string
}

func newCLIFixture(t *testing.T, useTLS bool) *cliFixture {
	t.Helper()
	dir := t.TempDir()
	code, out, errOut := runCLI(t, "", "--state-dir", dir, "init")
	if code != 0 {
		t.Fatalf("init: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	f := &cliFixture{
		dir:         dir,
		coder:       newCoderStub(t, useTLS),
		coderUserID: uuid.MustParse("55555555-5555-5555-5555-555555555555"),
		configPath:  config.DefaultConfigPath(dir),
	}
	f.writeConfig(t, "/bin/true")
	return f
}

// writeConfig overwrites the init-written starter config with a test config
// pointing at the stub Coder. Parse-only consumers accept the http URL; TLS
// fixtures additionally write the CA so serve's full validation passes.
func (f *cliFixture) writeConfig(t *testing.T, coderBinary string) {
	t.Helper()
	var sb strings.Builder
	fmt.Fprintf(&sb, "version: 1\n")
	fmt.Fprintf(&sb, "state:\n  dir: %s\n", f.dir)
	fmt.Fprintf(&sb, "deployment:\n")
	fmt.Fprintf(&sb, "  id: primary\n")
	fmt.Fprintf(&sb, "  coder_url: %s\n", f.coder.url())
	fmt.Fprintf(&sb, "  target_suffix: coder-gateway.example.com\n")
	fmt.Fprintf(&sb, "  coder_binary: %s\n", coderBinary)
	fmt.Fprintf(&sb, "  coder_global_config: %s\n", filepath.Join(f.dir, "coder-config"))
	fmt.Fprintf(&sb, "  working_directory: %s\n", filepath.Join(f.dir, "run"))
	if f.coder.tls {
		caPath := filepath.Join(f.dir, "ca.pem")
		if err := os.WriteFile(caPath, []byte(f.coder.tlsCAPEM), 0o644); err != nil {
			t.Fatalf("write CA: %v", err)
		}
		fmt.Fprintf(&sb, "  tls:\n    ca_file: %s\n", caPath)
	}
	if err := os.WriteFile(f.configPath, []byte(sb.String()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func (f *cliFixture) parse(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse(f.configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	config.ApplyStateDir(cfg, f.dir)
	return cfg
}

// addAccount runs admin account add --coder-user-id and returns the new
// account UUID parsed from stdout.
func (f *cliFixture) addAccount(t *testing.T, label string) uuid.UUID {
	t.Helper()
	code, out, errOut := runCLI(t, "", "--state-dir", f.dir, "admin", "account", "add",
		"--label", label, "--coder-user-id", f.coderUserID.String())
	if code != 0 {
		t.Fatalf("account add: exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	m := regexp.MustCompile(`account ([0-9a-f-]{36}) created`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("account add output missing UUID: %q", out)
	}
	id, err := uuid.Parse(m[1])
	if err != nil {
		t.Fatalf("parse account UUID: %v", err)
	}
	return id
}

// genKeyPair writes an authorized_keys public key file and returns signer,
// path, and expected fingerprint.
func genKeyPair(t *testing.T, dir, name string) (ssh.Signer, string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o600); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}
	return signer, path, ssh.FingerprintSHA256(signer.PublicKey())
}
