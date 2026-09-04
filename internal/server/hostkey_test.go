package server_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/server"
)

// writeHostKey writes a PEM-encoded private key into a temp dir with 0600
// perms (§30.1) and returns the path.
func writeHostKey(t *testing.T, key any) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ssh_host_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write host key: %v", err)
	}
	return path
}

func genEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return priv
}

func TestLoadHostSignersValidEd25519(t *testing.T) {
	path := writeHostKey(t, genEd25519(t))

	signers, fps, err := server.LoadHostSigners([]string{path})
	if err != nil {
		t.Fatalf("LoadHostSigners: %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("signers = %d, want 1", len(signers))
	}
	if len(fps) != 1 {
		t.Fatalf("fingerprints = %d, want 1", len(fps))
	}
	if got, want := fps[0], ssh.FingerprintSHA256(signers[0].PublicKey()); got != want {
		t.Errorf("fingerprint = %q, want %q", got, want)
	}
	if signers[0].PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("key type = %q, want %q", signers[0].PublicKey().Type(), ssh.KeyAlgoED25519)
	}

	// §30: fingerprints must be stable across instances loading the same file.
	signers2, fps2, err := server.LoadHostSigners([]string{path})
	if err != nil {
		t.Fatalf("LoadHostSigners (2nd): %v", err)
	}
	if fps2[0] != fps[0] {
		t.Errorf("fingerprint not stable: %q vs %q", fps2[0], fps[0])
	}
	if ssh.FingerprintSHA256(signers2[0].PublicKey()) != ssh.FingerprintSHA256(signers[0].PublicKey()) {
		t.Error("public key differs across loads of the same file")
	}
}

// §30.2: rotation overlap requires loading multiple host keys at once.
func TestLoadHostSignersMultiple(t *testing.T) {
	edPath := writeHostKey(t, genEd25519(t))

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	rsaPath := writeHostKey(t, rsaKey)

	signers, fps, err := server.LoadHostSigners([]string{edPath, rsaPath})
	if err != nil {
		t.Fatalf("LoadHostSigners: %v", err)
	}
	if len(signers) != 2 || len(fps) != 2 {
		t.Fatalf("got %d signers / %d fingerprints, want 2/2", len(signers), len(fps))
	}
	types := map[string]bool{signers[0].PublicKey().Type(): true, signers[1].PublicKey().Type(): true}
	if !types[ssh.KeyAlgoED25519] || !types[ssh.KeyAlgoRSASHA256] && !types[ssh.KeyAlgoRSA] {
		t.Errorf("unexpected signer types: %v", types)
	}
	if fps[0] == fps[1] {
		t.Error("distinct keys must have distinct fingerprints")
	}
}

// §30.1: zero configured host keys is a startup failure, never auto-generate.
func TestLoadHostSignersZeroPaths(t *testing.T) {
	signers, _, err := server.LoadHostSigners(nil)
	if err == nil {
		t.Fatal("expected error for zero paths")
	}
	if signers != nil {
		t.Error("signers must be nil on error")
	}
	if !errors.Is(err, server.ErrNoHostKeys) {
		t.Errorf("error = %v, want errors.Is ErrNoHostKeys", err)
	}
}

func TestLoadHostSignersMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, _, err := server.LoadHostSigners([]string{missing})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	var hkErr *server.HostKeyError
	if !errors.As(err, &hkErr) {
		t.Fatalf("error %T = %v, want *server.HostKeyError", err, err)
	}
	if hkErr.Path != missing {
		t.Errorf("HostKeyError.Path = %q, want %q", hkErr.Path, missing)
	}
}

func TestLoadHostSignersGarbageFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage")
	if err := os.WriteFile(path, []byte("this is not a private key\n"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	_, _, err := server.LoadHostSigners([]string{path})
	if err == nil {
		t.Fatal("expected error for unparseable key")
	}
	var hkErr *server.HostKeyError
	if !errors.As(err, &hkErr) {
		t.Fatalf("error %T = %v, want *server.HostKeyError", err, err)
	}
}

// A passphrase-protected key is unparseable without the passphrase: fail
// startup (§30.1) rather than silently skip.
func TestLoadHostSignersEncryptedKeyFails(t *testing.T) {
	block, err := ssh.MarshalPrivateKeyWithPassphrase(genEd25519(t), "", []byte("passphrase"))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	path := filepath.Join(t.TempDir(), "encrypted")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := server.LoadHostSigners([]string{path}); err == nil {
		t.Fatal("expected error for passphrase-protected key")
	}
}

// One bad file in a multi-key list must fail the whole load (§30.1: startup
// either has the full published key set or fails loudly).
func TestLoadHostSignersOneBadFailsAll(t *testing.T) {
	good := writeHostKey(t, genEd25519(t))
	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte("junk"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	signers, _, err := server.LoadHostSigners([]string{good, bad})
	if err == nil {
		t.Fatal("expected error when any key is unparseable")
	}
	if signers != nil {
		t.Error("partial signer set must not be returned on error")
	}
}
