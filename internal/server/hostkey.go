package server

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// ErrNoHostKeys is returned when no host key paths are configured. §30.1:
// the gateway never auto-generates an ephemeral host key — startup fails.
var ErrNoHostKeys = errors.New("no host keys configured")

// HostKeyError describes a host key that could not be loaded or parsed.
// Startup must fail when any configured key is unloadable (§28.1, §30.1).
type HostKeyError struct {
	Path string
	Err  error
}

func (e *HostKeyError) Error() string {
	return fmt.Sprintf("host key %s: %v", e.Path, e.Err)
}

func (e *HostKeyError) Unwrap() error { return e.Err }

// LoadHostSigners loads every PEM-encoded private host key in paths (§30).
// It returns the signers together with their SHA256 fingerprints so the
// caller can log them at startup for comparison against the published
// fingerprint (§30.1). Multiple signers support rotation overlap (§30.2).
// Any unreadable or unparseable key fails the entire load.
func LoadHostSigners(paths []string) ([]ssh.Signer, []string, error) {
	if len(paths) == 0 {
		return nil, nil, ErrNoHostKeys
	}
	signers := make([]ssh.Signer, 0, len(paths))
	fingerprints := make([]string, 0, len(paths))
	for _, path := range paths {
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, &HostKeyError{Path: path, Err: err}
		}
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return nil, nil, &HostKeyError{Path: path, Err: err}
		}
		signers = append(signers, signer)
		fingerprints = append(fingerprints, ssh.FingerprintSHA256(signer.PublicKey()))
	}
	return signers, fingerprints, nil
}
