// Package secretbox implements AES-256-GCM envelope encryption for
// credentials at rest, per design section 22.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
)

const (
	KeySize   = 32
	NonceSize = 12
)

var (
	ErrKeySize       = errors.New("key must be 32 bytes")
	ErrDecryptFailed = errors.New("decryption failed")
)

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("aes-256-gcm: %w, got %d", ErrKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-256-gcm init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-256-gcm init: %w", err)
	}
	return gcm, nil
}

// Seal encrypts plaintext with AES-256-GCM under key, binding aad as
// authenticated associated data. A fresh 12-byte nonce from crypto/rand is
// generated per call and returned alongside the ciphertext. keyID identifies
// the key version for the caller's records; it is not embedded in the output.
func Seal(keyID string, key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce for key %q: %w", keyID, err)
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts ciphertext produced by Seal. Any authentication failure —
// wrong key, wrong AAD, tampered or truncated ciphertext — returns an error
// matching ErrDecryptFailed with detail code core.CRYPTO_DECRYPT_FAILED.
func Open(keyID string, key, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSize {
		return nil, decryptErr(keyID)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, decryptErr(keyID)
	}
	return plaintext, nil
}

func decryptErr(keyID string) error {
	return fmt.Errorf("key %q: %w (%s)", keyID, ErrDecryptFailed, core.CRYPTO_DECRYPT_FAILED)
}
