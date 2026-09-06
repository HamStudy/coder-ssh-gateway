package secretbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

var (
	ErrKeyNotFound = errors.New("key id not found")
	ErrKeyFormat   = errors.New("unrecognized key format")
)

// KeyProvider supplies versioned envelope keys per design section 22.2: one
// active key for sealing, older versions retrievable by ID for opening.
type KeyProvider interface {
	ActiveKey(ctx context.Context) (keyID string, key []byte, err error)
	Key(ctx context.Context, keyID string) ([]byte, error)
}

// envSourcePrefix marks a Keys value as an environment variable reference
// (env:VARNAME) instead of a file path. The variable holds the key material:
// 32 raw bytes or a base64 encoding (standard or URL, padded or unpadded)
// of 32 bytes. Base64 is the deployable form — Kubernetes injects Secret
// data base64-encoded, and raw bytes do not survive env transport safely.
const envSourcePrefix = "env:"

// SourceKeyProvider loads keys from the sources listed in Keys (keyID to
// source) and caches them lazily. A source is a file path or an env:VARNAME
// reference; see envSourcePrefix. Key material is never logged. Returned
// keys are fresh copies.
type SourceKeyProvider struct {
	Keys     map[string]string
	ActiveID string
	Logger   *slog.Logger

	mu    sync.Mutex
	cache map[string][]byte
}

func (p *SourceKeyProvider) ActiveKey(ctx context.Context) (string, []byte, error) {
	if p.ActiveID == "" {
		return "", nil, fmt.Errorf("active key: %w (%s)", ErrKeyNotFound, core.CRYPTO_KEY_UNAVAILABLE)
	}
	key, err := p.Key(ctx, p.ActiveID)
	if err != nil {
		return "", nil, err
	}
	return p.ActiveID, key, nil
}

func (p *SourceKeyProvider) Key(ctx context.Context, keyID string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source, ok := p.Keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key %q: %w (%s)", keyID, ErrKeyNotFound, core.CRYPTO_KEY_UNAVAILABLE)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if key, ok := p.cache[keyID]; ok {
		return slices.Clone(key), nil
	}

	var key []byte
	var err error
	if varName, ok := strings.CutPrefix(source, envSourcePrefix); ok {
		key, err = p.envKey(keyID, varName)
	} else {
		key, err = p.fileKey(keyID, source)
	}
	if err != nil {
		return nil, err
	}
	if p.cache == nil {
		p.cache = make(map[string][]byte)
	}
	p.cache[keyID] = key
	return slices.Clone(key), nil
}

// envKey resolves an env:VARNAME source. A missing variable fails closed
// with the stable CRYPTO_KEY_UNAVAILABLE code — the gateway never starts
// with a half-configured envelope.
func (p *SourceKeyProvider) envKey(keyID, varName string) ([]byte, error) {
	if varName == "" {
		return nil, fmt.Errorf("key %q: %w: empty env reference", keyID, ErrKeyFormat)
	}
	value := os.Getenv(varName)
	if value == "" {
		return nil, fmt.Errorf("key %q: environment variable %s is not set (%s)",
			keyID, varName, core.CRYPTO_KEY_UNAVAILABLE)
	}
	key, err := parseKeyMaterial([]byte(value))
	if err != nil {
		return nil, fmt.Errorf("key %q from %s: %w", keyID, varName, err)
	}
	return key, nil
}

func (p *SourceKeyProvider) fileKey(keyID, path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("key %q: %w (%s)", keyID, err, core.CRYPTO_KEY_UNAVAILABLE)
	}
	if perm := info.Mode().Perm(); perm&^0o400 != 0 {
		p.logger().Warn("key file permissions looser than 0400",
			"key_id", keyID, "path", path, "mode", fmt.Sprintf("%#o", perm))
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is operator-configured
	if err != nil {
		return nil, fmt.Errorf("key %q: %w (%s)", keyID, err, core.CRYPTO_KEY_UNAVAILABLE)
	}
	key, err := parseKeyMaterial(data)
	if err != nil {
		return nil, fmt.Errorf("key %q: %w", keyID, err)
	}
	return key, nil
}

func (p *SourceKeyProvider) logger() *slog.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return slog.Default()
}

func parseKeyMaterial(data []byte) ([]byte, error) {
	// Exact-size raw key material wins BEFORE any whitespace trimming:
	// TrimSpace would silently corrupt a binary key whose edge bytes happen
	// to be ASCII/unicode space (found by E2E: init writes raw 32-byte keys).
	if len(data) == KeySize {
		return slices.Clone(data), nil
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == KeySize {
		return slices.Clone(trimmed), nil
	}
	decodedOK := false
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(string(trimmed))
		if err != nil {
			continue
		}
		decodedOK = true
		if len(decoded) == KeySize {
			return decoded, nil
		}
	}
	if decodedOK {
		return nil, fmt.Errorf("decoded key: %w", ErrKeySize)
	}
	return nil, ErrKeyFormat
}
