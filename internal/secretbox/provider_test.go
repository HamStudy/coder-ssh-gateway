package secretbox_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
)

func writeKeyFile(t *testing.T, dir, name string, content []byte, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, perm); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod key file: %v", err)
	}
	return path
}

func rawKey(b byte) []byte {
	k := make([]byte, secretbox.KeySize)
	for i := range k {
		k[i] = b
	}
	return k
}

func TestSourceKeyProviderRawKey(t *testing.T) {
	dir := t.TempDir()
	raw := rawKey(0x11)
	p := &secretbox.SourceKeyProvider{
		Keys:     map[string]string{"v1": writeKeyFile(t, dir, "v1", raw, 0o400)},
		ActiveID: "v1",
	}

	id, key, err := p.ActiveKey(context.Background())
	if err != nil {
		t.Fatalf("ActiveKey: %v", err)
	}
	if id != "v1" {
		t.Fatalf("keyID = %q, want v1", id)
	}
	if !bytes.Equal(key, raw) {
		t.Fatal("key mismatch")
	}
}

// A raw 32-byte key whose edge bytes are whitespace (space, newline, tab)
// must round-trip byte-exact: whitespace trimming is only for text-encoded
// key files. Regression: init writes raw keys; TrimSpace corrupted any key
// whose first/last byte was unicode-space, breaking credential storage.
func TestSourceKeyProviderRawKeyWhitespaceEdges(t *testing.T) {
	dir := t.TempDir()
	for _, edge := range []byte{' ', '\n', '\t', '\r'} {
		raw := rawKey(0x42)
		raw[0] = edge
		raw[len(raw)-1] = edge
		name := fmt.Sprintf("v1-edge-%02x", edge)
		p := &secretbox.SourceKeyProvider{
			Keys:     map[string]string{"v1": writeKeyFile(t, dir, name, raw, 0o400)},
			ActiveID: "v1",
		}
		_, key, err := p.ActiveKey(context.Background())
		if err != nil {
			t.Fatalf("ActiveKey (edge %#x): %v", edge, err)
		}
		if !bytes.Equal(key, raw) {
			t.Fatalf("edge %#x: key corrupted by trimming", edge)
		}
	}
}

func TestSourceKeyProviderBase64Variants(t *testing.T) {
	raw := rawKey(0x42)
	variants := map[string][]byte{
		"std-padded":       []byte(base64.StdEncoding.EncodeToString(raw)),
		"std-unpadded":     []byte(base64.RawStdEncoding.EncodeToString(raw)),
		"url-padded":       []byte(base64.URLEncoding.EncodeToString(raw)),
		"url-unpadded":     []byte(base64.RawURLEncoding.EncodeToString(raw)),
		"std-with-newline": []byte(base64.StdEncoding.EncodeToString(raw) + "\n"),
	}
	for name, content := range variants {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := &secretbox.SourceKeyProvider{
				Keys:     map[string]string{"v1": writeKeyFile(t, dir, "v1", content, 0o400)},
				ActiveID: "v1",
			}
			key, err := p.Key(context.Background(), "v1")
			if err != nil {
				t.Fatalf("Key: %v", err)
			}
			if !bytes.Equal(key, raw) {
				t.Fatal("decoded key mismatch")
			}
		})
	}
}

func TestSourceKeyProviderWrongLength(t *testing.T) {
	dir := t.TempDir()

	short := writeKeyFile(t, dir, "short", bytes.Repeat([]byte("a"), 31), 0o400)
	p := &secretbox.SourceKeyProvider{Keys: map[string]string{"v1": short}, ActiveID: "v1"}
	if _, err := p.Key(context.Background(), "v1"); !errors.Is(err, secretbox.ErrKeySize) {
		t.Fatalf("31 bytes: err = %v, want ErrKeySize", err)
	}

	long := writeKeyFile(t, dir, "long", bytes.Repeat([]byte("a"), 33), 0o400)
	p = &secretbox.SourceKeyProvider{Keys: map[string]string{"v1": long}, ActiveID: "v1"}
	if _, err := p.Key(context.Background(), "v1"); !errors.Is(err, secretbox.ErrKeyFormat) {
		t.Fatalf("33 bytes: err = %v, want ErrKeyFormat", err)
	}
}

func TestSourceKeyProviderUnknownKeyID(t *testing.T) {
	p := &secretbox.SourceKeyProvider{Keys: map[string]string{}, ActiveID: "v1"}
	if _, err := p.Key(context.Background(), "nope"); !errors.Is(err, secretbox.ErrKeyNotFound) {
		t.Fatalf("err = %v, want ErrKeyNotFound", err)
	}
	if _, _, err := p.ActiveKey(context.Background()); !errors.Is(err, secretbox.ErrKeyNotFound) {
		t.Fatalf("ActiveKey: err = %v, want ErrKeyNotFound", err)
	}
}

func TestSourceKeyProviderMissingFile(t *testing.T) {
	p := &secretbox.SourceKeyProvider{
		Keys:     map[string]string{"v1": filepath.Join(t.TempDir(), "absent")},
		ActiveID: "v1",
	}
	if _, err := p.Key(context.Background(), "v1"); err == nil {
		t.Fatal("want error for missing file")
	}
}

func TestSourceKeyProviderCachesAndCopies(t *testing.T) {
	dir := t.TempDir()
	raw := rawKey(0x77)
	path := writeKeyFile(t, dir, "v1", raw, 0o400)
	p := &secretbox.SourceKeyProvider{Keys: map[string]string{"v1": path}, ActiveID: "v1"}

	first, err := p.Key(context.Background(), "v1")
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	second, err := p.Key(context.Background(), "v1")
	if err != nil {
		t.Fatalf("cached Key after file removal: %v", err)
	}
	first[0] ^= 0xff
	if !bytes.Equal(second, raw) {
		t.Fatal("mutating returned key corrupted provider cache")
	}
}

func TestSourceKeyProviderLoosePermsSucceed(t *testing.T) {
	dir := t.TempDir()
	raw := rawKey(0x33)
	p := &secretbox.SourceKeyProvider{
		Keys:     map[string]string{"v1": writeKeyFile(t, dir, "v1", raw, 0o440)},
		ActiveID: "v1",
	}
	if _, err := p.Key(context.Background(), "v1"); err != nil {
		t.Fatalf("group-readable key must load (warn only): %v", err)
	}
}

func TestSourceKeyProviderConcurrent(t *testing.T) {
	dir := t.TempDir()
	raw := rawKey(0x55)
	p := &secretbox.SourceKeyProvider{
		Keys:     map[string]string{"v1": writeKeyFile(t, dir, "v1", raw, 0o400)},
		ActiveID: "v1",
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				key, err := p.Key(context.Background(), "v1")
				if err != nil {
					t.Errorf("Key: %v", err)
					return
				}
				if !bytes.Equal(key, raw) {
					t.Errorf("key mismatch")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestKeyRotation(t *testing.T) {
	dir := t.TempDir()
	rawV1 := rawKey(0x01)
	rawV2 := rawKey(0x02)
	p := &secretbox.SourceKeyProvider{
		Keys: map[string]string{
			"v1": writeKeyFile(t, dir, "v1", rawV1, 0o400),
			"v2": writeKeyFile(t, dir, "v2", rawV2, 0o400),
		},
		ActiveID: "v2",
	}
	ctx := context.Background()

	keyV1, err := p.Key(ctx, "v1")
	if err != nil {
		t.Fatalf("Key v1: %v", err)
	}
	aad := secretbox.CredentialAAD(testDeployment, testAccount, 3)
	nonce, ct, err := secretbox.Seal("v1", keyV1, []byte("old-token"), aad)
	if err != nil {
		t.Fatalf("Seal v1: %v", err)
	}

	activeID, activeKey, err := p.ActiveKey(ctx)
	if err != nil {
		t.Fatalf("ActiveKey: %v", err)
	}
	if activeID != "v2" || !bytes.Equal(activeKey, rawV2) {
		t.Fatalf("active = %q, want v2", activeID)
	}

	oldKey, err := p.Key(ctx, "v1")
	if err != nil {
		t.Fatalf("Key v1 after rotation: %v", err)
	}
	got, err := secretbox.Open("v1", oldKey, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open v1 ciphertext after rotation: %v", err)
	}
	if string(got) != "old-token" {
		t.Fatalf("got %q", got)
	}

	if _, err := secretbox.Open("v2", activeKey, nonce, ct, aad); !errors.Is(err, secretbox.ErrDecryptFailed) {
		t.Fatalf("v1 ciphertext under v2 key: err = %v, want ErrDecryptFailed", err)
	}

	newNonce, newCT, err := secretbox.Seal(activeID, activeKey, []byte("new-token"), aad)
	if err != nil {
		t.Fatalf("Seal v2: %v", err)
	}
	if _, err := secretbox.Open(activeID, activeKey, newNonce, newCT, aad); err != nil {
		t.Fatalf("Open v2: %v", err)
	}
}

func TestSourceKeyProviderEnvSources(t *testing.T) {
	key := rawKey(0x07)
	b64 := base64.StdEncoding.EncodeToString(key)

	t.Run("loads base64 value", func(t *testing.T) {
		t.Setenv("CSGW_TEST_KEY_V1", b64)
		p := &secretbox.SourceKeyProvider{Keys: map[string]string{"v1": "env:CSGW_TEST_KEY_V1"}, ActiveID: "v1"}
		got, err := p.Key(context.Background(), "v1")
		if err != nil {
			t.Fatalf("Key: %v", err)
		}
		if !bytes.Equal(got, key) {
			t.Errorf("key mismatch")
		}
	})

	t.Run("unset variable fails closed with stable code", func(t *testing.T) {
		p := &secretbox.SourceKeyProvider{Keys: map[string]string{"v1": "env:CSGW_TEST_KEY_UNSET"}, ActiveID: "v1"}
		_, err := p.Key(context.Background(), "v1")
		if err == nil || !strings.Contains(err.Error(), core.CRYPTO_KEY_UNAVAILABLE) {
			t.Fatalf("err = %v, want %s", err, core.CRYPTO_KEY_UNAVAILABLE)
		}
	})

	t.Run("empty reference is a format error", func(t *testing.T) {
		p := &secretbox.SourceKeyProvider{Keys: map[string]string{"v1": "env:"}, ActiveID: "v1"}
		_, err := p.Key(context.Background(), "v1")
		if err == nil || !strings.Contains(err.Error(), "format") {
			t.Fatalf("err = %v, want format error", err)
		}
	})

	t.Run("wrong decoded size rejected", func(t *testing.T) {
		t.Setenv("CSGW_TEST_KEY_SHORT", base64.StdEncoding.EncodeToString([]byte("too-short")))
		p := &secretbox.SourceKeyProvider{Keys: map[string]string{"v1": "env:CSGW_TEST_KEY_SHORT"}, ActiveID: "v1"}
		_, err := p.Key(context.Background(), "v1")
		if err == nil || !strings.Contains(err.Error(), "32 bytes") {
			t.Fatalf("err = %v, want size error", err)
		}
	})

	t.Run("mixed file and env sources with rotation", func(t *testing.T) {
		dir := t.TempDir()
		old := rawKey(0x08)
		t.Setenv("CSGW_TEST_KEY_V2", b64)
		p := &secretbox.SourceKeyProvider{
			Keys: map[string]string{
				"v1": writeKeyFile(t, dir, "v1", old, 0o400),
				"v2": "env:CSGW_TEST_KEY_V2",
			},
			ActiveID: "v2",
		}
		ctx := context.Background()
		id1, k1, err := p.ActiveKey(ctx)
		if err != nil || id1 != "v2" || !bytes.Equal(k1, key) {
			t.Fatalf("active = %s, %v", id1, err)
		}
		kOld, err := p.Key(ctx, "v1")
		if err != nil || !bytes.Equal(kOld, old) {
			t.Fatalf("old key: %v", err)
		}
	})

	t.Run("trailing newline tolerated", func(t *testing.T) {
		t.Setenv("CSGW_TEST_KEY_NL", b64+"\n")
		p := &secretbox.SourceKeyProvider{Keys: map[string]string{"v1": "env:CSGW_TEST_KEY_NL"}, ActiveID: "v1"}
		got, err := p.Key(context.Background(), "v1")
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("Key: %v", err)
		}
	})
}
