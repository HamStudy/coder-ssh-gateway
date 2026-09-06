package secretbox_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, secretbox.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	return key
}

var (
	testDeployment = uuid.MustParse("11111111-2222-3333-4444-555555555555")
	testAccount    = uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := testKey(t)
	aad := secretbox.CredentialAAD(testDeployment, testAccount, 7)
	plaintext := []byte("coder-session-token-material")

	nonce, ct, err := secretbox.Seal("v1", key, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(nonce) != secretbox.NonceSize {
		t.Fatalf("nonce size = %d, want %d", len(nonce), secretbox.NonceSize)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, err := secretbox.Open("v1", key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestSealOpenEmptyPlaintext(t *testing.T) {
	key := testKey(t)
	aad := secretbox.CredentialAAD(testDeployment, testAccount, 1)

	nonce, ct, err := secretbox.Seal("v1", key, nil, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := secretbox.Open("v1", key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d bytes, want empty", len(got))
	}
}

func TestSealNonceUniqueness(t *testing.T) {
	key := testKey(t)
	aad := secretbox.CredentialAAD(testDeployment, testAccount, 1)

	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		nonce, _, err := secretbox.Seal("v1", key, []byte("x"), aad)
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		s := string(nonce)
		if _, dup := seen[s]; dup {
			t.Fatalf("nonce reused at iteration %d", i)
		}
		seen[s] = struct{}{}
	}
}

func TestSealRejectsWrongKeySize(t *testing.T) {
	aad := secretbox.CredentialAAD(testDeployment, testAccount, 1)
	for _, n := range []int{0, 16, 31, 33, 64} {
		_, _, err := secretbox.Seal("v1", make([]byte, n), []byte("x"), aad)
		if !errors.Is(err, secretbox.ErrKeySize) {
			t.Fatalf("Seal key size %d: err = %v, want ErrKeySize", n, err)
		}
	}
}

func TestOpenWrongAAD(t *testing.T) {
	key := testKey(t)
	aad := secretbox.CredentialAAD(testDeployment, testAccount, 7)
	nonce, ct, err := secretbox.Seal("v1", key, []byte("token"), aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := map[string][]byte{
		"different account":    secretbox.CredentialAAD(testDeployment, uuid.MustParse("bbbbbbbb-1111-2222-3333-444444444444"), 7),
		"different generation": secretbox.CredentialAAD(testDeployment, testAccount, 8),
		"different deployment": secretbox.CredentialAAD(uuid.MustParse("99999999-8888-7777-6666-555555555555"), testAccount, 7),
		"empty":                nil,
	}
	for name, badAAD := range cases {
		_, err := secretbox.Open("v1", key, nonce, ct, badAAD)
		if !errors.Is(err, secretbox.ErrDecryptFailed) {
			t.Fatalf("%s: err = %v, want ErrDecryptFailed", name, err)
		}
		if !bytes.Contains([]byte(err.Error()), []byte(core.CRYPTO_DECRYPT_FAILED)) {
			t.Fatalf("%s: error %q missing detail code %s", name, err, core.CRYPTO_DECRYPT_FAILED)
		}
	}
}

func TestOpenWrongKey(t *testing.T) {
	key := testKey(t)
	other := testKey(t)
	aad := secretbox.CredentialAAD(testDeployment, testAccount, 1)
	nonce, ct, err := secretbox.Seal("v1", key, []byte("token"), aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := secretbox.Open("v1", other, nonce, ct, aad); !errors.Is(err, secretbox.ErrDecryptFailed) {
		t.Fatalf("err = %v, want ErrDecryptFailed", err)
	}
}

func TestOpenTamperedCiphertext(t *testing.T) {
	key := testKey(t)
	aad := secretbox.CredentialAAD(testDeployment, testAccount, 1)
	nonce, ct, err := secretbox.Seal("v1", key, []byte("token-material"), aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	flipped := slices.Clone(ct)
	flipped[len(flipped)/2] ^= 0x01
	if _, err := secretbox.Open("v1", key, nonce, flipped, aad); !errors.Is(err, secretbox.ErrDecryptFailed) {
		t.Fatalf("flipped byte: err = %v, want ErrDecryptFailed", err)
	}

	truncated := slices.Clone(ct[:len(ct)-1])
	if _, err := secretbox.Open("v1", key, nonce, truncated, aad); !errors.Is(err, secretbox.ErrDecryptFailed) {
		t.Fatalf("truncated: err = %v, want ErrDecryptFailed", err)
	}

	extended := append(slices.Clone(ct), 0x00)
	if _, err := secretbox.Open("v1", key, nonce, extended, aad); !errors.Is(err, secretbox.ErrDecryptFailed) {
		t.Fatalf("extended: err = %v, want ErrDecryptFailed", err)
	}

	badNonce := slices.Clone(nonce)
	badNonce[0] ^= 0x01
	if _, err := secretbox.Open("v1", key, badNonce, ct, aad); !errors.Is(err, secretbox.ErrDecryptFailed) {
		t.Fatalf("tampered nonce: err = %v, want ErrDecryptFailed", err)
	}
}

func TestOpenMalformedInputsNoPanic(t *testing.T) {
	key := testKey(t)
	aad := secretbox.CredentialAAD(testDeployment, testAccount, 1)

	if _, err := secretbox.Open("v1", key, nil, nil, aad); err == nil {
		t.Fatal("nil nonce/ciphertext: want error")
	}
	if _, err := secretbox.Open("v1", key, []byte{1, 2, 3}, []byte{1, 2, 3}, aad); err == nil {
		t.Fatal("short nonce/ciphertext: want error")
	}
	if _, err := secretbox.Open("v1", make([]byte, 31), make([]byte, 12), []byte("x"), aad); !errors.Is(err, secretbox.ErrKeySize) {
		t.Fatalf("short key: err = %v, want ErrKeySize", err)
	}
}

func TestCredentialAADByteStable(t *testing.T) {
	got := secretbox.CredentialAAD(testDeployment, testAccount, 7)
	want := "coder-ssh-gateway\n" +
		"schema=v1\n" +
		"deployment=11111111-2222-3333-4444-555555555555\n" +
		"account=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n" +
		"record=credential\n" +
		"generation=7"
	if string(got) != want {
		t.Fatalf("AAD =\n%q\nwant\n%q", got, want)
	}

	if bytes.Equal(secretbox.CredentialAAD(testDeployment, testAccount, 7), secretbox.CredentialAAD(testDeployment, testAccount, 8)) {
		t.Fatal("AAD identical across generations")
	}
}

func TestBestEffortWipe(t *testing.T) {
	b := []byte("super-secret-token")
	secretbox.BestEffortWipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %d after wipe", i, v)
		}
	}
	secretbox.BestEffortWipe(nil)
}
