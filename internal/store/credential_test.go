package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
	"github.com/HamStudy/coder-ssh-gateway/internal/testleaks"
)

// --- key provider -----------------------------------------------------------

// memoryKeyProvider is an in-memory secretbox.KeyProvider for tests. Keys are
// random 32-byte values; the last ID passed to newMemoryKeyProvider is active.
type memoryKeyProvider struct {
	mu     sync.Mutex
	keys   map[string][]byte
	active string
}

func newMemoryKeyProvider(t *testing.T, ids ...string) *memoryKeyProvider {
	t.Helper()
	if len(ids) == 0 {
		t.Fatalf("newMemoryKeyProvider: at least one key id required")
	}
	m := &memoryKeyProvider{keys: make(map[string][]byte, len(ids))}
	for _, id := range ids {
		k := make([]byte, secretbox.KeySize)
		if _, err := rand.Read(k); err != nil {
			t.Fatalf("rand key: %v", err)
		}
		m.keys[id] = k
		m.active = id
	}
	return m
}

func (m *memoryKeyProvider) ActiveKey(ctx context.Context) (string, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == "" {
		return "", nil, errors.New("no active key")
	}
	return m.active, bytes.Clone(m.keys[m.active]), nil
}

func (m *memoryKeyProvider) Key(ctx context.Context, keyID string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key %q: %w", keyID, secretbox.ErrKeyNotFound)
	}
	return bytes.Clone(k), nil
}

func (m *memoryKeyProvider) setActive(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active = id
}

// --- helpers ----------------------------------------------------------------

func seedAccount(t *testing.T, s *store.Store) (core.Deployment, core.Account) {
	t.Helper()
	dep := testDeployment()
	if err := s.EnsureDeployment(dep); err != nil {
		t.Fatalf("EnsureDeployment: %v", err)
	}
	acct := testAccount(dep.ID)
	if err := s.AddAccount(acct); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	return dep, acct
}

func credIdentity() core.CoderIdentity {
	return core.CoderIdentity{
		ID:       uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		Username: "taxilian",
		Status:   "active",
	}
}

func replaceReq(acctID uuid.UUID, gen int64, token []byte) core.ReplaceCredentialRequest {
	return core.ReplaceCredentialRequest{
		AccountID:          acctID,
		ExpectedGeneration: gen,
		Token:              token,
		Identity:           credIdentity(),
	}
}

func mustReplace(t *testing.T, s *store.Store, acctID uuid.UUID, gen int64, token string) core.CredentialSnapshot {
	t.Helper()
	snap, err := s.ReplaceCredential(context.Background(), replaceReq(acctID, gen, []byte(token)))
	if err != nil {
		t.Fatalf("ReplaceCredential(gen=%d): %v", gen, err)
	}
	return snap
}

func credentialFilePath(dir string, acctID uuid.UUID) string {
	return filepath.Join(dir, "credentials", acctID.String()+".json")
}

func readCredentialJSON(t *testing.T, dir string, acctID uuid.UUID) map[string]any {
	t.Helper()
	b, err := os.ReadFile(credentialFilePath(dir, acctID))
	if err != nil {
		t.Fatalf("read credential file: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal credential file: %v", err)
	}
	return m
}

// writeCredentialJSON overwrites the credential file directly (tampering).
func writeCredentialJSON(t *testing.T, dir string, acctID uuid.UUID, m map[string]any) {
	t.Helper()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered record: %v", err)
	}
	if err := os.WriteFile(credentialFilePath(dir, acctID), append(b, '\n'), 0o600); err != nil {
		t.Fatalf("write tampered record: %v", err)
	}
}

// --- §38.1: encryption/decryption round trip ---------------------------------

func TestCredentialRoundTrip(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)

	ctx := context.Background()
	if snap, err := s.LoadCredential(ctx, acct.ID); err != nil {
		t.Fatalf("LoadCredential (missing): %v", err)
	} else {
		if snap.State != core.CredentialStateMissing {
			t.Errorf("state = %q, want missing", snap.State)
		}
		if snap.Token != nil {
			t.Errorf("token = %v, want nil", snap.Token)
		}
		if snap.Generation != 0 {
			t.Errorf("generation = %d, want 0", snap.Generation)
		}
	}

	snap := mustReplace(t, s, acct.ID, 0, "token-roundtrip-0123456789")
	if snap.Generation != 1 {
		t.Errorf("replace generation = %d, want 1", snap.Generation)
	}
	if snap.State != core.CredentialStateValid {
		t.Errorf("replace state = %q, want valid", snap.State)
	}
	if snap.Token != nil {
		t.Errorf("replace snapshot token must be nil (plaintext not retained), got %d bytes", len(snap.Token))
	}

	got, err := s.LoadCredential(ctx, acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if got.Generation != 1 || got.State != core.CredentialStateValid {
		t.Errorf("snapshot = gen %d state %q, want gen 1 valid", got.Generation, got.State)
	}
	if string(got.Token) != "token-roundtrip-0123456789" {
		t.Errorf("token mismatch: %q", got.Token)
	}
	if got.LastValidatedAt.IsZero() {
		t.Errorf("LastValidatedAt is zero after replace")
	}
}

// --- §38.1: wrong AAD (tampered record fails closed) --------------------------

func TestCredentialWrongAAD(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)
	mustReplace(t, s, acct.ID, 0, "token-wrong-aad-0123456789")
	pristine := readCredentialJSON(t, dir, acct.ID)

	t.Run("tampered account_id", func(t *testing.T) {
		m := readCredentialJSON(t, dir, acct.ID)
		m["account_id"] = uuid.MustParse("99999999-9999-9999-9999-999999999999").String()
		writeCredentialJSON(t, dir, acct.ID, m)

		// Record/filename binding check fails closed before any decryption.
		_, err := s.LoadCredential(context.Background(), acct.ID)
		if !errors.Is(err, store.ErrStoreCorrupt) {
			t.Fatalf("errors.Is(ErrStoreCorrupt) = false, err = %v", err)
		}
	})

	t.Run("tampered generation", func(t *testing.T) {
		writeCredentialJSON(t, dir, acct.ID, pristine)
		m := readCredentialJSON(t, dir, acct.ID)
		m["generation"] = float64(42)
		writeCredentialJSON(t, dir, acct.ID, m)

		_, err := s.LoadCredential(context.Background(), acct.ID)
		if !errors.Is(err, store.ErrCryptoDecryptFailed) {
			t.Fatalf("errors.Is(ErrCryptoDecryptFailed) = false, err = %v", err)
		}
		if code := store.CodeOf(err); code != core.CRYPTO_DECRYPT_FAILED {
			t.Errorf("code = %q, want %q", code, core.CRYPTO_DECRYPT_FAILED)
		}
	})
}

// --- §38.1: wrong key ----------------------------------------------------------

func TestCredentialWrongKey(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)
	mustReplace(t, s, acct.ID, 0, "token-wrong-key-0123456789")

	// Same key ID, different key material.
	other := newMemoryKeyProvider(t, "v1")
	s.SetKeyProvider(other)
	_, err := s.LoadCredential(context.Background(), acct.ID)
	if !errors.Is(err, store.ErrCryptoDecryptFailed) {
		t.Fatalf("errors.Is(ErrCryptoDecryptFailed) = false, err = %v", err)
	}
	if code := store.CodeOf(err); code != core.CRYPTO_DECRYPT_FAILED {
		t.Errorf("code = %q, want %q", code, core.CRYPTO_DECRYPT_FAILED)
	}
}

// --- §22.3: key rotation --------------------------------------------------------

func TestCredentialRotation(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	ctx := context.Background()

	kp := newMemoryKeyProvider(t, "v1", "v2")
	kp.setActive("v1")
	s.SetKeyProvider(kp)
	_, acct := seedAccount(t, s)
	mustReplace(t, s, acct.ID, 0, "token-rotation-0123456789")

	if m := readCredentialJSON(t, dir, acct.ID); m["key_version"] != "v1" {
		t.Fatalf("key_version = %v, want v1", m["key_version"])
	}

	kp.setActive("v2")
	if err := s.ReencryptAll(ctx, kp); err != nil {
		t.Fatalf("ReencryptAll: %v", err)
	}

	m := readCredentialJSON(t, dir, acct.ID)
	if m["key_version"] != "v2" {
		t.Errorf("key_version after rotation = %v, want v2", m["key_version"])
	}
	if gen := m["generation"]; gen != float64(1) {
		t.Errorf("generation changed by rotation: %v", gen)
	}

	got, err := s.LoadCredential(ctx, acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential after rotation: %v", err)
	}
	if string(got.Token) != "token-rotation-0123456789" {
		t.Errorf("token mismatch after rotation: %q", got.Token)
	}
}

// --- §21.4/§21.6: generation CAS -------------------------------------------------

func TestReplaceCredentialGenerationCAS(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)
	ctx := context.Background()

	mustReplace(t, s, acct.ID, 0, "token-cas-one-0123456789")

	// Stale expected generation -> conflict.
	_, err := s.ReplaceCredential(ctx, replaceReq(acct.ID, 0, []byte("token-cas-two-0123456789")))
	if !errors.Is(err, store.ErrGenerationConflict) {
		t.Fatalf("errors.Is(ErrGenerationConflict) = false, err = %v", err)
	}
	if code := store.CodeOf(err); code != core.STORE_GENERATION_CONFLICT {
		t.Errorf("code = %q, want %q", code, core.STORE_GENERATION_CONFLICT)
	}

	// Correct expected generation advances.
	snap := mustReplace(t, s, acct.ID, 1, "token-cas-two-0123456789")
	if snap.Generation != 2 {
		t.Errorf("generation = %d, want 2", snap.Generation)
	}
	got, err := s.LoadCredential(ctx, acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if string(got.Token) != "token-cas-two-0123456789" {
		t.Errorf("token mismatch: %q", got.Token)
	}
}

// --- §23.3: mark-invalid CAS -------------------------------------------------------

func TestMarkCredentialInvalid(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)
	ctx := context.Background()

	mustReplace(t, s, acct.ID, 0, "token-markinvalid-0123456")

	if err := s.MarkCredentialInvalid(ctx, acct.ID, 1, "unauthorized"); err != nil {
		t.Fatalf("MarkCredentialInvalid: %v", err)
	}
	rec, err := s.LoadCredentialRecord(acct.ID)
	if err != nil {
		t.Fatalf("LoadCredentialRecord: %v", err)
	}
	if rec.State != core.CredentialStateInvalid.String() {
		t.Errorf("state = %q, want invalid", rec.State)
	}
	if rec.InvalidatedAtMs == nil {
		t.Errorf("invalidated_at_ms is nil")
	}
	if rec.LastErrorClass == nil || *rec.LastErrorClass != "unauthorized" {
		t.Errorf("last_error_class = %v, want unauthorized", rec.LastErrorClass)
	}
	if rec.Generation != 1 {
		t.Errorf("generation changed by mark-invalid: %d", rec.Generation)
	}
	// Ciphertext retained: the invalid token still decrypts (§21.3).
	snap, err := s.LoadCredential(ctx, acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential (invalid): %v", err)
	}
	if snap.State != core.CredentialStateInvalid || string(snap.Token) != "token-markinvalid-0123456" {
		t.Errorf("snapshot = %q/%q, want invalid with token", snap.State, snap.Token)
	}

	// §23.3: stale generation must be a silent no-op SUCCESS.
	before, err := os.ReadFile(credentialFilePath(dir, acct.ID))
	if err != nil {
		t.Fatalf("read before stale mark-invalid: %v", err)
	}
	if err := s.MarkCredentialInvalid(ctx, acct.ID, 999, "unauthorized"); err != nil {
		t.Fatalf("stale MarkCredentialInvalid returned error: %v", err)
	}
	after, err := os.ReadFile(credentialFilePath(dir, acct.ID))
	if err != nil {
		t.Fatalf("read after stale mark-invalid: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("stale mark-invalid modified the record file")
	}

	// Mark-invalid on an account with no credential file: no-op success.
	other := testAccount(testDeployment().ID)
	other.ID = uuid.MustParse("44444444-4444-4444-4444-444444444444")
	other.BindOnFirstToken = false
	uid := uuid.MustParse("55555555-5555-5555-5555-555555555555")
	other.CoderUserID = &uid
	if err := s.AddAccount(other); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	if err := s.MarkCredentialInvalid(ctx, other.ID, 0, "unauthorized"); err != nil {
		t.Fatalf("mark-invalid without record: %v", err)
	}
}

// --- §14.5: clear -------------------------------------------------------------------

func TestClearCredential(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)
	ctx := context.Background()

	mustReplace(t, s, acct.ID, 0, "token-clear-01234567890123")

	// Stale generation -> conflict error (unlike mark-invalid, clear is explicit).
	if err := s.ClearCredential(ctx, acct.ID, 0); !errors.Is(err, store.ErrGenerationConflict) {
		t.Fatalf("stale clear: errors.Is(ErrGenerationConflict) = false, err = %v", err)
	}

	if err := s.ClearCredential(ctx, acct.ID, 1); err != nil {
		t.Fatalf("ClearCredential: %v", err)
	}
	rec, err := s.LoadCredentialRecord(acct.ID)
	if err != nil {
		t.Fatalf("LoadCredentialRecord: %v", err)
	}
	if rec.Generation != 2 {
		t.Errorf("generation = %d, want 2", rec.Generation)
	}
	if rec.State != core.CredentialStateMissing.String() {
		t.Errorf("state = %q, want missing", rec.State)
	}
	if rec.Ciphertext != nil || rec.Nonce != nil || rec.KeyVersion != nil {
		t.Errorf("tombstone not NULLed: ciphertext=%v nonce=%v key_version=%v", rec.Ciphertext, rec.Nonce, rec.KeyVersion)
	}

	snap, err := s.LoadCredential(ctx, acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential after clear: %v", err)
	}
	if snap.State != core.CredentialStateMissing || snap.Token != nil || snap.Generation != 2 {
		t.Errorf("snapshot = %q gen %d token %v, want missing/2/nil", snap.State, snap.Generation, snap.Token)
	}
}

// --- §10.5: bind-on-first-token ---------------------------------------------------------

func TestReplaceCredentialBindOnFirstToken(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	dep, acct := seedAccount(t, s) // testAccount: nil CoderUserID, BindOnFirstToken true
	ctx := context.Background()

	mustReplace(t, s, acct.ID, 0, "token-bind-012345678901234")

	bound, err := s.GetAccount(acct.ID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if bound.CoderUserID == nil || *bound.CoderUserID != credIdentity().ID {
		t.Errorf("coder_user_id = %v, want %s", bound.CoderUserID, credIdentity().ID)
	}
	if bound.CachedUsername != "taxilian" {
		t.Errorf("cached_username = %q, want taxilian", bound.CachedUsername)
	}

	// Second unbound account, same Coder UUID -> duplicate rejection.
	second := testAccount(dep.ID)
	second.ID = uuid.MustParse("66666666-6666-6666-6666-666666666666")
	if err := s.AddAccount(second); err != nil {
		t.Fatalf("AddAccount second: %v", err)
	}
	_, err = s.ReplaceCredential(ctx, replaceReq(second.ID, 0, []byte("token-bind-2-01234567890123")))
	if !errors.Is(err, store.ErrDuplicateCoderUser) {
		t.Fatalf("errors.Is(ErrDuplicateCoderUser) = false, err = %v", err)
	}
	// The failed bind must not have created a credential file.
	if _, statErr := os.Stat(credentialFilePath(dir, second.ID)); !os.IsNotExist(statErr) {
		t.Errorf("credential file exists for rejected bind: stat err = %v", statErr)
	}

	// Account with binding disabled must reject the first token.
	third := testAccount(dep.ID)
	third.ID = uuid.MustParse("77777777-7777-7777-7777-777777777777")
	third.BindOnFirstToken = false
	if err := s.AddAccount(third); err != nil {
		t.Fatalf("AddAccount third: %v", err)
	}
	_, err = s.ReplaceCredential(ctx, replaceReq(third.ID, 0, []byte("token-bind-3-01234567890123")))
	if !errors.Is(err, store.ErrWrongIdentity) {
		t.Fatalf("errors.Is(ErrWrongIdentity) = false, err = %v", err)
	}
}

// --- §10.4: wrong-user replacement rejected ------------------------------------------------

func TestReplaceCredentialWrongIdentity(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	dep, acct := seedAccount(t, s)
	ctx := context.Background()

	mustReplace(t, s, acct.ID, 0, "token-identity-012345678901")

	otherIdentity := core.CoderIdentity{
		ID:       uuid.MustParse("88888888-8888-8888-8888-888888888888"),
		Username: "mallory",
		Status:   "active",
	}
	req := core.ReplaceCredentialRequest{
		AccountID:          acct.ID,
		ExpectedGeneration: 1,
		Token:              []byte("token-identity-2-012345678"),
		Identity:           otherIdentity,
	}
	before, err := os.ReadFile(credentialFilePath(dir, acct.ID))
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	_, err = s.ReplaceCredential(ctx, req)
	if !errors.Is(err, store.ErrWrongIdentity) {
		t.Fatalf("errors.Is(ErrWrongIdentity) = false, err = %v", err)
	}
	if code := store.CodeOf(err); code != core.AUTH_WRONG_CODER_IDENTITY {
		t.Errorf("code = %q, want %q", code, core.AUTH_WRONG_CODER_IDENTITY)
	}
	after, err := os.ReadFile(credentialFilePath(dir, acct.ID))
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("wrong-identity rejection modified the credential file")
	}

	// Correct identity still replaces.
	snap := mustReplace(t, s, acct.ID, 1, "token-identity-2-012345678")
	if snap.Generation != 2 {
		t.Errorf("generation = %d, want 2", snap.Generation)
	}
	_ = dep
}

// --- account disabled during renewal -------------------------------------------------------

func TestReplaceCredentialAccountDisabled(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)

	mustReplace(t, s, acct.ID, 0, "token-disabled-012345678901")

	if err := s.SetAccountEnabled(acct.ID, false); err != nil {
		t.Fatalf("SetAccountEnabled: %v", err)
	}
	before, err := os.ReadFile(credentialFilePath(dir, acct.ID))
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	_, err = s.ReplaceCredential(context.Background(), replaceReq(acct.ID, 1, []byte("token-disabled-2-01234567")))
	if !errors.Is(err, store.ErrAccountDisabled) {
		t.Fatalf("errors.Is(ErrAccountDisabled) = false, err = %v", err)
	}
	if code := store.CodeOf(err); code != core.AUTH_ACCOUNT_DISABLED {
		t.Errorf("code = %q, want %q", code, core.AUTH_ACCOUNT_DISABLED)
	}
	after, err := os.ReadFile(credentialFilePath(dir, acct.ID))
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("disabled-account rejection modified the credential file")
	}
}

// --- §21.6: failed replace leaves the old file byte-identical --------------------------------

func TestReplaceCredentialFailurePreservesFile(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)

	mustReplace(t, s, acct.ID, 0, "token-preserve-012345678901")
	path := credentialFilePath(dir, acct.ID)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	sumBefore := sha256.Sum256(before)

	// Generation conflict after all checks pass: the deepest failure point.
	if _, err := s.ReplaceCredential(context.Background(), replaceReq(acct.ID, 42, []byte("token-preserve-2-01234567"))); !errors.Is(err, store.ErrGenerationConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if sumAfter := sha256.Sum256(after); sumAfter != sumBefore {
		t.Errorf("credential file changed after failed replace:\nbefore %x\nafter  %x", sumBefore, sumAfter)
	}
}

// --- §23.2: concurrent replace -> exactly one winner --------------------------------------------

func TestReplaceCredentialConcurrentSameGeneration(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)
	ctx := context.Background()

	const n = 20
	var successes, conflicts atomic.Int64
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token := fmt.Sprintf("token-concurrent-%02d-0123456789", i)
			_, err := s.ReplaceCredential(ctx, replaceReq(acct.ID, 0, []byte(token)))
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, store.ErrGenerationConflict):
				conflicts.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if successes.Load() != 1 {
		t.Errorf("successes = %d, want exactly 1", successes.Load())
	}
	if conflicts.Load() != n-1 {
		t.Errorf("conflicts = %d, want %d", conflicts.Load(), n-1)
	}

	snap, err := s.LoadCredential(ctx, acct.ID)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if snap.Generation != 1 {
		t.Errorf("generation = %d, want 1 after single winner", snap.Generation)
	}
}

// --- §21.5/§22: no plaintext at rest ------------------------------------------------------------

func TestCredentialNoPlaintextAtRest(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)

	marker := []byte("SECRETMARKER123-credential-plaintext")
	mustReplace(t, s, acct.ID, 0, string(marker))

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, marker) {
			t.Errorf("plaintext marker found in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
}

// --- §21.2 invariant: state=missing iff ciphertext NULL -------------------------------------------

func TestCredentialStateInvariant(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)

	cases := map[string]map[string]any{
		"missing with ciphertext": {
			"account_id": acct.ID.String(),
			"generation": 1,
			"state":      "missing",
			"ciphertext": "aGk=",
			"nonce":      "AAAAAAAAAAAA",
		},
		"valid without ciphertext": {
			"account_id": acct.ID.String(),
			"generation": 1,
			"state":      "valid",
		},
		"ciphertext without key_version": {
			"account_id": acct.ID.String(),
			"generation": 1,
			"state":      "valid",
			"ciphertext": "aGk=",
			"nonce":      "AAAAAAAAAAAA",
		},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			writeCredentialJSON(t, dir, acct.ID, m)
			_, err := s.LoadCredential(context.Background(), acct.ID)
			if !errors.Is(err, store.ErrStoreCorrupt) {
				t.Fatalf("errors.Is(ErrStoreCorrupt) = false, err = %v", err)
			}
		})
	}
}

// --- key provider required --------------------------------------------------------------------------

func TestCredentialKeyProviderRequired(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)
	mustReplace(t, s, acct.ID, 0, "token-noprovider-0123456789")

	s.SetKeyProvider(nil)
	ctx := context.Background()
	if _, err := s.LoadCredential(ctx, acct.ID); err == nil {
		t.Fatalf("LoadCredential without provider succeeded")
	} else if code := store.CodeOf(err); code != core.CRYPTO_KEY_UNAVAILABLE {
		t.Errorf("load code = %q, want %q", code, core.CRYPTO_KEY_UNAVAILABLE)
	}
	if _, err := s.ReplaceCredential(ctx, replaceReq(acct.ID, 1, []byte("token-noprovider-2-012345"))); err == nil {
		t.Fatalf("ReplaceCredential without provider succeeded")
	} else if code := store.CodeOf(err); code != core.CRYPTO_KEY_UNAVAILABLE {
		t.Errorf("replace code = %q, want %q", code, core.CRYPTO_KEY_UNAVAILABLE)
	}
}

// --- token wipe ----------------------------------------------------------------------------------------

func TestReplaceCredentialWipesToken(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	_, acct := seedAccount(t, s)

	token := []byte("token-wipe-me-01234567890123")
	if _, err := s.ReplaceCredential(context.Background(), replaceReq(acct.ID, 0, token)); err != nil {
		t.Fatalf("ReplaceCredential: %v", err)
	}
	if !bytes.Equal(token, make([]byte, len(token))) {
		t.Errorf("req.Token not wiped after ReplaceCredential: %q", token)
	}
}
