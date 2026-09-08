package store_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
	"github.com/HamStudy/coder-ssh-gateway/internal/testleaks"
)

// --- enriched key records ------------------------------------------------------

// AddKey, ListKeysForAccount, and LookupByPublicKey must all surface Label,
// CreatedAtMs, and LastUsedAtMs from the stored record.
func TestKeyRecordsEnriched(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep, acct, key, rec := seedStore(t, s)
	ctx := context.Background()

	if rec.Label != "laptop key" {
		t.Errorf("AddKey Label = %q, want %q", rec.Label, "laptop key")
	}
	if rec.CreatedAtMs <= 0 {
		t.Errorf("AddKey CreatedAtMs = %d, want > 0", rec.CreatedAtMs)
	}
	if rec.LastUsedAtMs != nil {
		t.Errorf("AddKey LastUsedAtMs = %v, want nil for fresh key", *rec.LastUsedAtMs)
	}

	keys, err := s.ListKeysForAccount(acct.ID)
	if err != nil {
		t.Fatalf("ListKeysForAccount: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("ListKeysForAccount = %d keys, want 1", len(keys))
	}
	if keys[0].Label != "laptop key" || keys[0].CreatedAtMs != rec.CreatedAtMs || keys[0].LastUsedAtMs != nil {
		t.Errorf("ListKeysForAccount record = %+v, want label/created populated, last-used nil", keys[0])
	}

	_, lk, err := s.LookupByPublicKey(ctx, dep.ID, key)
	if err != nil {
		t.Fatalf("LookupByPublicKey: %v", err)
	}
	if lk.Label != "laptop key" || lk.CreatedAtMs != rec.CreatedAtMs || lk.LastUsedAtMs != nil {
		t.Errorf("LookupByPublicKey record = %+v, want label/created populated, last-used nil", lk)
	}

	if err := s.TouchKeyLastUsed(rec.ID); err != nil {
		t.Fatalf("TouchKeyLastUsed: %v", err)
	}
	keys, err = s.ListKeysForAccount(acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].LastUsedAtMs == nil || *keys[0].LastUsedAtMs < rec.CreatedAtMs {
		t.Errorf("LastUsedAtMs = %v, want >= CreatedAtMs %d after touch", keys[0].LastUsedAtMs, rec.CreatedAtMs)
	}
}

// --- DeleteKey -----------------------------------------------------------------

func TestDeleteKeyHappyOneOfTwo(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep, acct, keyA, recA := seedStore(t, s)
	keyB := mustKey(t)
	recB, err := s.AddKey(acct.ID, keyB, "second key")
	if err != nil {
		t.Fatalf("AddKey B: %v", err)
	}
	ctx := context.Background()

	if err := s.DeleteKey(acct.ID, recB.ID); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "keys", keyHexFilename(keyB))); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("deleted key file still present (stat err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keys", keyHexFilename(keyA))); err != nil {
		t.Errorf("surviving key file missing: %v", err)
	}

	keys, err := s.ListKeysForAccount(acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != recA.ID {
		t.Fatalf("ListKeysForAccount after delete = %+v, want only key A", keys)
	}

	// Deleted key -> uniform unknown-key rejection, byte-identical to any
	// other unknown key (no existence oracle).
	_, _, errDeleted := s.LookupByPublicKey(ctx, dep.ID, keyB)
	if !errors.Is(errDeleted, store.ErrUnknownKey) {
		t.Fatalf("deleted key err = %v, want ErrUnknownKey (uniform)", errDeleted)
	}
	if got := store.CodeOf(errDeleted); got != core.AUTH_UNKNOWN_KEY {
		t.Errorf("deleted key CodeOf = %q, want %q", got, core.AUTH_UNKNOWN_KEY)
	}
	_, _, errUnknown := s.LookupByPublicKey(ctx, dep.ID, mustKey(t))
	if errDeleted.Error() != errUnknown.Error() {
		t.Errorf("deleted key error %q differs from unknown key error %q", errDeleted, errUnknown)
	}

	if _, _, err := s.LookupByPublicKey(ctx, dep.ID, keyA); err != nil {
		t.Errorf("surviving key no longer looks up: %v", err)
	}
}

func TestDeleteKeyUnknownID(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	_, acct, _, _ := seedStore(t, s)

	err := s.DeleteKey(acct.ID, uuid.New())
	if !errors.Is(err, store.ErrKeyNotFound) {
		t.Fatalf("DeleteKey(unknown) err = %v, want ErrKeyNotFound chain", err)
	}
	if got := store.CodeOf(err); got != core.STORE_UNAVAILABLE {
		t.Errorf("CodeOf = %q, want %q", got, core.STORE_UNAVAILABLE)
	}
}

// Account scoping is enforced at the store layer: a valid keyID offered with
// the wrong accountID is a not-found, and the store is left untouched.
func TestDeleteKeyAccountScopeMismatch(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep := testDeployment()
	if err := s.EnsureDeployment(dep); err != nil {
		t.Fatal(err)
	}
	owner := testAccount(dep.ID)
	if err := s.AddAccount(owner); err != nil {
		t.Fatal(err)
	}
	other := testAccount(dep.ID)
	other.ID = uuid.New()
	if err := s.AddAccount(other); err != nil {
		t.Fatal(err)
	}
	key := mustKey(t)
	rec, err := s.AddKey(owner.ID, key, "owner key")
	if err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteKey(other.ID, rec.ID); !errors.Is(err, store.ErrKeyNotFound) {
		t.Fatalf("DeleteKey(mismatched account) err = %v, want ErrKeyNotFound chain", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "keys", keyHexFilename(key))); err != nil {
		t.Errorf("key file removed by mismatched-account delete: %v", err)
	}
	keys, err := s.ListKeysForAccount(owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != rec.ID {
		t.Errorf("owner keys after mismatched delete = %+v, want unchanged", keys)
	}
}

// Deleting an account's ONLY key must succeed: there is deliberately no
// last-key preservation guard (recovery is `login@` + a fresh Coder token).
func TestDeleteOnlyKeySucceeds(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	_, acct, key, rec := seedStore(t, s)

	if err := s.DeleteKey(acct.ID, rec.ID); err != nil {
		t.Fatalf("deleting the account's only key failed: %v (no last-key guard by design)", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keys", keyHexFilename(key))); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("key file still present after only-key delete (stat err=%v)", err)
	}
	keys, err := s.ListKeysForAccount(acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("ListKeysForAccount after only-key delete = %+v, want empty", keys)
	}
}

func TestDeleteKeyLeavesOtherAccountsIntact(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	dep := testDeployment()
	if err := s.EnsureDeployment(dep); err != nil {
		t.Fatal(err)
	}
	acctA := testAccount(dep.ID)
	acctB := testAccount(dep.ID)
	acctB.ID = uuid.New()
	for _, a := range []core.Account{acctA, acctB} {
		if err := s.AddAccount(a); err != nil {
			t.Fatal(err)
		}
	}
	keyA := mustKey(t)
	recA, err := s.AddKey(acctA.ID, keyA, "A key")
	if err != nil {
		t.Fatal(err)
	}
	keyB := mustKey(t)
	if _, err := s.AddKey(acctB.ID, keyB, "B key"); err != nil {
		t.Fatal(err)
	}
	mustReplace(t, s, acctB.ID, 0, "token-b-0123456789abcdef")
	credBBefore, err := os.ReadFile(credentialFilePath(dir, acctB.ID))
	if err != nil {
		t.Fatal(err)
	}
	acctBFile := filepath.Join(dir, "accounts", acctB.ID.String()+".json")
	acctBBefore, err := os.ReadFile(acctBFile)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteKey(acctA.ID, recA.ID); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	// Account B untouched: key file, credential bytes, account bytes.
	if _, err := os.Stat(filepath.Join(dir, "keys", keyHexFilename(keyB))); err != nil {
		t.Errorf("account B key file affected: %v", err)
	}
	if got, _ := os.ReadFile(credentialFilePath(dir, acctB.ID)); string(got) != string(credBBefore) {
		t.Error("account B credential file changed by deleting account A's key")
	}
	if got, _ := os.ReadFile(acctBFile); string(got) != string(acctBBefore) {
		t.Error("account B record changed by deleting account A's key")
	}
	if _, err := s.GetAccount(acctB.ID); err != nil {
		t.Errorf("GetAccount(B) after deleting A's key: %v", err)
	}
	// Account A's own record also untouched by a key delete.
	if _, err := s.GetAccount(acctA.ID); err != nil {
		t.Errorf("GetAccount(A) after key delete: %v", err)
	}
}

// The digest filename is derived from the key material, so after a delete the
// same public key can be enrolled again (fresh record, new key ID).
func TestReAddKeyAfterDelete(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	_, acct, key, rec := seedStore(t, s)

	if err := s.DeleteKey(acct.ID, rec.ID); err != nil {
		t.Fatal(err)
	}
	rec2, err := s.AddKey(acct.ID, key, "re-added")
	if err != nil {
		t.Fatalf("re-adding the same public key after delete: %v", err)
	}
	if rec2.ID == rec.ID {
		t.Error("re-added key reused the old record ID")
	}
	if rec2.Label != "re-added" {
		t.Errorf("re-added label = %q", rec2.Label)
	}
	keys, err := s.ListKeysForAccount(acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != rec2.ID {
		t.Errorf("ListKeysForAccount after re-add = %+v", keys)
	}
}

func TestDeleteKeyClosedStore(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = s.DeleteKey(uuid.New(), uuid.New())
	if !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("DeleteKey(closed) err = %v, want ErrStoreClosed chain", err)
	}
	if got := store.CodeOf(err); got != core.STORE_UNAVAILABLE {
		t.Errorf("CodeOf = %q, want %q", got, core.STORE_UNAVAILABLE)
	}

	err = s.DeleteAccount(uuid.New())
	if !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("DeleteAccount(closed) err = %v, want ErrStoreClosed chain", err)
	}
}

// --- DeleteAccount -------------------------------------------------------------

func TestDeleteAccountCascade(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	dep := testDeployment()
	if err := s.EnsureDeployment(dep); err != nil {
		t.Fatal(err)
	}
	acct := testAccount(dep.ID)
	if err := s.AddAccount(acct); err != nil {
		t.Fatal(err)
	}
	keyA, keyB := mustKey(t), mustKey(t)
	if _, err := s.AddKey(acct.ID, keyA, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddKey(acct.ID, keyB, "b"); err != nil {
		t.Fatal(err)
	}
	mustReplace(t, s, acct.ID, 0, "token-cascade-01234567")
	ctx := context.Background()

	if err := s.DeleteAccount(acct.ID); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "keys", keyHexFilename(keyA))); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("key A file still present (stat err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keys", keyHexFilename(keyB))); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("key B file still present (stat err=%v)", err)
	}
	if _, err := os.Stat(credentialFilePath(dir, acct.ID)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("credential file still present (stat err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "accounts", acct.ID.String()+".json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("account file still present (stat err=%v)", err)
	}

	if _, err := s.GetAccount(acct.ID); !errors.Is(err, store.ErrAccountNotFound) {
		t.Errorf("GetAccount after cascade err = %v, want ErrAccountNotFound", err)
	}

	// Former keys fail uniformly — no existence oracle after account death.
	_, _, errA := s.LookupByPublicKey(ctx, dep.ID, keyA)
	if !errors.Is(errA, store.ErrUnknownKey) {
		t.Fatalf("former key A err = %v, want ErrUnknownKey (uniform)", errA)
	}
	if got := store.CodeOf(errA); got != core.AUTH_UNKNOWN_KEY {
		t.Errorf("former key A CodeOf = %q, want %q", got, core.AUTH_UNKNOWN_KEY)
	}
	_, _, errUnknown := s.LookupByPublicKey(ctx, dep.ID, mustKey(t))
	if errA.Error() != errUnknown.Error() {
		t.Errorf("former key error %q differs from unknown key error %q", errA, errUnknown)
	}
}

// Zero keys and a missing credential are not errors: delete what exists.
func TestDeleteAccountZeroKeysMissingCredential(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	_, acct, _, _ := seedStore(t, s)
	// seedStore adds one key; delete it first to get a keyless, credential-less
	// account.
	keys, err := s.ListKeysForAccount(acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteKey(acct.ID, keys[0].ID); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteAccount(acct.ID); err != nil {
		t.Fatalf("DeleteAccount(zero keys, no credential): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "accounts", acct.ID.String()+".json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("account file still present (stat err=%v)", err)
	}
}

func TestDeleteAccountUnknown(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)

	err := s.DeleteAccount(uuid.New())
	if !errors.Is(err, store.ErrAccountNotFound) {
		t.Fatalf("DeleteAccount(unknown) err = %v, want ErrAccountNotFound chain", err)
	}
	if got := store.CodeOf(err); got != core.STORE_UNAVAILABLE {
		t.Errorf("CodeOf = %q, want %q", got, core.STORE_UNAVAILABLE)
	}
}

func TestDeleteAccountLeavesOthersIntact(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	s.SetKeyProvider(newMemoryKeyProvider(t, "v1"))
	dep := testDeployment()
	if err := s.EnsureDeployment(dep); err != nil {
		t.Fatal(err)
	}
	doomed := testAccount(dep.ID)
	survivor := testAccount(dep.ID)
	survivor.ID = uuid.New()
	for _, a := range []core.Account{doomed, survivor} {
		if err := s.AddAccount(a); err != nil {
			t.Fatal(err)
		}
	}
	dKey, sKey := mustKey(t), mustKey(t)
	if _, err := s.AddKey(doomed.ID, dKey, "doomed"); err != nil {
		t.Fatal(err)
	}
	sRec, err := s.AddKey(survivor.ID, sKey, "survivor")
	if err != nil {
		t.Fatal(err)
	}
	mustReplace(t, s, doomed.ID, 0, "token-doomed-01234567")
	// Distinct Coder identity: (deployment, coder_user_id) is unique.
	survivorReq := replaceReq(survivor.ID, 0, []byte("token-survive-01234567"))
	survivorReq.Identity.ID = uuid.MustParse("44444444-4444-4444-4444-444444444444")
	if _, err := s.ReplaceCredential(context.Background(), survivorReq); err != nil {
		t.Fatalf("ReplaceCredential(survivor): %v", err)
	}
	ctx := context.Background()

	if err := s.DeleteAccount(doomed.ID); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if _, _, err := s.LookupByPublicKey(ctx, dep.ID, sKey); err != nil {
		t.Fatalf("survivor key no longer looks up: %v", err)
	}
	snap, err := s.LoadCredential(ctx, survivor.ID)
	if err != nil {
		t.Fatalf("survivor credential load: %v", err)
	}
	if snap.Generation != 1 {
		t.Errorf("survivor credential generation = %d, want 1", snap.Generation)
	}
	got, err := s.GetAccount(survivor.ID)
	if err != nil || got.ID != survivor.ID {
		t.Errorf("survivor account = %v, %v", got, err)
	}
	keys, err := s.ListKeysForAccount(survivor.ID)
	if err != nil || len(keys) != 1 || keys[0].ID != sRec.ID {
		t.Errorf("survivor keys = %+v, %v", keys, err)
	}
	if _, err := os.Stat(credentialFilePath(dir, survivor.ID)); err != nil {
		t.Errorf("survivor credential file affected: %v", err)
	}
}

// Fail-closed property the cascade ordering relies on: a key record whose
// account record is gone (crash-midpoint or restore mismatch) must NEVER
// authenticate — LookupByPublicKey treats it as corruption, not a match.
func TestLookupFailsClosedWhenAccountMissing(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep, _, key, _ := seedStore(t, s)
	acctID := testAccount(dep.ID).ID // the account seedStore created

	if err := os.Remove(filepath.Join(dir, "accounts", acctID.String()+".json")); err != nil {
		t.Fatal(err)
	}

	_, _, err := s.LookupByPublicKey(context.Background(), dep.ID, key)
	if err == nil {
		t.Fatal("orphaned key authenticated against a missing account, want fail-closed error")
	}
	if !errors.Is(err, store.ErrStoreCorrupt) {
		t.Errorf("orphaned key err = %v, want ErrStoreCorrupt chain", err)
	}
}

// --- concurrency -----------------------------------------------------------------

// Concurrent SetKeyEnabled + DeleteKey on the same key set under -race must
// never corrupt the store: every error is the typed not-found (lost race),
// and afterwards the keys directory holds no leftover records for the
// account while the account record itself remains intact.
func TestConcurrentSetKeyEnabledAndDeleteKey(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep, acct, _, rec0 := seedStore(t, s)

	ids := []uuid.UUID{rec0.ID}
	for i := 0; i < 7; i++ {
		rec, err := s.AddKey(acct.ID, mustKey(t), "concurrent")
		if err != nil {
			t.Fatalf("AddKey %d: %v", i, err)
		}
		ids = append(ids, rec.ID)
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(ids)*2)
	for _, id := range ids {
		id := id
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := s.SetKeyEnabled(id, false); err != nil {
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			if err := s.DeleteKey(acct.ID, id); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, store.ErrKeyNotFound) {
			t.Errorf("concurrent mutation error = %v, want only ErrKeyNotFound losses", err)
		}
	}

	keys, err := s.ListKeysForAccount(acct.ID)
	if err != nil {
		t.Fatalf("ListKeysForAccount after concurrent run: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("keys remain after all deletes: %+v", keys)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			t.Errorf("leftover key record file after deletes: %s", e.Name())
		}
	}
	if _, err := s.GetAccount(acct.ID); err != nil {
		t.Errorf("account record damaged by concurrent key deletes: %v", err)
	}
	_ = dep
}
