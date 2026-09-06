// Credential record crypto semantics (design §21.3–21.6, §22, §23.2–23.3)
// on top of the flat-file primitives from store.go.
//
// Transactional model: there is no multi-file transaction. The store write
// mutex serializes every credential mutation (§23.2: one active renewal per
// account), generation compare-and-set detects interleaved actors (§21.4),
// and every record write is a temp-file + fsync + rename, so a failed
// ReplaceCredential leaves the previous credential file byte-identical.
//
// Plaintext ownership (§21.5/§22.5): ReplaceCredential wipes req.Token
// before returning, success or failure. LoadCredential returns a fresh
// plaintext buffer owned by the CALLER (T14/T17 need it); the store never
// caches decrypted tokens. ReencryptAll wipes each per-record plaintext
// after resealing.
package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/secretbox"
)

var (
	ErrGenerationConflict  = errors.New("credential generation conflict")
	ErrWrongIdentity       = errors.New("credential identity does not match account binding")
	ErrCryptoDecryptFailed = errors.New("credential decryption failed")
	ErrNoKeyProvider       = errors.New("no encryption key provider configured")
)

func generationConflictErr(accountID uuid.UUID, want, got int64) error {
	return &Error{
		Code: core.STORE_GENERATION_CONFLICT,
		Msg:  fmt.Sprintf("credential generation conflict for account %s: expected %d, current %d", accountID, want, got),
		Err:  ErrGenerationConflict,
	}
}

func wrongIdentityErr(accountID uuid.UUID) error {
	return &Error{
		Code: core.AUTH_WRONG_CODER_IDENTITY,
		Msg:  "credential identity does not match the binding of account " + accountID.String(),
		Err:  ErrWrongIdentity,
	}
}

func cryptoKeyUnavailable(msg string, cause error) error {
	return &Error{Code: core.CRYPTO_KEY_UNAVAILABLE, Msg: msg, Err: cause}
}

// SetKeyProvider installs the envelope key provider used by the credential
// methods (§22.2). It must be called after Open, before any Load/Replace/
// ReencryptAll on records holding ciphertext; tests use in-memory providers,
// production wires a secretbox.FileKeyProvider from the deployment secrets.
func (s *Store) SetKeyProvider(kp secretbox.KeyProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kp = kp
}

// loadCredentialRecordLocked reads the record; exists is false (with a
// synthesized state=missing, generation 0 record) when no file has been
// written yet. The caller must hold s.mu.
func (s *Store) loadCredentialRecordLocked(accountID uuid.UUID) (rec CredentialRecord, exists bool, err error) {
	err = s.readRecord(dirCredentials, accountID.String()+".json", &rec)
	if errors.Is(err, fs.ErrNotExist) {
		return CredentialRecord{
			AccountID: accountID.String(),
			State:     core.CredentialStateMissing.String(),
		}, false, nil
	}
	if err != nil {
		return CredentialRecord{}, false, err
	}
	return rec, true, nil
}

// validateCredentialRecord enforces the §21.2 CHECK invariant in code:
// state=missing iff ciphertext is NULL, and any ciphertext requires a key
// version and nonce. Violations mean on-disk tampering or corruption.
func validateCredentialRecord(rec CredentialRecord) error {
	if _, err := core.ParseCredentialState(rec.State); err != nil {
		return storeUnavailable("credential "+rec.AccountID+": unknown state "+rec.State, ErrStoreCorrupt)
	}
	missing := rec.State == core.CredentialStateMissing.String()
	hasCiphertext := len(rec.Ciphertext) > 0
	if missing == hasCiphertext {
		return storeUnavailable(
			fmt.Sprintf("credential %s: state %q inconsistent with ciphertext presence", rec.AccountID, rec.State),
			ErrStoreCorrupt)
	}
	if hasCiphertext && (rec.KeyVersion == nil || len(rec.Nonce) == 0) {
		return storeUnavailable("credential "+rec.AccountID+": ciphertext without key_version/nonce", ErrStoreCorrupt)
	}
	return nil
}

func (s *Store) keyProviderLocked() (secretbox.KeyProvider, error) {
	if s.kp == nil {
		return nil, cryptoKeyUnavailable("credential operation requires a key provider (SetKeyProvider)", ErrNoKeyProvider)
	}
	return s.kp, nil
}

func snapshotFromRecord(rec CredentialRecord, token []byte) core.CredentialSnapshot {
	state, _ := core.ParseCredentialState(rec.State)
	snap := core.CredentialSnapshot{
		AccountID:  uuid.MustParse(rec.AccountID),
		Generation: rec.Generation,
		State:      state,
		Token:      token,
	}
	if rec.LastValidatedAtMs != nil {
		snap.LastValidatedAt = time.UnixMilli(*rec.LastValidatedAtMs).UTC()
	}
	return snap
}

// LoadCredential decrypts the stored credential into a caller-owned snapshot.
//
// A missing record is a state, not an error (§21.3): the snapshot has
// State=missing and a nil Token. Decryption failure (wrong key, tampered
// AAD/ciphertext) fails closed with ErrCryptoDecryptFailed
// (CRYPTO_DECRYPT_FAILED). The returned Token buffer belongs to the caller;
// the store retains no copy.
func (s *Store) LoadCredential(ctx context.Context, accountID uuid.UUID) (core.CredentialSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return core.CredentialSnapshot{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return core.CredentialSnapshot{}, err
	}

	rec, exists, err := s.loadCredentialRecordLocked(accountID)
	if err != nil {
		return core.CredentialSnapshot{}, err
	}
	if !exists {
		return snapshotFromRecord(rec, nil), nil
	}
	if err := validateCredentialRecord(rec); err != nil {
		return core.CredentialSnapshot{}, err
	}
	if rec.AccountID != accountID.String() {
		return core.CredentialSnapshot{}, storeUnavailable(
			"credential file "+accountID.String()+".json holds account "+rec.AccountID, ErrStoreCorrupt)
	}
	if rec.State == core.CredentialStateMissing.String() {
		return snapshotFromRecord(rec, nil), nil
	}

	acct, err := s.getAccountLocked(accountID)
	if err != nil {
		return core.CredentialSnapshot{}, err
	}
	kp, err := s.keyProviderLocked()
	if err != nil {
		return core.CredentialSnapshot{}, err
	}
	key, err := kp.Key(ctx, *rec.KeyVersion)
	if err != nil {
		return core.CredentialSnapshot{}, cryptoKeyUnavailable("load credential key "+*rec.KeyVersion, err)
	}
	token, err := secretbox.Open(*rec.KeyVersion, key, rec.Nonce, rec.Ciphertext,
		secretbox.CredentialAAD(acct.DeploymentID, accountID, rec.Generation))
	if err != nil {
		return core.CredentialSnapshot{}, &Error{
			Code: core.CRYPTO_DECRYPT_FAILED,
			Msg:  ErrCryptoDecryptFailed.Error(),
			Err:  fmt.Errorf("%w: %w", ErrCryptoDecryptFailed, err),
		}
	}
	return snapshotFromRecord(rec, token), nil
}

// ReplaceCredential atomically installs a validated token per §21.6.
//
// The caller (T14/T20) has already validated req.Token against the Coder
// control plane. Under the store write mutex this method: confirms the
// account exists and is enabled; enforces the identity binding (§10.4: a
// bound account only accepts its own Coder UUID; §10.5: an unbound account
// binds on first token only when bind_on_first_token is set); compares
// req.ExpectedGeneration against the current record (§21.4 CAS); seals the
// token with AAD carrying the NEW generation (§22.1 transplant protection);
// refreshes the account identity (duplicate coder_user_id rejected);
// and renames the new record into place. Any failure before the rename
// leaves the previous credential file byte-identical (§21.6: never destroy
// the old credential before the new one is proven).
//
// req.Token is wiped before return, success or failure. The returned
// snapshot carries no plaintext (Token is nil).
func (s *Store) ReplaceCredential(ctx context.Context, req core.ReplaceCredentialRequest) (core.CredentialSnapshot, error) {
	defer secretbox.BestEffortWipe(req.Token)
	if err := ctx.Err(); err != nil {
		return core.CredentialSnapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return core.CredentialSnapshot{}, err
	}
	kp, err := s.keyProviderLocked()
	if err != nil {
		return core.CredentialSnapshot{}, err
	}

	acct, err := s.getAccountLocked(req.AccountID)
	if err != nil {
		return core.CredentialSnapshot{}, err
	}
	if !acct.Enabled {
		return core.CredentialSnapshot{}, &Error{
			Code: core.AUTH_ACCOUNT_DISABLED,
			Msg:  ErrAccountDisabled.Error(),
			Err:  ErrAccountDisabled,
		}
	}
	if req.Identity.ID == uuid.Nil {
		return core.CredentialSnapshot{}, wrongIdentityErr(req.AccountID)
	}
	firstBind := acct.CoderUserID == nil
	if firstBind {
		if !acct.BindOnFirstToken {
			return core.CredentialSnapshot{}, wrongIdentityErr(req.AccountID)
		}
	} else if *acct.CoderUserID != req.Identity.ID {
		return core.CredentialSnapshot{}, wrongIdentityErr(req.AccountID)
	}

	rec, exists, err := s.loadCredentialRecordLocked(req.AccountID)
	if err != nil {
		return core.CredentialSnapshot{}, err
	}
	if exists {
		if err := validateCredentialRecord(rec); err != nil {
			return core.CredentialSnapshot{}, err
		}
	}
	if rec.Generation != req.ExpectedGeneration {
		return core.CredentialSnapshot{}, generationConflictErr(req.AccountID, req.ExpectedGeneration, rec.Generation)
	}

	newGeneration := rec.Generation + 1
	keyID, key, err := kp.ActiveKey(ctx)
	if err != nil {
		return core.CredentialSnapshot{}, cryptoKeyUnavailable("active key for credential replace", err)
	}
	nonce, ciphertext, err := secretbox.Seal(keyID, key, req.Token,
		secretbox.CredentialAAD(acct.DeploymentID, req.AccountID, newGeneration))
	if err != nil {
		return core.CredentialSnapshot{}, cryptoKeyUnavailable("seal credential", err)
	}

	// Account identity first: if this write fails the credential file is
	// untouched; if the credential write below fails, the identity refresh
	// (username cache, possibly the first bind) is harmless to retry.
	if err := s.updateAccountIdentityLocked(req.AccountID, req.Identity.ID, req.Identity.Username); err != nil {
		return core.CredentialSnapshot{}, err
	}

	now := nowMs()
	newRec := CredentialRecord{
		AccountID:         req.AccountID.String(),
		Generation:        newGeneration,
		State:             core.CredentialStateValid.String(),
		KeyVersion:        &keyID,
		Nonce:             nonce,
		Ciphertext:        ciphertext,
		LastValidatedAtMs: &now,
		UpdatedAtMs:       now,
	}
	if err := s.writeRecord(dirCredentials, req.AccountID.String()+".json", newRec); err != nil {
		return core.CredentialSnapshot{}, err
	}
	return snapshotFromRecord(newRec, nil), nil
}

// MarkCredentialInvalid records an authoritative 401 for one credential
// generation (§23.3). The compare-and-set is silent: a generation that no
// longer matches (or an account with no credential file) is a stale failure
// and returns nil without modifying anything.
func (s *Store) MarkCredentialInvalid(ctx context.Context, accountID uuid.UUID, expectedGeneration int64, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	rec, exists, err := s.loadCredentialRecordLocked(accountID)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if err := validateCredentialRecord(rec); err != nil {
		return err
	}
	if rec.Generation != expectedGeneration {
		return nil
	}
	now := nowMs()
	rec.State = core.CredentialStateInvalid.String()
	rec.InvalidatedAtMs = &now
	rec.LastErrorClass = &reason
	rec.UpdatedAtMs = now
	return s.writeRecord(dirCredentials, accountID.String()+".json", rec)
}

// ClearCredential tombstones the stored credential (§14.5): the record is
// kept with state=missing and ciphertext/nonce/key_version NULLed, and the
// generation is incremented so in-flight validations of the old credential
// cannot be confused with the next one. A stale expected generation is a
// conflict error — unlike MarkCredentialInvalid, clear is an explicit admin
// action and must not silently no-op.
func (s *Store) ClearCredential(ctx context.Context, accountID uuid.UUID, expectedGeneration int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	if _, err := s.getAccountLocked(accountID); err != nil {
		return err
	}

	rec, exists, err := s.loadCredentialRecordLocked(accountID)
	if err != nil {
		return err
	}
	if exists {
		if err := validateCredentialRecord(rec); err != nil {
			return err
		}
	}
	if rec.Generation != expectedGeneration {
		return generationConflictErr(accountID, expectedGeneration, rec.Generation)
	}
	newRec := CredentialRecord{
		AccountID:   accountID.String(),
		Generation:  rec.Generation + 1,
		State:       core.CredentialStateMissing.String(),
		UpdatedAtMs: nowMs(),
	}
	return s.writeRecord(dirCredentials, accountID.String()+".json", newRec)
}

// ReencryptAll re-seals every stored credential under the provider's ACTIVE
// key (§22.3 rotation step 4). Generation, state, and timestamps are
// preserved: only key_version, nonce, and ciphertext change, and the AAD is
// byte-identical because it carries the unchanged generation. Records
// already on the active version and tombstones (no ciphertext) are skipped.
// Each record write is atomic, so an interrupted run can simply be retried.
// The store write mutex is held for the whole pass (single-instance admin
// operation).
func (s *Store) ReencryptAll(ctx context.Context, kp secretbox.KeyProvider) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	if kp == nil {
		return cryptoKeyUnavailable("ReencryptAll requires a key provider", ErrNoKeyProvider)
	}
	activeID, activeKey, err := kp.ActiveKey(ctx)
	if err != nil {
		return cryptoKeyUnavailable("active key for re-encryption", err)
	}

	entries, err := os.ReadDir(filepath.Join(s.dir, dirCredentials))
	if err != nil {
		return storeUnavailable("scan credentials", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if err := s.reencryptOneLocked(ctx, kp, e.Name(), activeID, activeKey); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) reencryptOneLocked(ctx context.Context, kp secretbox.KeyProvider, name, activeID string, activeKey []byte) (err error) {
	var rec CredentialRecord
	if err := s.readRecord(dirCredentials, name, &rec); err != nil {
		return err
	}
	if err := validateCredentialRecord(rec); err != nil {
		return err
	}
	if len(rec.Ciphertext) == 0 || *rec.KeyVersion == activeID {
		return nil
	}
	accountID, err := uuid.Parse(rec.AccountID)
	if err != nil {
		return storeUnavailable("corrupt account id in credential "+name, ErrStoreCorrupt)
	}
	acct, err := s.getAccountLocked(accountID)
	if err != nil {
		return err
	}
	oldKey, err := kp.Key(ctx, *rec.KeyVersion)
	if err != nil {
		return cryptoKeyUnavailable("load old credential key "+*rec.KeyVersion, err)
	}
	aad := secretbox.CredentialAAD(acct.DeploymentID, accountID, rec.Generation)
	plaintext, err := secretbox.Open(*rec.KeyVersion, oldKey, rec.Nonce, rec.Ciphertext, aad)
	if err != nil {
		return &Error{
			Code: core.CRYPTO_DECRYPT_FAILED,
			Msg:  ErrCryptoDecryptFailed.Error(),
			Err:  fmt.Errorf("%w: %w", ErrCryptoDecryptFailed, err),
		}
	}
	defer secretbox.BestEffortWipe(plaintext)

	nonce, ciphertext, err := secretbox.Seal(activeID, activeKey, plaintext, aad)
	if err != nil {
		return cryptoKeyUnavailable("re-seal credential "+rec.AccountID, err)
	}
	keyID := activeID
	rec.KeyVersion = &keyID
	rec.Nonce = nonce
	rec.Ciphertext = ciphertext
	return s.writeRecord(dirCredentials, name, rec)
}
