// Package store implements the flat-file state store (plan Task 11;
// supersedes design §21.1–21.2 SQLite per the user storage override).
//
// All state lives under ONE state directory:
//
//	<state-dir>/
//	  VERSION                            # "1"
//	  lock                               # flock(2) LOCK_EX|LOCK_NB, process lifetime
//	  deployments/<deployment-uuid>.json
//	  accounts/<account-uuid>.json
//	  keys/<sha256-hex-of-canonical-key-blob>.json
//	  credentials/<account-uuid>.json
//	  audit/audit-YYYY-MM-DD.jsonl       # via internal/audit (see AuditDir)
//
// Durability: every mutation is write-temp-file -> fsync(file) -> rename(2)
// -> fsync(dir). Files are mode 0600, directories 0700 (explicit chmod after
// create; umask-independent). Single instance: an flock on <state-dir>/lock is
// held for the Store lifetime; a second Open fails fast with ErrStoreLocked.
// The flock is Linux-only by design (no cross-platform lock shims). Inside the
// process a sync.RWMutex serializes all record mutations.
//
// config.yaml and secrets/ live in the same directory but are NOT managed by
// this package.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/secretbox"
)

const (
	// VersionFile is the marker checked at Open; only "1" is supported.
	VersionFile  = "VERSION"
	storeVersion = "1"

	lockFileName = "lock"
	tmpSuffix    = ".tmp"

	dirDeployments = "deployments"
	dirAccounts    = "accounts"
	dirKeys        = "keys"
	dirCredentials = "credentials"
	dirAudit       = "audit"
)

var (
	ErrStoreLocked          = errors.New("store locked by another process")
	ErrStoreCorrupt         = errors.New("store record corrupt")
	ErrVersionMismatch      = errors.New("unsupported store version")
	ErrStoreClosed          = errors.New("store is closed")
	ErrUnknownKey           = errors.New("unknown key")
	ErrCertificatesRejected = errors.New("ssh certificates are not accepted")
	ErrDuplicateKey         = errors.New("duplicate key digest")
	ErrDuplicateCoderUser   = errors.New("coder user already bound to another account in this deployment")
	ErrAccountNotFound      = errors.New("account not found")
	ErrAccountExists        = errors.New("account already exists")
	ErrAccountDisabled      = errors.New("account disabled")
	ErrKeyNotFound          = errors.New("key not found")
)

// Error is the typed store error carrying a stable core detail code.
type Error struct {
	Code string
	Msg  string
	Err  error
}

func (e *Error) Error() string { return e.Msg }
func (e *Error) Unwrap() error { return e.Err }

// CodeOf extracts the stable detail code from a store error chain, or "".
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func storeUnavailable(msg string, cause error) error {
	return &Error{Code: core.STORE_UNAVAILABLE, Msg: msg, Err: cause}
}

// unknownKeyErr is the single outward error for unknown, disabled, wrong-
// deployment, and certificate keys (§35: generic authentication failure — no
// key-existence oracle).
func unknownKeyErr(cause error) error {
	return &Error{Code: core.AUTH_UNKNOWN_KEY, Msg: ErrUnknownKey.Error(), Err: cause}
}

// Store is a flat-file state store rooted at a single directory.
type Store struct {
	dir      string
	lockFile *os.File

	mu     sync.RWMutex
	closed bool
	kp     secretbox.KeyProvider
}

// Open creates (if absent) and exclusively locks the state directory.
//
// The VERSION marker must contain "1"; anything else fails with
// ErrVersionMismatch. Stray *.tmp files from a crash between temp-write and
// rename are removed. Linux flock only.
func Open(dir string) (s *Store, err error) {
	if dir == "" {
		return nil, storeUnavailable("state directory path is empty", nil)
	}

	_, statErr := os.Stat(dir)
	created := os.IsNotExist(statErr)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, storeUnavailable("create state directory", err)
	}
	if created {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, storeUnavailable("chmod state directory", err)
		}
	}

	lockPath := filepath.Join(dir, lockFileName)
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, storeUnavailable("open lock file", err)
	}
	if err := lockFile.Chmod(0o600); err != nil {
		lockFile.Close()
		return nil, storeUnavailable("chmod lock file", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lockFile.Close()
		return nil, storeUnavailable("state directory is locked by another process: "+dir, ErrStoreLocked)
	}

	st := &Store{dir: dir, lockFile: lockFile}
	defer func() {
		if err != nil {
			syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			lockFile.Close()
		}
	}()

	if err = st.ensureVersion(); err != nil {
		return nil, err
	}
	for _, d := range []string{dirDeployments, dirAccounts, dirKeys, dirCredentials, dirAudit} {
		p := filepath.Join(dir, d)
		if err := os.MkdirAll(p, 0o700); err != nil {
			return nil, storeUnavailable("create "+d, err)
		}
		if err := os.Chmod(p, 0o700); err != nil {
			return nil, storeUnavailable("chmod "+d, err)
		}
	}
	if err = st.cleanStrayTemps(); err != nil {
		return nil, err
	}
	return st, nil
}

// Close releases the flock and closes the store. Idempotent.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	unlockErr := syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
	closeErr := s.lockFile.Close()
	return errors.Join(unlockErr, closeErr)
}

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }

// AuditDir returns the directory holding per-day audit JSONL files; construct
// the writer with audit.NewJSONLFileLogger(store.AuditDir(), fsync).
func (s *Store) AuditDir() string { return filepath.Join(s.dir, dirAudit) }

func (s *Store) checkOpen() error {
	if s.closed {
		return storeUnavailable("operation on closed store", ErrStoreClosed)
	}
	return nil
}

func (s *Store) ensureVersion() error {
	b, err := os.ReadFile(filepath.Join(s.dir, VersionFile))
	if errors.Is(err, fs.ErrNotExist) {
		if err := writeFileAtomic(s.dir, VersionFile, []byte(storeVersion+"\n")); err != nil {
			return storeUnavailable("write VERSION marker", err)
		}
		return nil
	}
	if err != nil {
		return storeUnavailable("read VERSION marker", err)
	}
	if strings.TrimSpace(string(b)) != storeVersion {
		return storeUnavailable(fmt.Sprintf("VERSION marker is %q, want %s", strings.TrimSpace(string(b)), storeVersion), ErrVersionMismatch)
	}
	return nil
}

// cleanStrayTemps removes *.tmp crash artifacts from the root and record dirs.
func (s *Store) cleanStrayTemps() error {
	dirs := []string{s.dir}
	for _, d := range []string{dirDeployments, dirAccounts, dirKeys, dirCredentials} {
		dirs = append(dirs, filepath.Join(s.dir, d))
	}
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			return storeUnavailable("scan "+d, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), tmpSuffix) {
				continue
			}
			if err := os.Remove(filepath.Join(d, e.Name())); err != nil {
				return storeUnavailable("remove stray temp "+e.Name(), err)
			}
		}
	}
	return nil
}

// writeFileAtomic writes name under dir via temp file -> fsync -> rename ->
// fsync(dir). Never mutates in place.
func writeFileAtomic(dir, name string, data []byte) (err error) {
	tmp, err := os.CreateTemp(dir, name+".*"+tmpSuffix)
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if err != nil {
			os.Remove(tmpPath)
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpPath, filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Store) recordPath(subdir, name string) string {
	return filepath.Join(s.dir, subdir, name)
}

// readRecord unmarshals a JSON record. fs.ErrNotExist propagates unwrapped so
// callers can distinguish missing from corrupt; bad JSON yields ErrStoreCorrupt.
func (s *Store) readRecord(subdir, name string, v any) error {
	b, err := os.ReadFile(s.recordPath(subdir, name))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return storeUnavailable("corrupt record "+subdir+"/"+name, ErrStoreCorrupt)
	}
	return nil
}

// writeRecord marshals v and atomically replaces the record file.
func (s *Store) writeRecord(subdir, name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(s.dir, subdir), name, append(data, '\n')); err != nil {
		return storeUnavailable("write record "+subdir+"/"+name, err)
	}
	return nil
}

func nowMs() int64 { return time.Now().UnixMilli() }

// --- deployments ------------------------------------------------------------

type deploymentRecord struct {
	ID           string `json:"id"`
	CoderURL     string `json:"coder_url"`
	CoderBinary  string `json:"coder_binary"`
	GlobalConfig string `json:"global_config"`
	WorkingDir   string `json:"working_dir"`
	Autostart    bool   `json:"autostart"`
	WaitMode     string `json:"wait_mode"`
	CreatedAtMs  int64  `json:"created_at_ms"`
	UpdatedAtMs  int64  `json:"updated_at_ms"`
}

// EnsureDeployment idempotently upserts the deployment from config: fields
// are refreshed, created_at_ms is preserved.
func (s *Store) EnsureDeployment(d core.Deployment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}

	name := d.ID.String() + ".json"
	var rec deploymentRecord
	err := s.readRecord(dirDeployments, name, &rec)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		rec = deploymentRecord{ID: d.ID.String(), CreatedAtMs: nowMs()}
	case err != nil:
		return err
	}
	if d.CoderURL != nil {
		rec.CoderURL = d.CoderURL.String()
	} else {
		rec.CoderURL = ""
	}
	rec.CoderBinary = d.CoderBinary
	rec.GlobalConfig = d.GlobalConfig
	rec.WorkingDir = d.WorkingDir
	rec.Autostart = d.Autostart
	rec.WaitMode = d.WaitMode
	rec.UpdatedAtMs = nowMs()
	return s.writeRecord(dirDeployments, name, rec)
}

// --- accounts -----------------------------------------------------------------

type accountRecord struct {
	ID               string  `json:"id"`
	DeploymentID     string  `json:"deployment_id"`
	Label            string  `json:"label"`
	CoderUserID      *string `json:"coder_user_id"`
	CachedUsername   string  `json:"cached_username"`
	BindOnFirstToken bool    `json:"bind_on_first_token"`
	Enabled          bool    `json:"enabled"`
	CreatedAtMs      int64   `json:"created_at_ms"`
	UpdatedAtMs      int64   `json:"updated_at_ms"`
}

func accountToRecord(a core.Account, created, updated int64) accountRecord {
	rec := accountRecord{
		ID:               a.ID.String(),
		DeploymentID:     a.DeploymentID.String(),
		Label:            a.Label,
		CachedUsername:   a.CachedUsername,
		BindOnFirstToken: a.BindOnFirstToken,
		Enabled:          a.Enabled,
		CreatedAtMs:      created,
		UpdatedAtMs:      updated,
	}
	if a.CoderUserID != nil {
		s := a.CoderUserID.String()
		rec.CoderUserID = &s
	}
	return rec
}

func (r accountRecord) toCore() (core.Account, error) {
	id, err := uuid.Parse(r.ID)
	if err != nil {
		return core.Account{}, storeUnavailable("corrupt account id in "+r.ID, ErrStoreCorrupt)
	}
	depID, err := uuid.Parse(r.DeploymentID)
	if err != nil {
		return core.Account{}, storeUnavailable("corrupt deployment id in account "+r.ID, ErrStoreCorrupt)
	}
	a := core.Account{
		ID:               id,
		DeploymentID:     depID,
		Label:            r.Label,
		CachedUsername:   r.CachedUsername,
		BindOnFirstToken: r.BindOnFirstToken,
		Enabled:          r.Enabled,
	}
	if r.CoderUserID != nil {
		uid, err := uuid.Parse(*r.CoderUserID)
		if err != nil {
			return core.Account{}, storeUnavailable("corrupt coder_user_id in account "+r.ID, ErrStoreCorrupt)
		}
		a.CoderUserID = &uid
	}
	return a, nil
}

// checkDuplicateCoderUserLocked enforces UNIQUE (deployment_id,
// coder_user_id) when coder_user_id is non-null; nil duplicates are allowed
// (SQL UNIQUE-with-NULL semantics). excludeID skips the account being updated.
func (s *Store) checkDuplicateCoderUserLocked(deploymentID, coderUserID, excludeID uuid.UUID) error {
	entries, err := os.ReadDir(filepath.Join(s.dir, dirAccounts))
	if err != nil {
		return storeUnavailable("scan accounts", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var rec accountRecord
		if err := s.readRecord(dirAccounts, e.Name(), &rec); err != nil {
			return err
		}
		if rec.CoderUserID == nil || rec.DeploymentID != deploymentID.String() {
			continue
		}
		uid, err := uuid.Parse(*rec.CoderUserID)
		if err != nil {
			return storeUnavailable("corrupt coder_user_id in account "+rec.ID, ErrStoreCorrupt)
		}
		if uid == coderUserID && rec.ID != excludeID.String() {
			return &Error{
				Code: core.STORE_UNAVAILABLE,
				Msg:  fmt.Sprintf("coder user %s already bound to account %s in deployment %s", coderUserID, rec.ID, deploymentID),
				Err:  ErrDuplicateCoderUser,
			}
		}
	}
	return nil
}

// AddAccount creates a new account record. Duplicate account IDs are rejected
// with ErrAccountExists; duplicate (deployment_id, coder_user_id) pairs with
// ErrDuplicateCoderUser.
func (s *Store) AddAccount(a core.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	name := a.ID.String() + ".json"
	if _, err := os.Stat(s.recordPath(dirAccounts, name)); err == nil {
		return &Error{Code: core.STORE_UNAVAILABLE, Msg: "account " + a.ID.String() + " already exists", Err: ErrAccountExists}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return storeUnavailable("stat account", err)
	}
	if a.CoderUserID != nil {
		if err := s.checkDuplicateCoderUserLocked(a.DeploymentID, *a.CoderUserID, uuid.Nil); err != nil {
			return err
		}
	}
	now := nowMs()
	return s.writeRecord(dirAccounts, name, accountToRecord(a, now, now))
}

// GetAccount loads one account by ID (ErrAccountNotFound if absent).
func (s *Store) GetAccount(id uuid.UUID) (core.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return core.Account{}, err
	}
	return s.getAccountLocked(id)
}

func (s *Store) getAccountLocked(id uuid.UUID) (core.Account, error) {
	var rec accountRecord
	err := s.readRecord(dirAccounts, id.String()+".json", &rec)
	if errors.Is(err, fs.ErrNotExist) {
		return core.Account{}, &Error{Code: core.STORE_UNAVAILABLE, Msg: "account " + id.String() + " not found", Err: ErrAccountNotFound}
	}
	if err != nil {
		return core.Account{}, err
	}
	return rec.toCore()
}

// ListAccounts returns all accounts, sorted by ID for determinism.
func (s *Store) ListAccounts() ([]core.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, dirAccounts))
	if err != nil {
		return nil, storeUnavailable("scan accounts", err)
	}
	out := make([]core.Account, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var rec accountRecord
		if err := s.readRecord(dirAccounts, e.Name(), &rec); err != nil {
			return nil, err
		}
		a, err := rec.toCore()
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out, nil
}

// SetAccountEnabled flips the enabled flag.
func (s *Store) SetAccountEnabled(id uuid.UUID, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	name := id.String() + ".json"
	var rec accountRecord
	if err := s.mustReadAccountLocked(id, name, &rec); err != nil {
		return err
	}
	rec.Enabled = enabled
	rec.UpdatedAtMs = nowMs()
	return s.writeRecord(dirAccounts, name, rec)
}

// UpdateAccountIdentity binds coder_user_id + cached_username (§10.4).
// bind_on_first_token is left untouched.
func (s *Store) UpdateAccountIdentity(id uuid.UUID, coderUserID uuid.UUID, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	return s.updateAccountIdentityLocked(id, coderUserID, username)
}

func (s *Store) updateAccountIdentityLocked(id uuid.UUID, coderUserID uuid.UUID, username string) error {
	name := id.String() + ".json"
	var rec accountRecord
	if err := s.mustReadAccountLocked(id, name, &rec); err != nil {
		return err
	}
	depID, err := uuid.Parse(rec.DeploymentID)
	if err != nil {
		return storeUnavailable("corrupt deployment id in account "+rec.ID, ErrStoreCorrupt)
	}
	if err := s.checkDuplicateCoderUserLocked(depID, coderUserID, id); err != nil {
		return err
	}
	uid := coderUserID.String()
	rec.CoderUserID = &uid
	rec.CachedUsername = username
	rec.UpdatedAtMs = nowMs()
	return s.writeRecord(dirAccounts, name, rec)
}

func (s *Store) mustReadAccountLocked(id uuid.UUID, name string, rec *accountRecord) error {
	err := s.readRecord(dirAccounts, name, rec)
	if errors.Is(err, fs.ErrNotExist) {
		return &Error{Code: core.STORE_UNAVAILABLE, Msg: "account " + id.String() + " not found", Err: ErrAccountNotFound}
	}
	return err
}

// --- ssh keys -------------------------------------------------------------------

type keyRecord struct {
	ID              string `json:"id"`
	AccountID       string `json:"account_id"`
	KeyDigestSHA256 []byte `json:"key_digest_sha256"`
	PublicKeyBlob   []byte `json:"public_key_blob"`
	Algorithm       string `json:"algorithm"`
	Fingerprint     string `json:"fingerprint"`
	Label           string `json:"label"`
	Enabled         bool   `json:"enabled"`
	CreatedAtMs     int64  `json:"created_at_ms"`
	LastUsedAtMs    *int64 `json:"last_used_at_ms"`
}

func (r keyRecord) toCore() core.SSHKeyRecord {
	rec := core.SSHKeyRecord{
		Fingerprint: r.Fingerprint,
		Algorithm:   r.Algorithm,
		Enabled:     r.Enabled,
	}
	if id, err := uuid.Parse(r.ID); err == nil {
		rec.ID = id
	}
	if acctID, err := uuid.Parse(r.AccountID); err == nil {
		rec.AccountID = acctID
	}
	return rec
}

// keyFileName is the O(1) lookup key: hex sha256 of the canonical blob (§10.2).
func keyFileName(blob []byte) string {
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:]) + ".json"
}

// AddKey stores a key for an existing account. The digest (sha256 of the
// canonical Marshal() bytes) is the filename; a duplicate digest is rejected
// with ErrDuplicateKey. Certificates are rejected (§10.3).
func (s *Store) AddKey(accountID uuid.UUID, key ssh.PublicKey, label string) (core.SSHKeyRecord, error) {
	if _, isCert := key.(*ssh.Certificate); isCert {
		return core.SSHKeyRecord{}, unknownKeyErr(ErrCertificatesRejected)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return core.SSHKeyRecord{}, err
	}
	if _, err := s.getAccountLocked(accountID); err != nil {
		return core.SSHKeyRecord{}, err
	}

	blob := key.Marshal()
	sum := sha256.Sum256(blob)
	name := keyFileName(blob)
	if _, err := os.Stat(s.recordPath(dirKeys, name)); err == nil {
		return core.SSHKeyRecord{}, &Error{Code: core.STORE_UNAVAILABLE, Msg: "key digest already registered", Err: ErrDuplicateKey}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return core.SSHKeyRecord{}, storeUnavailable("stat key", err)
	}

	rec := keyRecord{
		ID:              uuid.New().String(),
		AccountID:       accountID.String(),
		KeyDigestSHA256: sum[:],
		PublicKeyBlob:   blob,
		Algorithm:       key.Type(),
		Fingerprint:     ssh.FingerprintSHA256(key),
		Label:           label,
		Enabled:         true,
		CreatedAtMs:     nowMs(),
	}
	if err := s.writeRecord(dirKeys, name, rec); err != nil {
		return core.SSHKeyRecord{}, err
	}
	return rec.toCore(), nil
}

// ListKeysForAccount returns keys bound to an account, sorted by ID.
func (s *Store) ListKeysForAccount(accountID uuid.UUID) ([]core.SSHKeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, dirKeys))
	if err != nil {
		return nil, storeUnavailable("scan keys", err)
	}
	out := make([]core.SSHKeyRecord, 0)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var rec keyRecord
		if err := s.readRecord(dirKeys, e.Name(), &rec); err != nil {
			return nil, err
		}
		if rec.AccountID != accountID.String() {
			continue
		}
		out = append(out, rec.toCore())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out, nil
}

// findKeyByIDLocked scans the keys dir for a record ID (N is small).
func (s *Store) findKeyByIDLocked(keyID uuid.UUID) (name string, rec keyRecord, err error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, dirKeys))
	if err != nil {
		return "", keyRecord{}, storeUnavailable("scan keys", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var r keyRecord
		if err := s.readRecord(dirKeys, e.Name(), &r); err != nil {
			return "", keyRecord{}, err
		}
		if r.ID == keyID.String() {
			return e.Name(), r, nil
		}
	}
	return "", keyRecord{}, &Error{Code: core.STORE_UNAVAILABLE, Msg: "key " + keyID.String() + " not found", Err: ErrKeyNotFound}
}

// SetKeyEnabled flips the enabled flag of a stored key.
func (s *Store) SetKeyEnabled(keyID uuid.UUID, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	name, rec, err := s.findKeyByIDLocked(keyID)
	if err != nil {
		return err
	}
	rec.Enabled = enabled
	return s.writeRecord(dirKeys, name, rec)
}

// TouchKeyLastUsed stamps last_used_at_ms with the current time.
func (s *Store) TouchKeyLastUsed(keyID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return err
	}
	name, rec, err := s.findKeyByIDLocked(keyID)
	if err != nil {
		return err
	}
	now := nowMs()
	rec.LastUsedAtMs = &now
	return s.writeRecord(dirKeys, name, rec)
}

// LookupByPublicKey resolves an offered key to (account, key record).
//
// Unknown digests, disabled keys, and keys from other deployments all yield
// the SAME uniform ErrUnknownKey error (no existence oracle, §35). Disabled
// accounts yield ErrAccountDisabled (AUTH_ACCOUNT_DISABLED). Certificates are
// rejected (§10.3).
func (s *Store) LookupByPublicKey(ctx context.Context, deploymentID uuid.UUID, key ssh.PublicKey) (core.Account, core.SSHKeyRecord, error) {
	if err := ctx.Err(); err != nil {
		return core.Account{}, core.SSHKeyRecord{}, err
	}
	if _, isCert := key.(*ssh.Certificate); isCert {
		return core.Account{}, core.SSHKeyRecord{}, unknownKeyErr(ErrCertificatesRejected)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return core.Account{}, core.SSHKeyRecord{}, err
	}

	var rec keyRecord
	err := s.readRecord(dirKeys, keyFileName(key.Marshal()), &rec)
	if errors.Is(err, fs.ErrNotExist) {
		return core.Account{}, core.SSHKeyRecord{}, unknownKeyErr(ErrUnknownKey)
	}
	if err != nil {
		return core.Account{}, core.SSHKeyRecord{}, err
	}
	if !rec.Enabled {
		return core.Account{}, core.SSHKeyRecord{}, unknownKeyErr(ErrUnknownKey)
	}

	acctID, err := uuid.Parse(rec.AccountID)
	if err != nil {
		return core.Account{}, core.SSHKeyRecord{}, storeUnavailable("corrupt account id in key "+rec.ID, ErrStoreCorrupt)
	}
	acct, err := s.getAccountLocked(acctID)
	if errors.Is(err, ErrAccountNotFound) {
		return core.Account{}, core.SSHKeyRecord{}, storeUnavailable("key "+rec.ID+" references missing account "+rec.AccountID, ErrStoreCorrupt)
	}
	if err != nil {
		return core.Account{}, core.SSHKeyRecord{}, err
	}
	if acct.DeploymentID != deploymentID {
		return core.Account{}, core.SSHKeyRecord{}, unknownKeyErr(ErrUnknownKey)
	}
	if !acct.Enabled {
		return core.Account{}, core.SSHKeyRecord{}, &Error{Code: core.AUTH_ACCOUNT_DISABLED, Msg: ErrAccountDisabled.Error(), Err: ErrAccountDisabled}
	}
	return acct, rec.toCore(), nil
}

// --- credentials (record type + missing-state handling; crypto semantics are T12) ---

// CredentialRecord is the §21.2 credentials row as JSON. Nullable SQL columns
// are pointers. Encryption/decryption and generation CAS land in Task 12.
type CredentialRecord struct {
	AccountID         string  `json:"account_id"`
	Generation        int64   `json:"generation"`
	State             string  `json:"state"`
	KeyVersion        *string `json:"key_version"`
	Nonce             []byte  `json:"nonce"`
	Ciphertext        []byte  `json:"ciphertext"`
	LastValidatedAtMs *int64  `json:"last_validated_at_ms"`
	InvalidatedAtMs   *int64  `json:"invalidated_at_ms"`
	LastErrorClass    *string `json:"last_error_class"`
	UpdatedAtMs       int64   `json:"updated_at_ms"`
}

// LoadCredentialRecord returns the stored credential record, or a synthesized
// record with state "missing" when no file exists yet (§21.3: missing is a
// state, not an error).
func (s *Store) LoadCredentialRecord(accountID uuid.UUID) (CredentialRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return CredentialRecord{}, err
	}
	rec, _, err := s.loadCredentialRecordLocked(accountID)
	return rec, err
}
