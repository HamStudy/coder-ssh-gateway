package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
	"github.com/taxilian/coder-ssh-gateway/internal/store"
	"github.com/taxilian/coder-ssh-gateway/internal/testleaks"
)

// --- helpers ---------------------------------------------------------------

func testDeployment() core.Deployment {
	u, err := url.Parse("https://example.test")
	if err != nil {
		panic(err)
	}
	return core.Deployment{
		ID:           uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		CoderURL:     u,
		TargetSuffix: "coder-gateway.example.com",
		CoderBinary:  "/usr/local/bin/coder",
		GlobalConfig: "/tmp/coder-global",
		WorkingDir:   "/tmp",
		Autostart:    true,
		WaitMode:     "auto",
	}
}

func testAccount(depID uuid.UUID) core.Account {
	return core.Account{
		ID:               uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		DeploymentID:     depID,
		Label:            "richard laptop",
		CoderUserID:      nil,
		CachedUsername:   "",
		BindOnFirstToken: true,
		Enabled:          true,
	}
}

func mustKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return k
}

// mustAuthorizedKey parses the same wire format a client would offer, so two
// parses of the same text produce independently-marshaled canonical blobs.
func mustAuthorizedKey(t *testing.T, authorized string) ssh.PublicKey {
	t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	return k
}

func keyHexFilename(k ssh.PublicKey) string {
	sum := sha256.Sum256(k.Marshal())
	return hex.EncodeToString(sum[:]) + ".json"
}

func openStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("Open(%q): %v", dir, err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func seedStore(t *testing.T, s *store.Store) (core.Deployment, core.Account, ssh.PublicKey, core.SSHKeyRecord) {
	t.Helper()
	dep := testDeployment()
	if err := s.EnsureDeployment(dep); err != nil {
		t.Fatalf("EnsureDeployment: %v", err)
	}
	acct := testAccount(dep.ID)
	if err := s.AddAccount(acct); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	key := mustKey(t)
	rec, err := s.AddKey(acct.ID, key, "laptop key")
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	return dep, acct, key, rec
}

// treeListing walks dir and returns a sorted list of relative paths, dirs
// suffixed with "/".
func treeListing(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			rel += "/"
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	sort.Strings(out)
	return out
}

// --- layout -----------------------------------------------------------------

func TestLayoutAfterOpenAndSeed(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep, acct, key, _ := seedStore(t, s)

	got := treeListing(t, dir)
	want := []string{
		"VERSION",
		"accounts/",
		"accounts/" + acct.ID.String() + ".json",
		"audit/",
		"credentials/",
		"deployments/",
		"deployments/" + dep.ID.String() + ".json",
		"keys/",
		"keys/" + keyHexFilename(key),
		"lock",
	}
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("layout mismatch\ngot:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// VERSION marker content
	b, err := os.ReadFile(filepath.Join(dir, "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	if strings.TrimSpace(string(b)) != "1" {
		t.Errorf("VERSION content = %q, want \"1\"", string(b))
	}
}

func TestPermissions(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep, acct, key, _ := seedStore(t, s)

	files := []string{
		"VERSION",
		"lock",
		"accounts/" + acct.ID.String() + ".json",
		"deployments/" + dep.ID.String() + ".json",
		"keys/" + keyHexFilename(key),
	}
	for _, f := range files {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if got := st.Mode().Perm(); got != 0o600 {
			t.Errorf("file %s mode = %o, want 600", f, got)
		}
	}
	dirs := []string{"accounts", "audit", "credentials", "deployments", "keys"}
	for _, d := range dirs {
		st, err := os.Stat(filepath.Join(dir, d))
		if err != nil {
			t.Fatalf("stat %s: %v", d, err)
		}
		if got := st.Mode().Perm(); got != 0o700 {
			t.Errorf("dir %s mode = %o, want 700", d, got)
		}
	}
}

// --- VERSION enforcement -----------------------------------------------------

func TestVersionMismatchRejected(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := store.Open(dir)
	if err == nil {
		t.Fatal("Open with VERSION=2 succeeded, want error")
	}
	if !errors.Is(err, store.ErrVersionMismatch) {
		t.Errorf("errors.Is(ErrVersionMismatch) = false for %v", err)
	}
	if got := store.CodeOf(err); got != core.STORE_UNAVAILABLE {
		t.Errorf("CodeOf = %q, want %q", got, core.STORE_UNAVAILABLE)
	}
}

func TestVersionAcceptedOnReopen(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s1, err := store.Open(dir)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	openStore(t, dir) // must not fail on existing VERSION=1
}

// --- single-instance lock ----------------------------------------------------

func TestSecondOpenFailsFast(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)

	_, err := store.Open(dir)
	if err == nil {
		t.Fatal("second Open succeeded while lock held")
	}
	if !errors.Is(err, store.ErrStoreLocked) {
		t.Errorf("errors.Is(ErrStoreLocked) = false for %v", err)
	}
	if got := store.CodeOf(err); got != core.STORE_UNAVAILABLE {
		t.Errorf("CodeOf = %q, want %q", got, core.STORE_UNAVAILABLE)
	}

	// After close the lock is released and Open succeeds again.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	openStore(t, dir)
}

// --- atomic-write crash simulation -------------------------------------------

// Simulates a crash between temp-write and rename: a stray *.tmp artifact sits
// next to the intact original record. Reopen must clean the stray file and
// leave the original record readable and byte-identical.
func TestCrashBetweenTempWriteAndRename(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()

	var origAccountJSON []byte
	var acctID uuid.UUID
	{
		s, err := store.Open(dir)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		dep := testDeployment()
		if err := s.EnsureDeployment(dep); err != nil {
			t.Fatalf("EnsureDeployment: %v", err)
		}
		acct := testAccount(dep.ID)
		acctID = acct.ID
		if err := s.AddAccount(acct); err != nil {
			t.Fatalf("AddAccount: %v", err)
		}
		var err2 error
		origAccountJSON, err2 = os.ReadFile(filepath.Join(dir, "accounts", acct.ID.String()+".json"))
		if err2 != nil {
			t.Fatalf("read account json: %v", err2)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	// Crash artifacts: partial temp files in two record dirs.
	stray1 := filepath.Join(dir, "accounts", acctID.String()+".json.12345.tmp")
	stray2 := filepath.Join(dir, "keys", "deadbeef.67890.tmp")
	if err := os.WriteFile(stray1, []byte(`{"id": "partial`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stray2, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := openStore(t, dir)

	if _, err := os.Stat(stray1); !os.IsNotExist(err) {
		t.Errorf("stray tmp %s not cleaned on Open (stat err=%v)", stray1, err)
	}
	if _, err := os.Stat(stray2); !os.IsNotExist(err) {
		t.Errorf("stray tmp %s not cleaned on Open (stat err=%v)", stray2, err)
	}

	got, err := s.GetAccount(acctID)
	if err != nil {
		t.Fatalf("GetAccount after crash: %v", err)
	}
	if got.Label != "richard laptop" {
		t.Errorf("account label = %q, want %q", got.Label, "richard laptop")
	}

	after, err := os.ReadFile(filepath.Join(dir, "accounts", acctID.String()+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(origAccountJSON) {
		t.Errorf("account record changed across crash reopen\ngot:  %s\nwant: %s", after, origAccountJSON)
	}
}

// --- corrupt records ----------------------------------------------------------

func TestCorruptAccountRecord(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	_, acct, _, _ := seedStore(t, s)

	p := filepath.Join(dir, "accounts", acct.ID.String()+".json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, fn := range map[string]func() error{
		"GetAccount":   func() error { _, err := s.GetAccount(acct.ID); return err },
		"ListAccounts": func() error { _, err := s.ListAccounts(); return err },
	} {
		err := fn()
		if err == nil {
			t.Fatalf("%s on corrupt record succeeded", name)
		}
		if !errors.Is(err, store.ErrStoreCorrupt) {
			t.Errorf("%s: errors.Is(ErrStoreCorrupt) = false for %v", name, err)
		}
		if got := store.CodeOf(err); got != core.STORE_UNAVAILABLE {
			t.Errorf("%s: CodeOf = %q, want %q", name, got, core.STORE_UNAVAILABLE)
		}
	}
}

// --- deployments --------------------------------------------------------------

func TestEnsureDeploymentIdempotentUpsert(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep := testDeployment()

	if err := s.EnsureDeployment(dep); err != nil {
		t.Fatalf("first EnsureDeployment: %v", err)
	}
	first := readDeploymentFile(t, dir, dep.ID)

	dep.WaitMode = "yes"
	dep.CoderBinary = "/usr/bin/coder"
	if err := s.EnsureDeployment(dep); err != nil {
		t.Fatalf("second EnsureDeployment: %v", err)
	}
	second := readDeploymentFile(t, dir, dep.ID)

	if first["created_at_ms"] != second["created_at_ms"] {
		t.Errorf("created_at_ms changed across upsert: %v -> %v", first["created_at_ms"], second["created_at_ms"])
	}
	if second["wait_mode"] != "yes" {
		t.Errorf("wait_mode = %v, want yes", second["wait_mode"])
	}
	if second["coder_binary"] != "/usr/bin/coder" {
		t.Errorf("coder_binary = %v", second["coder_binary"])
	}
	if second["coder_url"] != "https://example.test" {
		t.Errorf("coder_url = %v", second["coder_url"])
	}

	entries, err := os.ReadDir(filepath.Join(dir, "deployments"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("deployments dir has %d entries, want 1", len(entries))
	}
}

func readDeploymentFile(t *testing.T, dir string, id uuid.UUID) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "deployments", id.String()+".json"))
	if err != nil {
		t.Fatalf("read deployment: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal deployment: %v", err)
	}
	return m
}

// --- accounts -----------------------------------------------------------------

func TestAccountCRUD(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep := testDeployment()
	if err := s.EnsureDeployment(dep); err != nil {
		t.Fatal(err)
	}

	acct := testAccount(dep.ID)
	if err := s.AddAccount(acct); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}

	got, err := s.GetAccount(acct.ID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if got != acct {
		t.Errorf("GetAccount = %+v, want %+v", got, acct)
	}

	// Duplicate ID rejected.
	if err := s.AddAccount(acct); !errors.Is(err, store.ErrAccountExists) {
		t.Errorf("duplicate AddAccount err = %v, want ErrAccountExists", err)
	}

	// Disable / enable round trip.
	if err := s.SetAccountEnabled(acct.ID, false); err != nil {
		t.Fatalf("SetAccountEnabled(false): %v", err)
	}
	got, err = s.GetAccount(acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled {
		t.Error("account still enabled after SetAccountEnabled(false)")
	}
	if err := s.SetAccountEnabled(acct.ID, true); err != nil {
		t.Fatal(err)
	}

	// Identity binding.
	uid := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	if err := s.UpdateAccountIdentity(acct.ID, uid, "taxilian"); err != nil {
		t.Fatalf("UpdateAccountIdentity: %v", err)
	}
	got, err = s.GetAccount(acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CoderUserID == nil || *got.CoderUserID != uid {
		t.Errorf("CoderUserID = %v, want %v", got.CoderUserID, uid)
	}
	if got.CachedUsername != "taxilian" {
		t.Errorf("CachedUsername = %q", got.CachedUsername)
	}

	list, err := s.ListAccounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != acct.ID {
		t.Errorf("ListAccounts = %+v", list)
	}

	// Missing account.
	_, err = s.GetAccount(uuid.New())
	if !errors.Is(err, store.ErrAccountNotFound) {
		t.Errorf("GetAccount(missing) err = %v, want ErrAccountNotFound", err)
	}
}

func TestDuplicateCoderUserRejected(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep := testDeployment()
	if err := s.EnsureDeployment(dep); err != nil {
		t.Fatal(err)
	}
	otherDep := testDeployment()
	otherDep.ID = uuid.MustParse("99999999-9999-9999-9999-999999999999")
	if err := s.EnsureDeployment(otherDep); err != nil {
		t.Fatal(err)
	}

	uid := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	a1 := testAccount(dep.ID)
	a1.CoderUserID = &uid
	if err := s.AddAccount(a1); err != nil {
		t.Fatalf("AddAccount a1: %v", err)
	}

	// Same deployment + same coder_user_id -> rejected.
	a2 := testAccount(dep.ID)
	a2.ID = uuid.New()
	a2.CoderUserID = &uid
	if err := s.AddAccount(a2); !errors.Is(err, store.ErrDuplicateCoderUser) {
		t.Errorf("AddAccount dup err = %v, want ErrDuplicateCoderUser", err)
	}

	// Different deployment + same coder_user_id -> allowed (unique per deployment).
	a3 := testAccount(otherDep.ID)
	a3.ID = uuid.New()
	a3.CoderUserID = &uid
	if err := s.AddAccount(a3); err != nil {
		t.Errorf("AddAccount other deployment: %v", err)
	}

	// NULL coder_user_id duplicates allowed (SQL UNIQUE-with-NULL semantics).
	a4 := testAccount(dep.ID)
	a4.ID = uuid.New()
	if err := s.AddAccount(a4); err != nil {
		t.Errorf("AddAccount second unbound: %v", err)
	}

	// Binding a second account in the same deployment to the same user -> rejected.
	if err := s.UpdateAccountIdentity(a4.ID, uid, "taxilian"); !errors.Is(err, store.ErrDuplicateCoderUser) {
		t.Errorf("UpdateAccountIdentity dup err = %v, want ErrDuplicateCoderUser", err)
	}
	// Re-binding the same account to its own identity is fine (a1).
	if err := s.UpdateAccountIdentity(a1.ID, uid, "taxilian"); err != nil {
		t.Errorf("UpdateAccountIdentity self rebind: %v", err)
	}
}

// --- keys ----------------------------------------------------------------------

func TestKeyRecords(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep, acct, key, rec := seedStore(t, s)

	if !rec.Enabled {
		t.Error("new key record not enabled")
	}
	if rec.Algorithm != ssh.KeyAlgoED25519 {
		t.Errorf("algorithm = %q, want %q", rec.Algorithm, ssh.KeyAlgoED25519)
	}
	if !strings.HasPrefix(rec.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q, want SHA256: prefix", rec.Fingerprint)
	}
	if rec.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Errorf("fingerprint = %q, want %q", rec.Fingerprint, ssh.FingerprintSHA256(key))
	}

	// Record JSON carries digest/blob/timestamps per §21.2 + §10.2.
	b, err := os.ReadFile(filepath.Join(dir, "keys", keyHexFilename(key)))
	if err != nil {
		t.Fatalf("read key record: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(key.Marshal())
	if m["key_digest_sha256"] != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Errorf("key_digest_sha256 = %v", m["key_digest_sha256"])
	}
	if m["public_key_blob"] != base64.StdEncoding.EncodeToString(key.Marshal()) {
		t.Errorf("public_key_blob mismatch")
	}
	if m["label"] != "laptop key" {
		t.Errorf("label = %v", m["label"])
	}
	if _, ok := m["created_at_ms"].(float64); !ok {
		t.Errorf("created_at_ms missing/not numeric: %v", m["created_at_ms"])
	}
	if v, present := m["last_used_at_ms"]; present && v != nil {
		t.Errorf("last_used_at_ms = %v, want null for fresh key", v)
	}

	// Duplicate digest -> typed error, even for a different account.
	other := testAccount(dep.ID)
	other.ID = uuid.New()
	if err := s.AddAccount(other); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddKey(other.ID, key, "again"); !errors.Is(err, store.ErrDuplicateKey) {
		t.Errorf("duplicate AddKey err = %v, want ErrDuplicateKey", err)
	}

	// Key for missing account.
	if _, err := s.AddKey(uuid.New(), mustKey(t), "orphan"); !errors.Is(err, store.ErrAccountNotFound) {
		t.Errorf("AddKey orphan err = %v, want ErrAccountNotFound", err)
	}

	keys, err := s.ListKeysForAccount(acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != rec.ID {
		t.Errorf("ListKeysForAccount = %+v", keys)
	}

	// Disable + last-used.
	if err := s.SetKeyEnabled(rec.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchKeyLastUsed(rec.ID); err != nil {
		t.Fatal(err)
	}
	keys, err = s.ListKeysForAccount(acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].Enabled {
		t.Error("key still enabled after SetKeyEnabled(false)")
	}
	b, err = os.ReadFile(filepath.Join(dir, "keys", keyHexFilename(key)))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["last_used_at_ms"].(float64); !ok {
		t.Errorf("last_used_at_ms not set after TouchKeyLastUsed: %v", m["last_used_at_ms"])
	}
}

// TestCanonicalMarshalingSameDigest: two independent parses of the same
// authorized_keys line must marshal to the same canonical blob → same digest
// → single store record (§38.1).
func TestCanonicalMarshalingSameDigest(t *testing.T) {
	defer testleaks.Verify(t)
	k1 := mustKey(t)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k1)))
	k2 := mustAuthorizedKey(t, line)
	k3 := mustAuthorizedKey(t, line)

	if keyHexFilename(k1) != keyHexFilename(k2) || keyHexFilename(k2) != keyHexFilename(k3) {
		t.Fatal("same key parsed twice produced different digests")
	}

	dir := t.TempDir()
	s := openStore(t, dir)
	dep, acct, _, _ := seedStore(t, s)
	if _, err := s.AddKey(acct.ID, k2, "parsed once"); err != nil {
		t.Fatalf("AddKey k2: %v", err)
	}
	// k3 is byte-identical after canonical marshal -> duplicate digest.
	if _, err := s.AddKey(acct.ID, k3, "parsed twice"); !errors.Is(err, store.ErrDuplicateKey) {
		t.Errorf("AddKey k3 err = %v, want ErrDuplicateKey", err)
	}
	_ = dep
}

// --- key lookup (§38.1) --------------------------------------------------------

func TestLookupByPublicKey(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep, acct, key, rec := seedStore(t, s)
	ctx := context.Background()

	gotAcct, gotKey, err := s.LookupByPublicKey(ctx, dep.ID, key)
	if err != nil {
		t.Fatalf("LookupByPublicKey: %v", err)
	}
	if gotAcct.ID != acct.ID || gotKey.ID != rec.ID {
		t.Errorf("lookup returned acct=%v key=%v", gotAcct.ID, gotKey.ID)
	}

	// Unknown key -> uniform ErrUnknownKey carrying AUTH_UNKNOWN_KEY.
	unknown := mustKey(t)
	_, _, errUnknown := s.LookupByPublicKey(ctx, dep.ID, unknown)
	if !errors.Is(errUnknown, store.ErrUnknownKey) {
		t.Fatalf("unknown key err = %v, want ErrUnknownKey", errUnknown)
	}
	if got := store.CodeOf(errUnknown); got != core.AUTH_UNKNOWN_KEY {
		t.Errorf("unknown key CodeOf = %q, want %q", got, core.AUTH_UNKNOWN_KEY)
	}

	// Disabled key -> identical outward error (uniform, no existence oracle).
	if err := s.SetKeyEnabled(rec.ID, false); err != nil {
		t.Fatal(err)
	}
	_, _, errDisabled := s.LookupByPublicKey(ctx, dep.ID, key)
	if !errors.Is(errDisabled, store.ErrUnknownKey) {
		t.Fatalf("disabled key err = %v, want ErrUnknownKey (uniform)", errDisabled)
	}
	if errDisabled.Error() != errUnknown.Error() {
		t.Errorf("disabled key error %q differs from unknown key error %q", errDisabled, errUnknown)
	}
	if got := store.CodeOf(errDisabled); got != core.AUTH_UNKNOWN_KEY {
		t.Errorf("disabled key CodeOf = %q", got)
	}
	if err := s.SetKeyEnabled(rec.ID, true); err != nil {
		t.Fatal(err)
	}

	// Disabled account -> AUTH_ACCOUNT_DISABLED.
	if err := s.SetAccountEnabled(acct.ID, false); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.LookupByPublicKey(ctx, dep.ID, key)
	if !errors.Is(err, store.ErrAccountDisabled) {
		t.Fatalf("disabled account err = %v, want ErrAccountDisabled", err)
	}
	if got := store.CodeOf(err); got != core.AUTH_ACCOUNT_DISABLED {
		t.Errorf("disabled account CodeOf = %q, want %q", got, core.AUTH_ACCOUNT_DISABLED)
	}
	if err := s.SetAccountEnabled(acct.ID, true); err != nil {
		t.Fatal(err)
	}

	// Key offered against the wrong deployment -> uniform unknown.
	_, _, err = s.LookupByPublicKey(ctx, uuid.New(), key)
	if !errors.Is(err, store.ErrUnknownKey) {
		t.Errorf("wrong deployment err = %v, want ErrUnknownKey", err)
	}

	// Certificates rejected (§10.3).
	cert := &ssh.Certificate{Key: key}
	_, _, err = s.LookupByPublicKey(ctx, dep.ID, cert)
	if !errors.Is(err, store.ErrCertificatesRejected) {
		t.Errorf("certificate err = %v, want ErrCertificatesRejected", err)
	}
	if got := store.CodeOf(err); got != core.AUTH_UNKNOWN_KEY {
		t.Errorf("certificate CodeOf = %q, want %q", got, core.AUTH_UNKNOWN_KEY)
	}
}

// --- concurrency -----------------------------------------------------------------

func TestConcurrentLookupsAndMutations(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir)
	dep, acct, key, rec := seedStore(t, s)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if _, _, err := s.LookupByPublicKey(ctx, dep.ID, key); err != nil {
					errs <- err
					return
				}
				if _, err := s.ListAccounts(); err != nil {
					errs <- err
					return
				}
				if _, err := s.ListKeysForAccount(acct.ID); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 25; j++ {
			if err := s.TouchKeyLastUsed(rec.ID); err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent op: %v", err)
	}
}

// --- credential record (missing-state handling; encryption is T12) ----------------

func TestCredentialRecordMissingState(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	_, acct, _, _ := seedStore(t, s)

	// No file on disk -> synthesized missing record, not an error (§21.3).
	rec, err := s.LoadCredentialRecord(acct.ID)
	if err != nil {
		t.Fatalf("LoadCredentialRecord: %v", err)
	}
	if rec.State != string(core.CredentialStateMissing) {
		t.Errorf("State = %q, want %q", rec.State, core.CredentialStateMissing)
	}
	if rec.Generation != 0 {
		t.Errorf("Generation = %d, want 0", rec.Generation)
	}
	if rec.AccountID != acct.ID.String() {
		t.Errorf("AccountID = %q, want %q", rec.AccountID, acct.ID)
	}
	if len(rec.Ciphertext) != 0 || len(rec.Nonce) != 0 {
		t.Error("missing credential record carries nonce/ciphertext")
	}

	// Corrupt credential file -> typed corruption, never panic.
	p := filepath.Join(dir, "credentials", acct.ID.String()+".json")
	if err := os.WriteFile(p, []byte("~~~"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = s.LoadCredentialRecord(acct.ID)
	if !errors.Is(err, store.ErrStoreCorrupt) {
		t.Errorf("corrupt credential err = %v, want ErrStoreCorrupt", err)
	}
}

// --- audit wiring -------------------------------------------------------------------

func TestAuditDir(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	want := filepath.Join(dir, "audit")
	if got := s.AuditDir(); got != want {
		t.Errorf("AuditDir = %q, want %q", got, want)
	}
	st, err := os.Stat(want)
	if err != nil || !st.IsDir() {
		t.Errorf("audit dir missing: %v", err)
	}
}
