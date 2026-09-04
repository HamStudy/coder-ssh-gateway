package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/taxilian/coder-ssh-gateway/internal/testleaks"
)

func TestLookupOrCreateAccountByCoderID(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	dep := testDeployment()
	if err := s.EnsureDeployment(dep); err != nil {
		t.Fatalf("EnsureDeployment: %v", err)
	}
	coderUserID := uuid.MustParse("77777777-7777-7777-7777-777777777777")

	t.Run("creates enabled bound account", func(t *testing.T) {
		acct, created, err := s.LookupOrCreateAccountByCoderID(context.Background(), dep.ID, coderUserID, "taxilian")
		if err != nil {
			t.Fatalf("LookupOrCreateAccountByCoderID: %v", err)
		}
		if !created {
			t.Error("created = false, want true on first call")
		}
		if acct.ID == uuid.Nil {
			t.Error("account ID is zero")
		}
		if acct.DeploymentID != dep.ID {
			t.Errorf("DeploymentID = %s, want %s", acct.DeploymentID, dep.ID)
		}
		if acct.CoderUserID == nil || *acct.CoderUserID != coderUserID {
			t.Errorf("CoderUserID = %v, want %s", acct.CoderUserID, coderUserID)
		}
		if acct.CachedUsername != "taxilian" {
			t.Errorf("CachedUsername = %q, want taxilian", acct.CachedUsername)
		}
		if acct.Label != "taxilian" {
			t.Errorf("Label = %q, want taxilian", acct.Label)
		}
		if acct.BindOnFirstToken {
			t.Error("BindOnFirstToken = true, want false (already bound)")
		}
		if !acct.Enabled {
			t.Error("Enabled = false, want true")
		}
	})

	t.Run("lookup is idempotent", func(t *testing.T) {
		first, _, err := s.LookupOrCreateAccountByCoderID(context.Background(), dep.ID, coderUserID, "taxilian")
		if err != nil {
			t.Fatalf("first call: %v", err)
		}
		second, created, err := s.LookupOrCreateAccountByCoderID(context.Background(), dep.ID, coderUserID, "taxilian")
		if err != nil {
			t.Fatalf("second call: %v", err)
		}
		if created {
			t.Error("created = true, want false on existing account")
		}
		if second.ID != first.ID {
			t.Errorf("second call returned different account ID %s, want %s", second.ID, first.ID)
		}
	})

	t.Run("refreshes cached username", func(t *testing.T) {
		acct, created, err := s.LookupOrCreateAccountByCoderID(context.Background(), dep.ID, coderUserID, "richard")
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if created {
			t.Error("created = true, want false (rename is not a new account)")
		}
		if acct.CachedUsername != "richard" {
			t.Errorf("CachedUsername = %q, want richard", acct.CachedUsername)
		}
		got, err := s.GetAccount(acct.ID)
		if err != nil {
			t.Fatalf("GetAccount: %v", err)
		}
		if got.CachedUsername != "richard" {
			t.Errorf("persisted CachedUsername = %q, want richard", got.CachedUsername)
		}
	})

	t.Run("distinct coder users get distinct accounts", func(t *testing.T) {
		other := uuid.MustParse("88888888-8888-8888-8888-888888888888")
		a, created, err := s.LookupOrCreateAccountByCoderID(context.Background(), dep.ID, other, "other")
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if !created {
			t.Error("created = false, want true for new coder user")
		}
		accts, err := s.ListAccounts()
		if err != nil {
			t.Fatalf("ListAccounts: %v", err)
		}
		if len(accts) != 2 {
			t.Errorf("ListAccounts len = %d, want 2", len(accts))
		}
		if a.Label != "other" {
			t.Errorf("Label = %q, want other", a.Label)
		}
	})

	t.Run("same coder user in another deployment is a separate account", func(t *testing.T) {
		otherDep := uuid.MustParse("99999999-9999-9999-9999-999999999999")
		a, created, err := s.LookupOrCreateAccountByCoderID(context.Background(), otherDep, coderUserID, "taxilian")
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if !created {
			t.Error("created = false, want true for other deployment")
		}
		if a.DeploymentID != otherDep {
			t.Errorf("DeploymentID = %s, want %s", a.DeploymentID, otherDep)
		}
	})

	t.Run("cancelled context fails fast", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := s.LookupOrCreateAccountByCoderID(ctx, dep.ID, uuid.New(), "x"); err == nil {
			t.Error("want error for cancelled context")
		}
	})
}

func TestKeyDigestExists(t *testing.T) {
	defer testleaks.Verify(t)
	dir := t.TempDir()
	s := openStore(t, dir)
	_, acct, key, keyRec := seedStore(t, s)

	sum := sha256.Sum256(key.Marshal())
	digestHex := hex.EncodeToString(sum[:])

	t.Run("absent digest", func(t *testing.T) {
		absent := sha256.Sum256([]byte("no such key"))
		id, exists, err := s.KeyDigestExists(hex.EncodeToString(absent[:]))
		if err != nil {
			t.Fatalf("KeyDigestExists: %v", err)
		}
		if exists {
			t.Error("exists = true, want false")
		}
		if id != uuid.Nil {
			t.Errorf("accountID = %s, want zero", id)
		}
	})

	t.Run("present digest returns owning account", func(t *testing.T) {
		id, exists, err := s.KeyDigestExists(digestHex)
		if err != nil {
			t.Fatalf("KeyDigestExists: %v", err)
		}
		if !exists {
			t.Fatal("exists = false, want true")
		}
		if id != acct.ID {
			t.Errorf("accountID = %s, want %s", id, acct.ID)
		}
		if keyRec.AccountID != acct.ID {
			t.Errorf("AddKey record AccountID = %s, want %s", keyRec.AccountID, acct.ID)
		}
	})

	t.Run("malformed digest is an error", func(t *testing.T) {
		for _, bad := range []string{"", "zz" + digestHex[2:], digestHex[:62], digestHex + "ff"} {
			if _, _, err := s.KeyDigestExists(bad); err == nil {
				t.Errorf("KeyDigestExists(%q): want error, got nil", bad)
			}
		}
	})

	t.Run("caller label and zero last_used persist", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(dir, "keys", digestHex+".json"))
		if err != nil {
			t.Fatalf("read key record: %v", err)
		}
		var rec struct {
			Label        string `json:"label"`
			LastUsedAtMs *int64 `json:"last_used_at_ms"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatalf("unmarshal key record: %v", err)
		}
		if rec.Label != "laptop key" {
			t.Errorf("label = %q, want %q (caller-supplied)", rec.Label, "laptop key")
		}
		if rec.LastUsedAtMs != nil {
			t.Errorf("last_used_at_ms = %v, want null for a fresh key", *rec.LastUsedAtMs)
		}
	})
}
