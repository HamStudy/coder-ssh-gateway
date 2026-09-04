package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/taxilian/coder-ssh-gateway/internal/core"
)

// LookupOrCreateAccountByCoderID resolves the account bound to
// (deploymentID, coderUserID). When none exists it creates an enabled
// account labeled with username, coder_user_id bound, and
// bind_on_first_token=false (self-enrollment, §10.4: the identity is already
// proven by the token that produced it). An existing account is returned
// unchanged except that a changed username refreshes cached_username.
// created reports whether the account was created by this call.
func (s *Store) LookupOrCreateAccountByCoderID(ctx context.Context, deploymentID, coderUserID uuid.UUID, username string) (acct core.Account, created bool, err error) {
	if err := ctx.Err(); err != nil {
		return core.Account{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOpen(); err != nil {
		return core.Account{}, false, err
	}

	entries, err := os.ReadDir(filepath.Join(s.dir, dirAccounts))
	if err != nil {
		return core.Account{}, false, storeUnavailable("scan accounts", err)
	}
	depStr, uidStr := deploymentID.String(), coderUserID.String()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var rec accountRecord
		if err := s.readRecord(dirAccounts, e.Name(), &rec); err != nil {
			return core.Account{}, false, err
		}
		if rec.DeploymentID != depStr || rec.CoderUserID == nil || *rec.CoderUserID != uidStr {
			continue
		}
		if rec.CachedUsername != username {
			rec.CachedUsername = username
			rec.UpdatedAtMs = nowMs()
			if err := s.writeRecord(dirAccounts, e.Name(), rec); err != nil {
				return core.Account{}, false, err
			}
		}
		a, err := rec.toCore()
		if err != nil {
			return core.Account{}, false, err
		}
		return a, false, nil
	}

	uid := coderUserID
	a := core.Account{
		ID:               uuid.New(),
		DeploymentID:     deploymentID,
		Label:            username,
		CoderUserID:      &uid,
		CachedUsername:   username,
		BindOnFirstToken: false,
		Enabled:          true,
	}
	now := nowMs()
	if err := s.writeRecord(dirAccounts, a.ID.String()+".json", accountToRecord(a, now, now)); err != nil {
		return core.Account{}, false, err
	}
	return a, true, nil
}

// KeyDigestExists reports whether a key with the given digest (lowercase hex
// sha256 of the canonical key blob, i.e. the keys/ filename stem) is linked
// to any account, returning the owning account ID when it is. Enrollment uses
// this to detect a key already linked to another account. A malformed digest
// (not exactly 64 hex chars) is an error.
func (s *Store) KeyDigestExists(digestHex string) (accountID uuid.UUID, exists bool, err error) {
	if len(digestHex) != sha256.Size*2 {
		return uuid.Nil, false, storeUnavailable(fmt.Sprintf("malformed key digest %q: want %d hex chars", digestHex, sha256.Size*2), nil)
	}
	if _, err := hex.DecodeString(digestHex); err != nil {
		return uuid.Nil, false, storeUnavailable(fmt.Sprintf("malformed key digest %q: not hex", digestHex), nil)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.checkOpen(); err != nil {
		return uuid.Nil, false, err
	}

	var rec keyRecord
	err = s.readRecord(dirKeys, digestHex+".json", &rec)
	if errors.Is(err, fs.ErrNotExist) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	id, err := uuid.Parse(rec.AccountID)
	if err != nil {
		return uuid.Nil, false, storeUnavailable("corrupt account id in key "+rec.ID, ErrStoreCorrupt)
	}
	return id, true, nil
}
