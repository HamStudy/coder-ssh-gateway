package keymgmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/goleak"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
	"github.com/HamStudy/coder-ssh-gateway/internal/store"
)

// The real store must satisfy the narrow interface (compile-time contract;
// kept in tests so the package never imports internal/store in production
// code, mirroring the sshauth KeyLookupStore pattern).
var _ Store = (*store.Store)(nil)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

var (
	deploymentID     = uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	accountID        = uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	sessionKeyID     = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	otherKeyID       = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	foreignAccountID = uuid.MustParse("33333333-3333-4333-8333-333333333333")
)

const (
	connID   = "conn-test-1"
	peerAddr = "203.0.113.7:51423"
)

var (
	fpSession = "SHA256:" + strings.Repeat("A", 43)
	fpOther   = "SHA256:" + strings.Repeat("B", 43)
	fpForeign = "SHA256:" + strings.Repeat("C", 43)
)

const createdSessionMs = int64(1756684800000) // 2025-09-01 UTC
const createdOtherMs = int64(1755216000000)   // 2025-08-15 UTC

func fixtureAccount() core.Account {
	return core.Account{
		ID:             accountID,
		DeploymentID:   deploymentID,
		CachedUsername: "alicia",
		Enabled:        true,
	}
}

// fixtureKeys is pre-sorted by ID, matching the store's ListKeysForAccount
// ordering. The foreign key belongs to another account and must never be
// listed or callable.
func fixtureKeys() []core.SSHKeyRecord {
	return []core.SSHKeyRecord{
		{
			ID:          sessionKeyID,
			AccountID:   accountID,
			Fingerprint: fpSession,
			Algorithm:   "ssh-ed25519",
			Label:       "laptop",
			Enabled:     true,
			CreatedAtMs: createdSessionMs,
		},
		{
			ID:          otherKeyID,
			AccountID:   accountID,
			Fingerprint: fpOther,
			Algorithm:   "rsa-sha2-256",
			Label:       "old phone",
			Enabled:     false,
			CreatedAtMs: createdOtherMs,
		},
		{
			ID:          uuid.MustParse("44444444-4444-4444-8444-444444444444"),
			AccountID:   foreignAccountID,
			Fingerprint: fpForeign,
			Algorithm:   "ssh-ed25519",
			Label:       "not yours",
			Enabled:     true,
			CreatedAtMs: createdSessionMs,
		},
	}
}

// ---------------------------------------------------------------------------
// Spy store
// ---------------------------------------------------------------------------

type deleteCall struct {
	accountID uuid.UUID
	keyID     uuid.UUID
}

// spyStore implements Store, records every mutation call, and applies
// successful deletions so re-listings shrink like the real store.
type spyStore struct {
	keys         []core.SSHKeyRecord
	listErr      error
	deleteKeyErr error
	deleteAccErr error

	deleteKeyCalls []deleteCall
	deleteAccCalls []uuid.UUID
}

func newSpyStore(keys []core.SSHKeyRecord) *spyStore {
	return &spyStore{keys: keys}
}

func (s *spyStore) ListKeysForAccount(accountID uuid.UUID) ([]core.SSHKeyRecord, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := make([]core.SSHKeyRecord, 0, len(s.keys))
	for _, k := range s.keys {
		if k.AccountID == accountID {
			out = append(out, k)
		}
	}
	return out, nil
}

func (s *spyStore) DeleteKey(accountID, keyID uuid.UUID) error {
	s.deleteKeyCalls = append(s.deleteKeyCalls, deleteCall{accountID: accountID, keyID: keyID})
	if s.deleteKeyErr != nil {
		return s.deleteKeyErr
	}
	kept := make([]core.SSHKeyRecord, 0, len(s.keys))
	for _, k := range s.keys {
		if k.ID != keyID {
			kept = append(kept, k)
		}
	}
	s.keys = kept
	return nil
}

func (s *spyStore) DeleteAccount(accountID uuid.UUID) error {
	s.deleteAccCalls = append(s.deleteAccCalls, accountID)
	if s.deleteAccErr != nil {
		return s.deleteAccErr
	}
	s.keys = nil
	return nil
}

// ---------------------------------------------------------------------------
// Golden-transcript harness
// ---------------------------------------------------------------------------

type wantEvent struct {
	eventType  string
	result     string
	detailCode string
	sshKeyID   uuid.UUID // zero means the event must not carry a key ID
}

type goldenCase struct {
	name           string
	pty            bool
	account        core.Account
	sessionKeyID   uuid.UUID
	enrollmentUser string
	store          *spyStore
	input          string
	want           string
	wantDeleteKey  []deleteCall
	wantDeleteAcc  int
	wantEvents     []wantEvent
}

const (
	headerAlicia = "Coder SSH Gateway -- key management for alicia\r\n"
	menuLine     = "Enter a key number to remove it, d to delete your account, r to refresh, q to quit:"
	byeLine      = "Bye.\r\n"

	invalidLine            = "Invalid input.\r\n"
	cancelledLine          = "Cancelled.\r\n"
	guardLine              = "This key authenticates your current session and cannot be removed.\r\n"
	removalFailedLine      = "Removal failed. The key was not changed; try again or contact your administrator.\r\n"
	accountDeletedLine     = "Account deleted. Reconnect with login@ to enroll again.\r\n"
	accountDeleteFailedLin = "Account deletion failed. Your account was not changed; try again or contact your administrator.\r\n"
	listFailedLine         = "Failed to load keys. Try again or contact your administrator.\r\n"
	noKeysLine             = "No keys enrolled.\r\n"
	deletePrompt           = "Type DELETE to permanently delete your account, anything else to cancel:\r\n"
)

var (
	listLineSession = "1 " + fpSession + " ssh-ed25519 \"laptop\" added 2025-09-01\r\n"
	listLineOther   = "2 " + fpOther + " rsa-sha2-256 [disabled] \"old phone\" added 2025-08-15\r\n"
	listingBoth     = listLineSession + listLineOther
	listingOne      = listLineSession
)

func home(listing string) string {
	return "\r\n" + listing + "\r\n" + menuLine + "\r\n"
}

func confirmBlock(n int, fp, alg, label string) string {
	return fmt.Sprintf("You selected key %d: %s %s \"%s\"\r\n", n, fp, alg, label) +
		fmt.Sprintf("Type %d again to permanently remove it, anything else to cancel:\r\n", n)
}

func consequences(n int, user string) string {
	return fmt.Sprintf("This will permanently delete your account: %d key(s) and your stored Coder token will be removed. You can re-enroll any time with %s@ and a fresh Coder token.\r\n", n, user)
}

func runGolden(t *testing.T, tc goldenCase) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	auditLog := audit.NewInMemoryLogger()
	svc := &Service{
		Store:          tc.store,
		Audit:          auditLog,
		Log:            logger,
		SessionKeyID:   tc.sessionKeyID,
		Account:        tc.account,
		EnrollmentUser: tc.enrollmentUser,
		PeerAddress:    peerAddr,
		ConnectionID:   connID,
	}
	if tc.pty {
		svc.WithPty(true)
	}

	var out bytes.Buffer
	if err := svc.Run(strings.NewReader(tc.input), &out); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if got := out.String(); got != tc.want {
		t.Errorf("transcript mismatch:\n--- want ---\n%q\n--- got ----\n%q", tc.want, got)
	}

	if len(tc.store.deleteKeyCalls) != len(tc.wantDeleteKey) {
		t.Errorf("DeleteKey calls = %v, want %v", tc.store.deleteKeyCalls, tc.wantDeleteKey)
	} else {
		for i, want := range tc.wantDeleteKey {
			if got := tc.store.deleteKeyCalls[i]; got != want {
				t.Errorf("DeleteKey call %d = %+v, want %+v", i, got, want)
			}
		}
	}
	if len(tc.store.deleteAccCalls) != tc.wantDeleteAcc {
		t.Errorf("DeleteAccount calls = %v, want %d calls", tc.store.deleteAccCalls, tc.wantDeleteAcc)
	}

	// Every mutation must be scoped to the session's own account.
	for _, c := range tc.store.deleteKeyCalls {
		if c.accountID != tc.account.ID {
			t.Errorf("DeleteKey called with accountID %s, want session account %s", c.accountID, tc.account.ID)
		}
	}
	for _, a := range tc.store.deleteAccCalls {
		if a != tc.account.ID {
			t.Errorf("DeleteAccount called with %s, want session account %s", a, tc.account.ID)
		}
	}

	events := auditLog.Events()
	if len(events) != len(tc.wantEvents) {
		t.Fatalf("audit events = %d, want %d: %+v", len(events), len(tc.wantEvents), events)
	}
	for i, want := range tc.wantEvents {
		got := events[i]
		if got.EventType != want.eventType || got.Result != want.result || got.DetailCode != want.detailCode {
			t.Errorf("event %d = (%s,%s,%s), want (%s,%s,%s)", i,
				got.EventType, got.Result, got.DetailCode, want.eventType, want.result, want.detailCode)
		}
		wantKey := ""
		if want.sshKeyID != uuid.Nil {
			wantKey = want.sshKeyID.String()
		}
		if got.SSHKeyID != wantKey {
			t.Errorf("event %d SSHKeyID = %q, want %q", i, got.SSHKeyID, wantKey)
		}
		if got.AccountID != tc.account.ID.String() {
			t.Errorf("event %d AccountID = %q, want %q", i, got.AccountID, tc.account.ID.String())
		}
		if got.ConnectionID != connID || got.PeerAddress != peerAddr {
			t.Errorf("event %d ConnectionID/PeerAddress = %q/%q, want %q/%q", i,
				got.ConnectionID, got.PeerAddress, connID, peerAddr)
		}
		if got.DeploymentID != tc.account.DeploymentID.String() {
			t.Errorf("event %d DeploymentID = %q, want %q", i, got.DeploymentID, tc.account.DeploymentID.String())
		}
		if got.ID == "" || got.OccurredAtMs == 0 {
			t.Errorf("event %d missing ID or timestamp: %+v", i, got)
		}
	}
}

func TestRunGoldenTranscript(t *testing.T) {
	confirmOther := confirmBlock(2, fpOther, "rsa-sha2-256", "old phone")

	tests := []goldenCase{
		{
			name:         "multi-key listing with disabled marker, then quit",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "q\n",
			want:         headerAlicia + home(listingBoth) + byeLine,
		},
		{
			name:         "CRLF terminated input tolerated",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "q\r\n",
			want:         headerAlicia + home(listingBoth) + byeLine,
		},
		{
			name:         "remove happy path re-lists after removal",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "2\n2\nq\n",
			want: headerAlicia + home(listingBoth) + confirmOther +
				"Key 2 removed.\r\n" + home(listingOne) + byeLine,
			wantDeleteKey: []deleteCall{{accountID: accountID, keyID: otherKeyID}},
			wantEvents:    []wantEvent{{eventType: EventTypeSSHKeyRemoved, result: "success", sshKeyID: otherKeyID}},
		},
		{
			name:         "guard refuses removal of the session key",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "1\nq\n",
			want:         headerAlicia + home(listingBoth) + guardLine + home(listingBoth) + byeLine,
			wantEvents:   []wantEvent{{eventType: EventTypeSSHKeyRemoved, result: "failure", detailCode: "current_session_key", sshKeyID: sessionKeyID}},
		},
		{
			name:         "cancel at key-removal confirmation",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "2\nx\nq\n",
			want:         headerAlicia + home(listingBoth) + confirmOther + cancelledLine + home(listingBoth) + byeLine,
		},
		{
			name:         "store error during removal keeps the loop alive",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store: func() *spyStore {
				s := newSpyStore(fixtureKeys())
				s.deleteKeyErr = errors.New("disk on fire")
				return s
			}(),
			input: "2\n2\nq\n",
			want: headerAlicia + home(listingBoth) + confirmOther +
				removalFailedLine + home(listingBoth) + byeLine,
			wantDeleteKey: []deleteCall{{accountID: accountID, keyID: otherKeyID}},
			wantEvents:    []wantEvent{{eventType: EventTypeSSHKeyRemoved, result: "failure", detailCode: "store_error", sshKeyID: otherKeyID}},
		},
		{
			name:         "account deletion happy path",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "d\nDELETE\n",
			want: headerAlicia + home(listingBoth) + consequences(2, "login") + deletePrompt +
				accountDeletedLine + byeLine,
			wantDeleteAcc: 1,
			wantEvents: []wantEvent{
				{eventType: EventTypeAccountDeleted, result: "success"},
				{eventType: EventTypeSSHKeyRemoved, result: "success", sshKeyID: sessionKeyID},
				{eventType: EventTypeSSHKeyRemoved, result: "success", sshKeyID: otherKeyID},
			},
		},
		{
			name:          "account deletion with zero keys",
			account:       fixtureAccount(),
			sessionKeyID:  sessionKeyID,
			store:         newSpyStore(nil),
			input:         "d\nDELETE\n",
			want:          headerAlicia + home(noKeysLine) + consequences(0, "login") + deletePrompt + accountDeletedLine + byeLine,
			wantDeleteAcc: 1,
			wantEvents:    []wantEvent{{eventType: EventTypeAccountDeleted, result: "success"}},
		},
		{
			name:         "account deletion cancel",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "d\nno\nq\n",
			want:         headerAlicia + home(listingBoth) + consequences(2, "login") + deletePrompt + cancelledLine + home(listingBoth) + byeLine,
		},
		{
			name:         "account deletion store error ends the connection cleanly",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store: func() *spyStore {
				s := newSpyStore(fixtureKeys())
				s.deleteAccErr = errors.New("lock denied")
				return s
			}(),
			input:         "d\nDELETE\n",
			want:          headerAlicia + home(listingBoth) + consequences(2, "login") + deletePrompt + accountDeleteFailedLin,
			wantDeleteAcc: 1,
			wantEvents:    []wantEvent{{eventType: EventTypeAccountDeleted, result: "failure", detailCode: "store_error"}},
		},
		{
			name:           "custom enrollment user rendered in account flow",
			account:        fixtureAccount(),
			sessionKeyID:   sessionKeyID,
			enrollmentUser: "ops-signin",
			store:          newSpyStore(fixtureKeys()),
			input:          "d\nnope\nq\n",
			want: headerAlicia + home(listingBoth) + consequences(2, "ops-signin") + deletePrompt +
				cancelledLine + home(listingBoth) + byeLine,
		},
		{
			name:         "invalid menu inputs rejected",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "x\n0\n-1\n99\nD\n\nq\n",
			want: headerAlicia + home(listingBoth) +
				strings.Repeat(invalidLine+home(listingBoth), 6) + byeLine,
		},
		{
			name:         "overlong input rejected",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        strings.Repeat("a", 300) + "\nq\n",
			want:         headerAlicia + home(listingBoth) + invalidLine + home(listingBoth) + byeLine,
		},
		{
			name:         "EOF at menu exits cleanly",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "",
			want:         headerAlicia + home(listingBoth) + byeLine,
		},
		{
			name:         "EOF at removal confirmation exits cleanly",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "2\n",
			want:         headerAlicia + home(listingBoth) + confirmOther + byeLine,
		},
		{
			name:         "EOF at DELETE confirmation exits cleanly",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "d\n",
			want:         headerAlicia + home(listingBoth) + consequences(2, "login") + deletePrompt + byeLine,
		},
		{
			name:         "refresh re-renders the listing",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "r\nq\n",
			want:         headerAlicia + home(listingBoth) + home(listingBoth) + byeLine,
		},
		{
			name:         "labels with control characters render stripped",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store: func() *spyStore {
				keys := fixtureKeys()
				keys[1].Label = "bad\x1b[31mphone\x07done"
				return newSpyStore(keys)
			}(),
			input: "2\nx\nq\n",
			want: headerAlicia + home(
				listLineSession+"2 "+fpOther+" rsa-sha2-256 [disabled] \"bad[31mphonedone\" added 2025-08-15\r\n",
			) + confirmBlock(2, fpOther, "rsa-sha2-256", "bad[31mphonedone") +
				cancelledLine + home(
				listLineSession+"2 "+fpOther+" rsa-sha2-256 [disabled] \"bad[31mphonedone\" added 2025-08-15\r\n",
			) + byeLine,
		},
		{
			name:         "empty listing shows no-keys line",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(nil),
			input:        "q\n",
			want:         headerAlicia + home(noKeysLine) + byeLine,
		},
		{
			name:         "list failure shows generic message and keeps menu",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			store: func() *spyStore {
				s := newSpyStore(fixtureKeys())
				s.listErr = errors.New("scan keys: read-only")
				return s
			}(),
			input: "q\n",
			want:  headerAlicia + home(listFailedLine) + byeLine,
		},
		{
			name:         "pty backspace editing removes wrong digit",
			account:      fixtureAccount(),
			sessionKeyID: sessionKeyID,
			pty:          true,
			store:        newSpyStore(fixtureKeys()),
			input:        "3\x7f2\r2\rq\r",
			want: headerAlicia + home(listingBoth) + "\b \b" + confirmOther +
				"Key 2 removed.\r\n" + home(listingOne) + byeLine,
			wantDeleteKey: []deleteCall{{accountID: accountID, keyID: otherKeyID}},
			wantEvents:    []wantEvent{{eventType: EventTypeSSHKeyRemoved, result: "success", sshKeyID: otherKeyID}},
		},
		{
			name:         "header falls back to account label",
			account:      core.Account{ID: accountID, DeploymentID: deploymentID, Label: "ops-team", Enabled: true},
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "q\n",
			want:         "Coder SSH Gateway -- key management for ops-team\r\n" + home(listingBoth) + byeLine,
		},
		{
			name:         "header falls back to account uuid",
			account:      core.Account{ID: accountID, DeploymentID: deploymentID, Enabled: true},
			sessionKeyID: sessionKeyID,
			store:        newSpyStore(fixtureKeys()),
			input:        "q\n",
			want:         "Coder SSH Gateway -- key management for " + accountID.String() + "\r\n" + home(listingBoth) + byeLine,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runGolden(t, tc)
		})
	}
}

// ---------------------------------------------------------------------------
// Line reader unit tests
// ---------------------------------------------------------------------------

func TestLineReader(t *testing.T) {
	tests := []struct {
		name     string
		pty      bool
		input    string
		wantLine string
		wantErr  error // io.EOF, errOverlong, or nil
		wantEcho string
	}{
		{name: "LF terminated", input: "hello\nrest", wantLine: "hello"},
		{name: "CRLF terminated", input: "hello\r\nrest", wantLine: "hello"},
		{name: "DEL byte kept without pty", input: "a\x7fb\nrest", wantLine: "a\x7fb"},
		{name: "bare CR terminates in pty mode", pty: true, input: "hi\rrest", wantLine: "hi"},
		{name: "CRLF collapses in pty mode", pty: true, input: "hi\r\nnext\r\n", wantLine: "hi"},
		{name: "backspace erases with echo in pty mode", pty: true, input: "ab\x7fc\rrest", wantLine: "ac", wantEcho: "\b \b"},
		{name: "backspace on empty line is silent", pty: true, input: "\x7fa\rrest", wantLine: "a", wantEcho: ""},
		{name: "BS byte also erases in pty mode", pty: true, input: "ab\x08c\rrest", wantLine: "ac", wantEcho: "\b \b"},
		{name: "exactly 256 bytes accepted", input: strings.Repeat("x", 256) + "\nrest", wantLine: strings.Repeat("x", 256)},
		{name: "257 bytes rejected", input: strings.Repeat("x", 257) + "\nrest", wantErr: errOverlong},
		{name: "EOF with pending bytes returns final line", input: "abc", wantLine: "abc"},
		{name: "EOF on empty input", input: "", wantErr: io.EOF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			r := newLineReader(strings.NewReader(tt.input), &out, tt.pty)
			line, err := r.readLine()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("readLine() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readLine() error = %v, want nil", err)
			}
			if line != tt.wantLine {
				t.Errorf("line = %q, want %q", line, tt.wantLine)
			}
			if got := out.String(); got != tt.wantEcho {
				t.Errorf("echo = %q, want %q", got, tt.wantEcho)
			}
		})
	}
}

func TestLineReaderContinuesAfterOverlong(t *testing.T) {
	r := newLineReader(strings.NewReader(strings.Repeat("a", 300)+"\nok\n"), io.Discard, false)
	if _, err := r.readLine(); !errors.Is(err, errOverlong) {
		t.Fatalf("first line error = %v, want errOverlong", err)
	}
	line, err := r.readLine()
	if err != nil || line != "ok" {
		t.Fatalf("second line = (%q, %v), want (\"ok\", nil)", line, err)
	}
}

func TestLineReaderPropagatesReadErrors(t *testing.T) {
	wantErr := errors.New("broken pipe")
	r := newLineReader(errReader{wantErr}, io.Discard, false)
	if _, err := r.readLine(); !errors.Is(err, wantErr) {
		t.Fatalf("readLine() error = %v, want %v", err, wantErr)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// ---------------------------------------------------------------------------
// Label sanitization
// ---------------------------------------------------------------------------

func TestSanitizeLabel(t *testing.T) {
	tests := []struct {
		name  string
		label string
		want  string
	}{
		{name: "plain label unchanged", label: "laptop", want: "laptop"},
		{name: "escape and bell stripped", label: "bad\x1b[31mphone\x07done", want: "bad[31mphonedone"},
		{name: "CRLF and tab stripped", label: "a\r\nb\tc", want: "abc"},
		{name: "NUL and DEL stripped", label: "a\x00b\x7fc", want: "abc"},
		{name: "spaces kept", label: "old phone", want: "old phone"},
		{name: "UTF-8 kept", label: "café ☂", want: "café ☂"},
		{name: "empty", label: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeLabel(tt.label); got != tt.want {
				t.Errorf("sanitizeLabel(%q) = %q, want %q", tt.label, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Serialized-audit hygiene
// ---------------------------------------------------------------------------

// TestAuditSerializedEvents asserts the serialized audit trail of a removal
// plus a full account deletion: IDs present, fingerprints and labels absent.
func TestAuditSerializedEvents(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	auditLog := audit.NewInMemoryLogger()

	run := func(input string) {
		t.Helper()
		svc := &Service{
			Store:        newSpyStore(fixtureKeys()),
			Audit:        auditLog,
			Log:          logger,
			SessionKeyID: sessionKeyID,
			Account:      fixtureAccount(),
			PeerAddress:  peerAddr,
			ConnectionID: connID,
		}
		var out bytes.Buffer
		if err := svc.Run(strings.NewReader(input), &out); err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	}
	run("2\n2\nq\n")   // removal: one success event
	run("d\nDELETE\n") // deletion: account_deleted + one event per key

	events := auditLog.Events()
	if len(events) != 4 {
		t.Fatalf("events = %d, want 4", len(events))
	}
	for i, ev := range events {
		data, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal event %d: %v", i, err)
		}
		s := string(data)
		if !strings.Contains(s, accountID.String()) {
			t.Errorf("event %d missing account ID: %s", i, s)
		}
		if ev.SSHKeyID != "" && !strings.Contains(s, ev.SSHKeyID) {
			t.Errorf("event %d missing key ID: %s", i, s)
		}
		for _, secret := range []string{fpSession, fpOther, "laptop", "old phone"} {
			if strings.Contains(s, secret) {
				t.Errorf("event %d leaks %q: %s", i, secret, s)
			}
		}
	}
}

// The UI transcript itself may show fingerprints and labels, but must never
// contain terminal control sequences smuggled in via stored labels.
func TestTranscriptIsControlFree(t *testing.T) {
	keys := fixtureKeys()
	keys[1].Label = "x\x1b]0;pwned\x07y"
	svc := &Service{
		Store:        newSpyStore(keys),
		Audit:        audit.NewInMemoryLogger(),
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		SessionKeyID: sessionKeyID,
		Account:      fixtureAccount(),
		ConnectionID: connID,
	}
	var out bytes.Buffer
	if err := svc.Run(strings.NewReader("q\n"), &out); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if got := out.String(); strings.ContainsAny(got, "\x00\x01\x07\x08\x1b\x7f") {
		t.Errorf("transcript contains control characters: %q", got)
	}
}
