// Package keymgmt serves the account-scoped, line-based SSH key management
// UI on the session channel of a keymanagement-mode connection. The UI is
// deliberately plain — ASCII, CR-LF terminated lines, no ANSI, no TUI
// library — so it behaves identically in every SSH client, mobile ones
// included. It talks only to the store: no Coder API, no credentials.
package keymgmt

import (
	"io"
	"log/slog"
	"strconv"

	"github.com/google/uuid"

	"github.com/HamStudy/coder-ssh-gateway/internal/audit"
	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

// Store is the narrow store subset the key-management UI needs.
// *store.Store satisfies it (pattern: sshauth KeyLookupStore).
type Store interface {
	ListKeysForAccount(accountID uuid.UUID) ([]core.SSHKeyRecord, error)
	DeleteKey(accountID, keyID uuid.UUID) error
	DeleteAccount(accountID uuid.UUID) error
}

// Service drives the key-management UI for one authenticated connection.
// Every store mutation is scoped to Account.ID — the session's own account —
// and the key that authenticated the session (SessionKeyID) can never be
// removed through the key-removal flow.
type Service struct {
	Store        Store
	Audit        audit.Logger
	Log          *slog.Logger
	SessionKeyID uuid.UUID
	Account      core.Account
	// EnrollmentUser renders the recovery hints ("re-enroll with <user>@").
	// Empty falls back to the default enrollment username "login".
	EnrollmentUser string
	PeerAddress    string
	ConnectionID   string

	pty  bool                // pty mode: backspace erase handling (todo 7 wires it)
	keys []core.SSHKeyRecord // last rendered listing; menu numbers index into it
}

// WithPty enables pty line-editing behaviors (backspace erase + echo).
// Returns the service for chaining.
func (s *Service) WithPty(enabled bool) *Service {
	s.pty = enabled
	return s
}

// Run drives the UI loop until the user quits, the input reaches EOF (client
// disconnect), or the account is deleted. It always returns nil: a
// disconnecting client must not produce error spam, and output is best-effort
// (write errors are ignored) for the same reason.
func (s *Service) Run(in io.Reader, out io.Writer) error {
	sc := screen{w: out}
	rd := newLineReader(in, out, s.pty)

	sc.line("%s", headerLine(s.displayName()))
	s.renderListing(sc)

	for {
		line, err := rd.readLine()
		if err == errOverlong {
			sc.line("%s", msgInvalidInput)
			s.renderListing(sc)
			continue
		}
		if err != nil {
			// EOF or a broken pipe: the client is gone. Clean exit.
			sc.line("%s", msgBye)
			return nil
		}
		switch line {
		case "q":
			sc.line("%s", msgBye)
			return nil
		case "r":
			s.renderListing(sc)
		case "d":
			if s.runAccountDeletion(sc, rd) {
				return nil
			}
		default:
			if s.runKeyRemoval(sc, rd, line) {
				return nil
			}
		}
	}
}

// runKeyRemoval handles a numeric menu selection: guard, two-step confirm,
// store call. Returns true when Run must return (client gone).
func (s *Service) runKeyRemoval(sc screen, rd *lineReader, line string) bool {
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(s.keys) {
		sc.line("%s", msgInvalidInput)
		s.renderListing(sc)
		return false
	}
	key := s.keys[n-1]

	// The session's own key is refused before any store call.
	if key.ID == s.SessionKeyID {
		sc.line("%s", msgSessionKeyGuard)
		s.logger().Warn("keymgmt: session-key removal refused",
			slog.String("connection_id", s.ConnectionID),
			slog.String("ssh_key_id", key.ID.String()))
		s.recordEvent(EventTypeSSHKeyRemoved, resultFailure, detailCurrentSessionKey, key.ID)
		s.renderListing(sc)
		return false
	}

	sc.line("You selected key %d: %s %s \"%s\"", n, key.Fingerprint, key.Algorithm, sanitizeLabel(key.Label))
	sc.line("Type %d again to permanently remove it, anything else to cancel:", n)

	confirm, err := rd.readLine()
	if err == errOverlong {
		confirm = "" // overlong input is "anything else": cancel
	} else if err != nil {
		sc.line("%s", msgBye)
		return true
	}
	if confirm != strconv.Itoa(n) {
		sc.line("%s", msgCancelled)
		s.renderListing(sc)
		return false
	}

	if err := s.Store.DeleteKey(s.Account.ID, key.ID); err != nil {
		s.logger().Warn("keymgmt: key removal failed",
			slog.String("connection_id", s.ConnectionID),
			slog.String("ssh_key_id", key.ID.String()),
			slog.String("detail", err.Error()))
		s.recordEvent(EventTypeSSHKeyRemoved, resultFailure, detailStoreError, key.ID)
		sc.line("%s", msgRemovalFailed)
		s.renderListing(sc)
		return false
	}

	s.recordEvent(EventTypeSSHKeyRemoved, resultSuccess, "", key.ID)
	sc.line("Key %d removed.", n)
	s.renderListing(sc)
	return false
}

// runAccountDeletion handles the `d` flow: consequences screen, typed DELETE
// confirmation, cascade. Returns true when Run must return (flow finished or
// client gone). A failed DeleteAccount also ends the connection cleanly.
func (s *Service) runAccountDeletion(sc screen, rd *lineReader) bool {
	keys, err := s.Store.ListKeysForAccount(s.Account.ID)
	if err != nil {
		s.logStoreFailure("keymgmt: key list failed", err)
		sc.line("%s", msgListFailed)
		s.renderListing(sc)
		return false
	}
	s.keys = keys

	sc.line("This will permanently delete your account: %d key(s) and your stored Coder token will be removed. You can re-enroll any time with %s@ and a fresh Coder token.",
		len(keys), s.enrollmentUser())
	sc.line("%s", msgDeletePrompt)

	confirm, err := rd.readLine()
	if err == errOverlong {
		confirm = ""
	} else if err != nil {
		sc.line("%s", msgBye)
		return true
	}
	if confirm != "DELETE" {
		sc.line("%s", msgCancelled)
		s.renderListing(sc)
		return false
	}

	if err := s.Store.DeleteAccount(s.Account.ID); err != nil {
		s.logStoreFailure("keymgmt: account deletion failed", err)
		s.recordEvent(EventTypeAccountDeleted, resultFailure, detailStoreError, uuid.Nil)
		sc.line("%s", msgAccountDeletionFailed)
		return true
	}

	s.recordEvent(EventTypeAccountDeleted, resultSuccess, "", uuid.Nil)
	for _, k := range keys {
		s.recordEvent(EventTypeSSHKeyRemoved, resultSuccess, "", k.ID)
	}
	sc.line("Account deleted. Reconnect with %s@ to enroll again.", s.enrollmentUser())
	sc.line("%s", msgBye)
	return true
}

// renderListing refreshes the cached listing and writes it with the menu
// prompt. List failures print a generic message; the loop survives.
func (s *Service) renderListing(sc screen) {
	sc.blank()
	keys, err := s.Store.ListKeysForAccount(s.Account.ID)
	if err != nil {
		s.logStoreFailure("keymgmt: key list failed", err)
		sc.line("%s", msgListFailed)
	} else {
		s.keys = keys
		if len(keys) == 0 {
			sc.line("%s", msgNoKeys)
		}
		for i, k := range keys {
			sc.line("%s", keyLine(i+1, k))
		}
	}
	sc.blank()
	sc.line("%s", msgMenu)
}

// displayName picks the header identity: cached Coder username, else the
// account label, else the account UUID (never empty).
func (s *Service) displayName() string {
	if s.Account.CachedUsername != "" {
		return s.Account.CachedUsername
	}
	if s.Account.Label != "" {
		return s.Account.Label
	}
	return s.Account.ID.String()
}

// enrollmentUser resolves the recovery-hint username.
func (s *Service) enrollmentUser() string {
	if s.EnrollmentUser != "" {
		return s.EnrollmentUser
	}
	return "login"
}

func (s *Service) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) logStoreFailure(msg string, err error) {
	s.logger().Warn(msg,
		slog.String("connection_id", s.ConnectionID),
		slog.String("detail", err.Error()))
}
