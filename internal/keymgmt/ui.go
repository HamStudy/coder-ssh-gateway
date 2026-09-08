package keymgmt

import (
	"fmt"
	"io"
	"time"

	"github.com/HamStudy/coder-ssh-gateway/internal/core"
)

// UI strings. These are CONTRACTUAL: docs and the e2e suite pin them
// verbatim. Several exceed 72 columns by design — verbatim beats wrap.
const (
	headerPrefix = "Coder SSH Gateway -- key management for "

	msgMenu = "Enter a key number to remove it, d to delete your account, r to refresh, q to quit:"

	msgBye                   = "Bye."
	msgCancelled             = "Cancelled."
	msgInvalidInput          = "Invalid input."
	msgSessionKeyGuard       = "This key authenticates your current session and cannot be removed."
	msgRemovalFailed         = "Removal failed. The key was not changed; try again or contact your administrator."
	msgAccountDeletionFailed = "Account deletion failed. Your account was not changed; try again or contact your administrator."
	msgListFailed            = "Failed to load keys. Try again or contact your administrator."
	msgNoKeys                = "No keys enrolled."
	msgDeletePrompt          = "Type DELETE to permanently delete your account, anything else to cancel:"
)

// screen writes CR-LF terminated lines to the session. Writes are
// best-effort: errors are ignored because a failing writer means the client
// is gone, which the input side reports as EOF.
type screen struct{ w io.Writer }

func (s screen) line(format string, args ...any) {
	fmt.Fprintf(s.w, format+"\r\n", args...)
}

func (s screen) blank() {
	fmt.Fprint(s.w, "\r\n")
}

func headerLine(name string) string {
	return headerPrefix + name
}

// keyLine renders one numbered listing entry:
// <n> <Fingerprint> <Algorithm>[ [disabled]] "<Label>" added <YYYY-MM-DD>.
// There is deliberately no last-used column: TouchKeyLastUsed has no
// production caller, so it would always read "never"; the created date is
// the key-telling datum and the last-used timestamp stays reserved.
func keyLine(n int, k core.SSHKeyRecord) string {
	line := fmt.Sprintf("%d %s %s", n, k.Fingerprint, k.Algorithm)
	if !k.Enabled {
		line += " [disabled]"
	}
	line += fmt.Sprintf(" \"%s\" added %s", sanitizeLabel(k.Label), addedDate(k))
	return line
}

// addedDate renders the UTC calendar date of the key's creation.
func addedDate(k core.SSHKeyRecord) string {
	return time.UnixMilli(k.CreatedAtMs).UTC().Format("2006-01-02")
}
