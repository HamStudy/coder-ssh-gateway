# internal/keymgmt

The account-scoped, line-based SSH key management UI served on the session channel after keymanagement-mode auth (internal/server dispatches it; internal/sshauth grants the mode). Pure UI + store calls — no Coder API, no credentials, no tokens.

## WHERE TO LOOK
| Task | Location |
|------|----------|
| Run loop, removal + account-deletion flows | service.go |
| Screen rendering, pinned UI strings | ui.go |
| Input line reader (256-byte cap, bare-CR termination, pty echo + backspace) | reader.go |
| Audit event authoring | audit.go |
| Label control-char stripping | sanitize.go |

## MODEL
- UI strings are CONTRACTUAL (docs + e2e pin them verbatim). All output lines end `\r\n`, ASCII, no ANSI. Pinned lines (menu, consequences screen) exceed 72 columns by design — verbatim beats wrap.
- Every store mutation passes `Service.Account.ID` (the session's own account); menu numbers index the last rendered listing (store order, sorted by ID).
- The session key (`SessionKeyID`) is refused at SELECTION time, before any store call: exact guard message + WARN log + `ssh_key_removed` failure audit with `current_session_key`.
- Audit: `ssh_key_removed` per removal attempt (success / failure `store_error` / failure `current_session_key`); account deletion emits `account_deleted` PLUS one `ssh_key_removed` success per cascaded key (the trail survives the account). IDs only — never fingerprints or labels.
- Store errors never reach UI text: generic messages, real detail at WARN in the log. A failed key removal keeps the loop alive; a failed DeleteAccount ends the connection cleanly (transcript stops after the generic message).
- `Run` always returns nil (quit / EOF / account deleted are all clean exits); write errors are ignored — a disconnecting client must not error-spam.
- Terminators: LF always; CR terminates IMMEDIATELY (pty clients send bare CR for Enter — the reader never waits for a byte after CR; a drip-reader test in keymgmt_test.go is the anti-stall proof). CRLF is one terminator via a pending-LF flag: the CR sets it and the NEXT readLine discards one leading LF (applies on every subsequent read, never produces a phantom empty line, and is consumed even when the next byte is not an LF; CR-terminated overlong lines set it too). Pty mode (via `WithPty`) erases backspace bytes with a `\b \b` echo AND echoes printable ASCII (0x20–0x7e) as appended, so pty users see what they type; non-printable bytes stay unechoed; no-pty mode is byte-for-byte pass-through with no echo.
- `EnrollmentUser` (default "login") renders the recovery hints; the server sets it from the effective enrollment config at shell time (internal/server/keymanagement.go `runKeyManagementUI`).

## ANTI-PATTERNS
- Never widen `Store` beyond list/delete; never import coderapi/secretbox or touch credentials here.
- No last-key guard anywhere (owner decision; `login@` re-enrollment restores any state).
- Deleting the last key, and account deletion removing the session's own key, are both ALLOWED by design — the typed DELETE confirmation is the guard.
- Menu commands are exact lowercase `d`/`r`/`q`; `DELETE` is exact uppercase. Do not "helpfully" accept case variants — fail toward Invalid input / Cancelled.

## TESTING
- keymgmt_test.go: golden FULL-transcript table tests over in-memory reader/writer + spy store (records every delete call and asserts the session AccountID), reader unit table, sanitize table, serialized-audit hygiene (IDs present, fingerprints/labels absent), goleak via TestMain. Run with `-race` too.
