# internal/sshauth

Auth state machine for the outer SSH connection: key proof → credential verification → terminal permissions or an auth-time continuation. No session handling here.

## WHERE TO LOOK
| Task | Location |
|------|----------|
| Callback wiring (pubkey + verified) | config.go `BuildCallbacks` |
| Auth decisions, enrollment, renewal | callbacks.go |
| Permission types + wire encode/parse | permissions.go |
| Enrollment continuation | enrollment.go |
| Inline renewal continuation | renewal.go |

## MODEL
- Two terminal outcomes only: `FinalWorkspacePermissions` (proceed, any channel type) and `FinalEnrollmentPermissions` (`mustReconnect` — connection closes after enrollment; no workspace access on that connection).
- Renewal is INLINE: an expired credential triggers a keyboard-interactive continuation on the SAME connection; success returns `FinalWorkspacePermissions` — no reconnect. This is why reserved usernames (`auth@`) were removed; do not reintroduce a renewal username.
- Pubkey lookup makes NO Coder call. The verified-key callback loads the encrypted credential, verifies via the cached verifier, then grants permissions or installs a continuation.
- Continuations (KI) exist only after verified public key auth — never as top-level auth methods.

## ANTI-PATTERNS
- Candidate token bytes: never logged, audited, or returned in errors (renewal.go asserts this).
- Never widen `Final*Permissions` beyond what the account/key state supports.
- The Coder verify cache is keyed by (deployment, account, credential generation) — anything that changes stored credentials must bump the generation or the cache serves stale results.

## TESTING
- callbacks_wire_test.go / renewal_wire_test.go: httptest Coder double + real store + real callbacks; defines `leakCheck` (goleak, ignoring HTTP persistConn loops).
- Wire round-trip tests cover permission encode/parse; malformed input must reject (fuzz-style table cases).
