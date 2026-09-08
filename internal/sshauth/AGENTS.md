# internal/sshauth

Auth state machine for the outer SSH connection: key proof → credential verification → terminal permissions or an auth-time continuation. No session handling here.

## WHERE TO LOOK
| Task | Location |
|------|----------|
| Callback wiring (pubkey + verified) | config.go `BuildCallbacks` |
| Auth decisions, enrollment, renewal, key management | callbacks.go |
| Permission types + wire encode/parse (workspace, enrollment, **keymanagement**) | permissions.go |
| Enrollment continuation | enrollment.go |
| Inline renewal continuation | renewal.go |
| Key-management username branch | callbacks.go `keysCandidate` / `verifiedKeyManagement` |

## MODEL
- Three terminal outcomes on the wire: `FinalWorkspacePermissions` (proceed, any channel type), `FinalEnrollmentPermissions` (`mustReconnect` — connection closes after enrollment; no workspace access on that connection), and `FinalKeyManagementPermissions` (proceed to keymgmt dispatch; only one session channel accepted, no transport, no Coder call).
- Renewal is INLINE: an expired credential triggers a keyboard-interactive continuation on the SAME connection; success returns `FinalWorkspacePermissions` — no reconnect. This is why reserved usernames (`auth@`) were removed; do not reintroduce a renewal username.
- Key-management auth is pubkey-only: an enrolled key on the configured `key_management.user` username grants `FinalKeyManagementPermissions` and never touches the verifier, the credential, or Coder. An expired or missing stored credential does not block the UI — that is the cleanup scenario. `generation=0` on the wire (no credential consulted) marks this mode.
- Pubkey lookup makes NO Coder call. The verified-key callback loads the encrypted credential, verifies via the cached verifier, then grants permissions or installs a continuation.
- Continuations (KI) exist only after verified public key auth — never as top-level auth methods.

## ANTI-PATTERNS
- Candidate token bytes: never logged, audited, or returned in errors (renewal.go asserts this).
- Never widen `Final*Permissions` beyond what the account/key state supports.
- The Coder verify cache is keyed by (deployment, account, credential generation) — anything that changes stored credentials must bump the generation or the cache serves stale results.
- Key-management mode MUST NOT call `LoadCredential`, `VerifyCached`, or `startRenewal` (callbacks.go:174-179). The path that rejects with `current_session_key` lives in `internal/keymgmt` and is downstream of these finals.
- Disabled key-management (`KeyManagement == nil || !Enabled` or `KeyManagementUser == ""`) MUST reject byte-identically to any unknown username — see internal/sshauth/enrollment.go enrollment_wire_test.go:523-560 for the byte-equality pattern (`internal/sshauth/enrollment_wire_test.go:633-686` covers certificate rejection).
- Do not import `internal/keymgmt` from this package — the auth state and the UI are deliberately separate (auth decides the mode, server keymanagement.go runs the UI).

## TESTING
- callbacks_wire_test.go / renewal_wire_test.go / keymanagement_wire_test.go: httptest Coder double + real store + real callbacks; defines `leakCheck` (goleak, ignoring HTTP persistConn loops). The keymanagement wire tests additionally wrap the Coder double in an atomic counter and assert zero requests over the keys username.
- Wire round-trip tests cover permission encode/parse (workspace, enrollment, keymanagement); malformed input must reject (fuzz-style table cases). `ParseFinalPermissions` admits `{workspace, keymanagement}`; `ParseCandidatePermissions` admits `{candidate, keymanagement}`.
