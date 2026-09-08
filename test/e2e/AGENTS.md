# test/e2e

End-to-end tests: real gateway binary + real OpenSSH client vs a fake HTTPS Coder API. The `live`-tagged tests run against a real Coder deployment and NEVER in CI.

## LAYOUT
| File | Role |
|------|------|
| harness_test.go | gateway fixtures, fakeCoderAPI (httptest TLS), config generation, OpenSSH helpers |
| e2e_fake_test.go | ProxyJump, `-W` stdio, direct sessions, renewal PTY, child cleanup |
| e2e_live_test.go | `live` build tag; needs CODER_LIVE_URL/TOKEN/CODER_BINARY env |
| keymanagement_test.go | real-OpenSSH e2e for the key-management UI (PTY + no-pty flows, guard, refusals, audit, account-deletion recovery) |

## FIXTURE FLOW
`gatewayFixture`: run binary `init` → rewrite config → enroll account → register key → set credential → `serve`. Gateway env is minimal (PATH/HOME/TMPDIR) — anything else must be added deliberately.

## CI ENVIRONMENT TRAPS (all bit us once — do not regress)
- CI has NO `TERM`: any pty-based client must set `TERM=xterm-256color` in the child env or the gateway (correctly) rejects the pty-req.
- CI has no `/usr/local/bin/coder`: never reference absolute coder paths; write stubs into `t.TempDir()`.
- OpenSSH input probes need `\r\n` line endings; shutdown escalation uses `Process.Kill`, not clean waits.
- Limit/admission assertions race the listener's accept backlog — see internal/server/AGENTS.md (wait for banner bytes first).
- Live tests stay behind the `live` build tag; tokens via stdin/headers only, never argv or files.

## ASSERTIONS
- Renewal flow: wait for `Coder token:` prompt, write fresh token, assert continuation banner + shell output; assert the token is never echoed back.
- Child cleanup: `pgrep -P` via `waitNoChildren` after fixtures shut down (SIGTERM → SIGKILL).
