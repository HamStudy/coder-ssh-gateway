# internal/tunnel

Child process lifecycle (`coder ssh --stdio`) and the two transports layered over it: the session bridge (inner SSH) and the direct-tcpip pipe (raw bytes).

## WHERE TO LOOK
| Task | Location |
|------|----------|
| Spawn: argv/env/process group/token wipe | starter.go `Launcher` |
| Direct-tcpip pipe + supervision | tunnel_starter.go |
| Session bridge (pty/exec/shell) | workspace_session.go |
| Startup/half-close/escalation | supervisor.go |
| Credential recheck at channel open | recheck.go |
| Coder global config dir setup | globalconfig.go |

## MODEL
- `coder ssh --stdio` speaks SSH, not raw bytes. Two consequences:
  - direct-tcpip is a plain byte pipe (supervised child, no protocol awareness).
  - session channels need the inner SSH bridge: outer session channel → x/crypto client over child stdio → inner session.
- Inner client uses `InsecureIgnoreHostKey()` deliberately — the transport is a local child we spawned. Do not "fix".
- Never send `user@target` to the CLI: the inner username is agent-determined (Coder hardcodes it). Target is workspace name or owner/workspace only.
- Token reaches the child via `CODER_SESSION_TOKEN` env (allowlisted) — never argv, never stdin echo.

## SUPERVISION
- Startup timeout, first-byte timeout, half-close handled per direction, TERM→KILL escalation, descendant cleanup, stderr ring buffer bounded, `Wait` returns exactly once.

## ANTI-PATTERNS
- No new env vars without allowlist + fake-coder contract update (internal/testutil/fake-coder rejects unknown `CODER_*`).
- Do not add channel types here before server-side admission exists (internal/server decides what reaches the starter).

## TESTING
- supervisor_test.go covers exit-before-stdout, timeouts, half-close, TERM-ignored, descendants, shutdown.
- Env allowlist + token-not-in-argv are asserted in starter_test.go; update both sides together.
- Request forwarding matrix (pty-req/shell/exec/env/signal/window-change) lives in workspace_session.go; subsystem requests are intentionally NOT forwarded (SFTP gap — docs/client-setup.md).
