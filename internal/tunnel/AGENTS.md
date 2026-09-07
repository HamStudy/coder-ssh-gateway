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
  - standalone workspace:22 direct-tcpip is a plain byte pipe (supervised child, no protocol awareness).
  - session channels need the inner SSH bridge: outer session channel → x/crypto client over child stdio → inner session.
- SessionTransport (workspace_transport.go) owns one child + inner client per outer connection. The bridge does ALL piping manually: x/crypto's RequestSubsystem never calls the copy setup that Shell/Exec use, so hand-rolled pipes + wait funcs preserve output-drained-before-exit.
- Deferred bridge (workspace_session_deferred.go `BridgePendingSession`): the server accepts a session channel while the transport is still starting and answers pty/shell immediately (optimistic acks, §19.9), queueing them for replay inside `BridgeSession` (the `queued` parameter applies them to the fresh inner session before live traffic). Rationale: mobile clients time out on replies that wait for the child spawn + inner handshake. Transport failure is presented as stderr + exit-status 255, never a hang. `queueDecision` must stay consistent with `applySessionRequest` pre-start behavior.
- Request rejections are never silent: `applySessionRequest` and `queueDecision` return a reason, and callers log type + reason at WARN. Keep validation tolerance identical across both paths (pty parsing is shared via `parsePtyRequest` — empty Term and empty modes are legal from mobile clients).
- Inner client uses `InsecureIgnoreHostKey()` today, but the key is verifiable: Coder's stdio server presents a deterministic RSA-2048 key derived from FNV-1a(owner, workspace, agent) (`SSHKeySeed`/`CoderSigner` in coder/coder). Pin it with `ssh.FixedHostKey` computed from the parsed route; isolate the derivation in one file so a Coder algorithm change is a one-file fix.
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
- Request forwarding matrix (pty-req/shell/exec/env/signal/window-change/subsystem/auth-agent-req) lives in workspace_session.go; agent channels, forwarded-tcpip, direct-tcpip dials, and tcpip-forward relays live in workspace_transport.go.
