# internal/testutil

Test doubles for the Coder CLI and the workspace SSH endpoint. Everything integration/e2e tests fake lives here.

## LAYOUT
| Path | Role |
|------|------|
| fake-coder/main.go | standalone fake `coder` binary (build tag `fakecoder`) |
| fakecod.go | Go helpers: build, env, argv, process setup, record parsing |
| innerssh/ | in-memory stdio SSH server standing in for a workspace agent |

## FAKE-CODER CONTRACT (fake-coder/main.go)
- Exact argv shape: `--global-config <dir> ssh --stdio --wait=<yes|no|auto> [--disable-autostart=true] <target>` — deviations exit 70.
- `CODER_SESSION_TOKEN` must be in env and absent from every argv element (exit 71 on leak).
- Only approved `CODER_*` env vars accepted; `SSH_AUTH_SOCK` and `LD_PRELOAD` rejected.
- stdout is exclusively the SSH protocol; diagnostics go to stderr.
- `FAKE_CODER_RECORD` writes JSONL (argv, sorted env keys, token length — never token values); parse with `ReadFakeRecords`.
- Change gateway spawn behavior → update this contract AND fakecod_test.go in the same commit.

## HELPERS (fakecod.go)
- `BuildFakeCoder`: cached `go build -tags fakecoder`.
- `FakeEnv` / `FakeArgv` / `NewFakeCmd` (process-group isolation) / `ReadFakeRecords`.

## INNERSHH behavior (innerssh/innerssh.go)
- exec `printf hello` → literal `hello`; other exec → `ECHO:<command>`; `exit 7` → status 7.
- shell → prints `FAKE-SHELL-READY`, then echoes lines VERBATIM (no `ECHO:` prefix — probes must match raw line text).
- Supports pty-req/shell/exec/env/signal/window-change/subsystem sftp (pkg/sftp, real FS)/auth-agent-req + agent channel (agent-ping exec lists keys via the REAL agent when forwarded); no auth; no network listener (stdio pipes only).
- Feature extensions (innerssh_features.go): direct-tcpip dials real addresses; tcpip-forward binds real listeners and opens forwarded-tcpip channels. `agent-ping` exec probes the agent chain end to end.
