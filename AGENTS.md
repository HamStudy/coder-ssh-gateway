# PROJECT KNOWLEDGE BASE

**Generated:** 2026-09-07
**Commit:** 4eab9f2
**Branch:** main

## OVERVIEW
SSH gateway fronting a Coder deployment: users SSH to the gateway, authenticate with an SSH key enrolled per Coder account, and get proxied into workspaces via the Coder CLI run as a subprocess (`coder ssh --stdio`). Go 1.26, single module `github.com/HamStudy/coder-ssh-gateway`. State is a locked flat-file store; credentials are AES-256-GCM encrypted.

## STRUCTURE
```
cmd/coder-ssh-gateway/  # single entry point; delegates to internal/app
internal/app/           # CLI: serve, init, admin, doctor, version + runtime wiring (Build)
internal/server/        # outer SSH listener: admission, limits, channel dispatch
internal/sshauth/       # auth state machine: permissions, enrollment, inline renewal
internal/tunnel/        # child process lifecycle + session/direct-tcpip bridges
internal/coderapi/      # Coder API client, verifier, verify cache
internal/store/         # locked flat-file state store (deployments, accounts, keys, credentials)
internal/secretbox/     # AES-256-GCM envelope encryption, key providers (env:/file)
internal/config/        # YAML config, strict decoding (KnownFields), validation
internal/route/         # workspace target parsing (user/workspace, owner/workspace) + fuzz corpus
internal/limits/        # connection + rate limits (global, per-IP, per-account)
internal/core/          # shared domain types, error kinds
internal/audit/         # audit events
internal/health/ internal/metrics/ internal/version/  # small surfaces
internal/testutil/      # fake-coder binary + Go helpers (has own AGENTS.md)
test/e2e/               # real-OpenSSH e2e vs real gateway binary (has own AGENTS.md)
deploy/                 # helm chart (own AGENTS.md), k8s raw manifests, Dockerfile, systemd
docs/                   # operator-guide, client-setup, troubleshooting, adr/
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add/modify CLI command | internal/app/app.go | dispatch is explicit; serve wiring in serve.go `Build`/`ServeOn` |
| Auth flow change | internal/sshauth/callbacks.go | see internal/sshauth/AGENTS.md |
| Channel admission rules | internal/server/channels.go | see internal/server/AGENTS.md |
| Child spawn / argv / env | internal/tunnel/starter.go | env allowlist; token never in argv |
| Session bridging (pty/exec) | internal/tunnel/workspace_session.go | inner SSH client over child stdio |
| Config field or validation | internal/config/ | strict YAML: adding a field = add to struct + validate |
| Deployment assets | deploy/helm/coder-ssh-gateway/ | see its AGENTS.md for release lockstep |

## CODE MAP
Centrality unmeasured (no codegraph index); roles from LSP + reads.

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `app.Build` / `(*Built).ServeOn` | fn/meth | internal/app/serve.go | assemble runtime; bind SSH + aux HTTP |
| `sshauth.BuildCallbacks` | fn | internal/sshauth/config.go | per-connection pubkey + verified-key callbacks |
| `FinalWorkspacePermissions` / `FinalEnrollmentPermissions` | type | internal/sshauth/permissions.go | terminal auth outcomes; enrollment forces reconnect |
| `server.handleConn` | fn | internal/server/connection.go | admission → handshake → callbacks → dispatch |
| `dispatchWorkspaceChannels` | fn | internal/server/channels.go | one session channel + N direct-tcpip per connection |
| `WorkspaceSessionStarter` | type | internal/tunnel/workspace_session.go | outer session → inner SSH bridge |
| `TunnelStarter` | type | internal/tunnel/tunnel_starter.go | direct-tcpip raw byte pipe + supervision |
| `Launcher.Launch` | meth | internal/tunnel/starter.go | builds argv/env, process group, token wipe |
| `store.Open` | fn | internal/store/store.go | shared-lock state store (multi-instance safe; ADR-0004) |
| `verifier` + cache | type | internal/coderapi/ | token verification; cache keyed incl. credential generation |

## CONVENTIONS
- CLI flag order: global flags (`--state-dir`) go BEFORE the subcommand; enforced by the Dockerfile entrypoint too.
- Config YAML decodes with `KnownFields(true)` — unknown fields are errors. Every new field needs struct + validation.
- `env:VARNAME` indirection accepted for encryption-key paths (see internal/secretbox); resolution must exempt the `env:` prefix before path logic.
- Errors wrap with `%w`; user-facing errors must never contain tokens or response bodies.
- Never silently drop or reject client protocol traffic: every refusal logs the type and reason — WARN when something failed our expectations (invalid/malformed/incompatible), DEBUG for deliberate policy refusals. Client incompatibilities (e.g. mobile clients' pty-req quirks) must be diagnosable from logs alone.
- Docs live in docs/ (operator-guide, client-setup, troubleshooting) + docs/adr/ numbered records. Keep docs current with behavior.

## ANTI-PATTERNS (THIS PROJECT)
- NEVER put a Coder token in argv, CLI flags, logs, audit events, error text, or persisted files. Token path: stdin/prompt/env-to-child only. Tests assert this.
- NEVER co-locate the encryption key with the state directory.
- NEVER reintroduce reserved usernames (`auth@`, `coder@`, `transportUser`, `maintenanceUser`). Removed by design: renewal is inline on any workspace connection; direct-tcpip is available on every authenticated connection; the inner username is agent-determined (Coder hardcodes it — never send `user@target` to the CLI).
- Multi-instance: instances share the state dir via shared flock + atomic rename + credential-generation CAS; the flock is advisory (NFS/Gluster locks may be unreliable — never rely on it for correctness). Audit files are per-instance suffixed; retention parses the date before the suffix. Limits are per instance.
- Do not add top-level password/keyboard-interactive SSH auth — KI exists only as an auth-time continuation (renewal/enrollment) after verified public key auth.

## UNIQUE STYLES
- Distroless runtime image plus a static busybox: `sh` on PATH (and `/bin/sh`) for exec-in maintenance; applets run as `busybox <applet>` (`busybox tar`, `busybox vi`, ...). No package manager. `doctor` and logs remain the first tools.
- Pinned toolchain: staticcheck v0.8.1, govulncheck v1.7.0, x/crypto floor v0.52.0 (scripts/check-xcrypto-version.sh).
- CI extras beyond Go defaults: Dockerfile smoke build, fuzz smoke on route parsing.

## COMMANDS
```bash
make build        # bin/coder-ssh-gateway with version ldflags
make test         # go test ./... -count=1
make test-race    # -race
make lint         # go vet + pinned staticcheck
make vuln         # pinned govulncheck
make ci           # test + test-race + lint + vuln
make fmt          # check-only, does not rewrite
```
Release: bump Chart.yaml `version` AND `appVersion` to the new semver → tag `vX.Y.Z` → publish.yml builds multi-arch image (plus `:latest`), pushes chart to `oci://ghcr.io/hamstudy/charts/coder-ssh-gateway`, creates GitHub Release (tarball attached as fallback). Guard fails the release if Chart appVersion ≠ tag.

## NOTES
- Validation asymmetry: `serve` eager-loads the active encryption key and fails fast at boot; `doctor` performs its own independent checks. doctor passing ≠ serve boots. Test config changes through both.
- `coder ssh --stdio` speaks SSH, not raw bytes — that is why the session bridge (internal/tunnel/workspace_session.go) exists as a separate transport from the raw direct-tcpip pipe.
- The inner SSH client currently uses `InsecureIgnoreHostKey()`. Coder's stdio server presents a DETERMINISTIC host key (RSA-2048 from FNV-1a over owner/workspace/agent — `SSHKeySeed`/`CoderSigner` in coder/coder), so it can be pinned with `ssh.FixedHostKey` instead; pinning is the intended end state (see tunnel AGENTS.md).
- Known cleanup debt (as of 4eab9f2): `SSH.MaintenanceUser` still parsed in config (old configs accepted), unreachable `ModeTransport` branch in permissions parsing, stale maintenance/transport comments across server/app, and coder-ssh-gateway-design.md is historical (pre-removal design).
- The session bridge relays subsystems (sftp/scp), agent forwarding, and port forwarding (-L/-R/-D); arbitrary direct-tcpip targets and tcpip-forward global requests resolve through the connection's workspace transport (see internal/server/AGENTS.md + internal/tunnel/AGENTS.md). Jump syntax remains for exotic cases.
- Temporary INFO diagnostics (pty-reject, session-channel-reject reasons) added while debugging CI; keep or trim deliberately, do not silently accumulate more.
