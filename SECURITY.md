# Security — coder-ssh-gateway

Unofficial community project; not affiliated with Coder. This document
covers secure deployment requirements, what the gateway protects and
what it cannot, how to back up secrets safely, and how to report a
vulnerability.

## Secure deployment checklist

Treat every item below as required before opening the gateway to real
users.

### Host and process

- Run on a hardened single-purpose host or inside a hardened
  container. The gateway holds encrypted Coder session tokens and is
  a high-value target.
- Run as a dedicated non-login system user. The systemd unit and
  Kubernetes manifests do this for you; verify the same in any custom
  deployment.
- Keep the gateway binary and the Coder CLI pinned to known versions.
  Pin both together when bumping the CLI inside the container image.
- Disable core dumps. Tokens live in process memory; a core dump is a
  credential. The shipped systemd unit sets `LimitCORE=0`.
- Restrict SSH user certificates. The gateway always rejects SSH
  certificates regardless of `ssh.allow_ssh_certificates`; keep that
  value `false` in config.

### Network

- Expose only the SSH listener externally. The shipped container
  command publishes port 2222 to all host interfaces and binds
  metrics (`9090`) and health (`9091`) to host loopback only.
- In Kubernetes, expose port 22 on a `LoadBalancer` Service that maps
  to in-pod 2222; keep metrics and health cluster-internal.
- Permit egress to the Coder API URL plus DERP relays (and direct UDP
  peers if your Coder deployment uses them). Restricted egress
  silently breaks workspace connections.
- If you terminate SSH behind a load balancer that speaks PROXY v1,
  enable `listen.proxy_protocol` and restrict the Service to the
  balancer's source ranges. The gateway never auto-detects PROXY
  headers; with the option off, PROXY bytes are ignored and the socket
  peer is used.

### Storage and secrets

- Keep records under one `<state-dir>` with mode `0700` owned by the
  service user. Record files are mode `0600`, set with explicit chmod
  (umask-independent).
- Back up the state directory and `secrets/` **separately, to
  separately restricted storage**. State without the encryption key
  recovers nothing. The key without state identifies nothing. Together
  they recover everything — so they must NEVER share a backup bucket.
  Procedure: [Operator Guide → Backup and restore](./docs/operator-guide.md#backup-and-restore).
- Keep the encryption key off the volume that holds the encrypted data.
  Encryption at rest is only meaningful when the key is not stored next
  to the records it protects. In containers, prefer an `env:VARNAME`
  key source injected from a runtime Secret (the Helm chart does this
  by default); the Helm chart additionally keeps generated keys across
  upgrades and uninstalls so a re-install never orphans stored tokens.
- Treat the host key file and the credential encryption key as
  long-lived credentials. Rotate the host key on a schedule and on
  personnel change; rotate the encryption key when an operator with
  access leaves.
- Never put tokens on argv or in environment variables. The
  out-of-band enrollment flow pipes the token through stdin; nothing
  else is acceptable.
- Disable telemetry to Coder unless you explicitly want it. The
  default `deployment.network.disable_coder_telemetry: true` sets
  `CODER_DISABLE_NETWORK_TELEMETRY=1` for spawned CLI processes.

### Authentication policy

- Decide whether to enable `enrollment.enabled`. Token-anchored
  self-enrollment is the default and the simplest onboarding. Disable
  it for closed memberships where only out-of-band provisioning is
  permitted; the `init` username then rejects byte-identically to any
  unknown username.
- Treat the host-key fingerprint as a credential that requires an
  out-of-band channel to publish. Operators publish the fingerprint
  before users connect; users pin it in `known_hosts` before
  answering `yes`.
- The gateway accepts only public-key authentication on the SSH
  listener. There is no password login surface. Do not front it with
  anything that exposes a password path.
- Treat every wrong-identity token submission as a security event.
  The gateway audits `AUTH_WRONG_CODER_IDENTITY` and refuses further
  attempts on the same connection; alert on repeated rejections.

### Logging and monitoring

- Forward `<state-dir>/audit/audit-YYYY-MM-DD.jsonl` to your log
  pipeline. Audit events are append-oriented JSONL with one file per
  day; token-shaped values are redacted before write.
- Scrape Prometheus metrics on `observability.metrics_address`
  (default `127.0.0.1:9090`). The shipped metrics include
  `coder_ssh_gateway_enrollments_total{result}` — alert on
  rejections, not just on successes.
- Probe `/livez` and `/readyz` on `observability.health_address`
  (default `127.0.0.1:9091`). `/livez` means the process and store
  lock are healthy; `/readyz` additionally means the deployment
  config is usable.

## Incident response

If you suspect compromise of the gateway host, the encryption key, or
a stored token, follow this checklist.

### 1. Contain

- Stop the gateway immediately to release the state lock and prevent
  further credential reads:
  ```bash
  sudo systemctl stop coder-ssh-gateway
  # or
  kubectl -n coder-ssh-gateway scale deploy/coder-ssh-gateway --replicas=0
  ```
- Quarantine the host. Snapshot the filesystem for forensics before
  any cleanup.

### 2. Rotate the encryption key

Generate a new 32-byte key and place it as
`<state-dir>/secrets/credential-key-vN`. Add the entry under
`encryption.keys` alongside the old ID, set `encryption.active_key_id`
to the new ID, and restart. **As long as the old key ID stays listed
under `encryption.keys`, stored tokens encrypted with the old key
continue to decrypt** — rotation by itself does not break existing
records. Credentials only become unreadable if the old key ID is
removed from `encryption.keys` while records still reference it, or if
the key file is lost. Verify with `doctor`: the encryption-key check
must PASS. Procedure:
[Operator Guide → Encryption-key rotation](./docs/operator-guide.md#encryption-key-rotation).

### 3. Rotate the host key

Generate a new Ed25519 host key (`ssh-keygen -t ed25519 -f
ssh_host_ed25519_key.new -N ''`) and add the new path to
`ssh.host_keys`. Publish the new fingerprint out-of-band; users update
their `known_hosts` records and pin the new fingerprint. Verify with
`doctor`: it fingerprints every configured key.

### 4. Revoke tokens

For each affected Coder user, revoke the existing session token in
Coder (the gateway holds encrypted copies; revoking at Coder is the
authoritative action). Have users reconnect through the maintenance
user and paste fresh tokens. Verify: the revoked token is rejected at the
next workspace connect (`AUTH_CREDENTIAL_UNAUTHORIZED` in the audit log).
Procedure:
[Client Setup → Credential maintenance](./docs/client-setup.md#credential-maintenance).

### 5. Investigate

- Pull `<state-dir>/audit/audit-YYYY-MM-DD.jsonl` for the relevant
  window. Look for repeated `ssh_auth_rejected`,
  `enrollment_rejected`, and `ssh_wrong_user_token` events.
- Inspect `account_id`, `peer_address`, `connection_id`, and
  `credential_generation` to scope the impact.
- Check whether the encryption key file was modified (timestamp,
  hash) — its file path is in `<state-dir>/secrets/` and its content
  should match your secret backup.

### 6. Restore

Restore from your separately-stored state and secrets backups, only
after confirming the backups themselves were not touched. Procedure:
[Operator Guide → Restore](./docs/operator-guide.md#restore).

## Assets and threats

### Assets

- Coder bearer tokens (stored encrypted, per account)
- Gateway outer host private key
- Registered user public-key mappings
- Credential encryption key(s)
- Account-to-Coder-UUID bindings
- The workspace access path itself
- Audit integrity
- Service availability

### Threats and mitigations

| Threat | Mitigations | Residual risk |
| --- | --- | --- |
| Internet client without an approved key | Public-key-only first factor; no top-level password/token login; handshake and per-IP rate limits; safe SSH algorithm set; byte-identical generic rejection for unknown key, wrong username, disabled account, and certificates (no existence oracle). | Scanning cost is bounded by limits, not eliminated. |
| Stolen approved SSH private key | Fast key disable/revocation (`admin key disable`); per-account connection limits; full audit trail. | Attacker can ride a still-valid stored Coder token until the key is disabled; token replacement in maintenance mode additionally requires a valid token for the SAME bound Coder UUID. |
| Token for the wrong Coder account | Immutable Coder user UUID comparison before storage; wrong-identity submissions are audited as security events (`ssh_wrong_user_token`); no username-only binding. | Operator mis-binding at enrollment. |
| State-dir (backup) theft | AES-256-GCM envelope encryption with per-write random nonce; AAD binds deployment, account, and generation so ciphertexts cannot be transplanted; encryption key stored separately from records; 0600/0700 permissions; backup separation mandated. | A backup of the state dir PLUS the encryption key yields all stored tokens. Restrict access to both. |
| Gateway host compromise | Minimal host/container image; non-root service; read-only root filesystem; dropped capabilities; pinned and checksummed CLI; disabled core dumps; no public pprof; systemd sandboxing. | Mitigations reduce probability, NOT impact. A compromised gateway can decrypt stored tokens, alter the CLI, proxy or substitute workspace sessions, and capture newly entered tokens. Treat the gateway as a high-value credential broker and defend it accordingly. |
| Command injection via workspace hostname | Strict one-to-three-label grammar on bare targets and port 22 only; argv construction with no shell; no user-controlled flags or environment for the child process. | None known. |
| Arbitrary network proxy abuse | `direct-tcpip` targets are never passed to `net.Dial`; only strict bare Coder targets on port 22 reach `coder ssh`; reverse and global forwarding rejected. | None known. |
| Inner protocol data leakage | Child stdout isolated from stderr; no packet logging or payload capture; metrics carry byte counts only; bounded, token-redacting stderr ring. | A compromised gateway can alter or terminate the stream; the inner SSH layer is trusted to detect tampering at its own boundary. |
| Denial of service | Admission semaphores across connections, handshakes, channels, and child processes; token-bucket rate limits (pre-auth per-IP, renewal per-account); bounded inputs and stderr; handshake deadlines; process-group kill escalation and reaping; global child cap; no unbounded goroutines. | Determined attackers can still consume the configured capacity; limits trade availability for containment. |
| Credential-replacement race | Generation compare-and-set on every replace/clear; per-account serialization; validate-before-store ordering; wrong-generation writes never overwrite. | None known. |
| Self-enrollment abuse (`login@`) | Token possession IS enrollment authority: a presented Coder token anchors the account identity (Coder user UUID from `/api/v2/users/me`), and proof of key possession is required before any token prompt. Per-IP pre-token rate gate plus per-connection/per-account attempt bounds; cross-account key conflicts hard-rejected before any mutation; every outcome audited (`enrollment_success`/`enrollment_rejected`) and counted (`coder_ssh_gateway_enrollments_total`); disabled usernames reject byte-identically to unknown usernames. | A stolen valid Coder token can enroll the attacker's key into the victim's gateway account — the same blast radius as the stolen token itself (the token already impersonates the victim against Coder). Rate limits bound attempts; audit events expose them. For closed memberships, set `enrollment.enabled: false` and enroll out-of-band only. |
| Stale invalidation race | Credentials are marked invalid only when the generation still matches. | None known. |
| Secret leakage through diagnostics | Tokens never in argv; strict, enumerated log fields; token redaction in audit and child stderr; disabled core dumps; environment allowlist for child processes. | Go cannot guarantee erasure of copied strings or GC'd buffers; process memory access equals credential compromise. |

## Storage security notes

- All state lives under one `--state-dir`. Record files are mode 0600,
  directories 0700, applied with explicit chmod (umask-independent).
- Every mutation is write-temp, fsync, rename, fsync(dir); a crash
  leaves either the old or the new record, never a partial one.
- An exclusive `flock(2)` on `<state-dir>/lock` is held for the
  process lifetime (Linux-only). A second process fails fast. This is
  why deployments are single-replica and admin commands cannot
  overlap with a running server.
- Credential plaintext never persists: records store key version,
  nonce, and AES-256-GCM ciphertext only. The encryption key lives
  under `secrets/` (or an external mount), never inside a record.
- Audit logs are append-oriented JSONL, one file per day, with
  token-shaped values redacted before write.
- Go memory hygiene is best-effort: plaintext buffers are wiped where
  owned, but the runtime offers no erasure guarantee. Core dumps are
  disabled in the shipped systemd unit for this reason.

## Reporting a vulnerability

Please do not open public issues for security reports.

- Email: <security contact TBD — see the repository maintainer>
- Include: affected version/commit, reproduction steps, and impact.
- You can expect an acknowledgment within 72 hours.

Until a dedicated contact is published, report privately to the
repository maintainer through GitHub's private vulnerability reporting
if enabled on the repository.
