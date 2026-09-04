# Security — coder-ssh-gateway

Unofficial community project; not affiliated with Coder. This document
summarizes the threat model (design section 36), the storage security
model, and how to report vulnerabilities.

## Assets

- Coder bearer tokens (stored encrypted, per account);
- gateway outer host private key;
- registered user public-key mappings;
- credential encryption key(s);
- account-to-Coder-UUID bindings;
- the workspace access path itself;
- audit integrity;
- service availability.

## Threats and mitigations

| Threat | Mitigations | Residual risk |
| --- | --- | --- |
| Internet client without an approved key | Public-key-only first factor; no top-level password/token login; handshake and per-IP rate limits; safe SSH algorithm set; byte-identical generic rejection for unknown key, wrong username, disabled account, and certificates (no existence oracle). | Credential stuffing is impossible (no password surface); scanning cost is bounded by limits, not eliminated. |
| Stolen approved SSH private key | Fast key disable/revocation (`admin key disable`); per-account connection limits; full audit trail. | Attacker can ride a still-valid stored Coder token until the key is disabled; token replacement in maintenance mode additionally requires a valid token for the SAME bound Coder UUID. |
| Token for the wrong Coder account | Immutable Coder user UUID comparison before storage; wrong-identity submissions are audited as security events (`ssh_wrong_user_token`); no username-only binding. | None known beyond operator mis-binding at enrollment. |
| State-dir (backup) theft | AES-256-GCM envelope encryption with per-write random nonce; AAD binds deployment, account, and generation so ciphertexts cannot be transplanted; encryption key stored separately from records; 0600/0700 permissions; backup separation mandated (section 22.4). | A backup of the state dir PLUS the encryption key yields all stored tokens. Restrict access to both. |
| Gateway host compromise | Minimal host/container image; non-root service; read-only root filesystem; dropped capabilities; pinned and checksummed Coder CLI; disabled core dumps; no public pprof; systemd sandboxing (section 31.1). | Mitigations reduce probability, NOT impact. A compromised gateway can decrypt stored tokens, alter the CLI, proxy or substitute workspace sessions, and capture newly entered tokens. Treat the gateway as a high-value credential broker and defend it accordingly. |
| Command injection via workspace hostname | Strict DNS-label grammar on targets; exact suffix and port 22 only; argv construction with no shell; no user-controlled flags or environment for the child process. | None known. |
| Arbitrary network proxy abuse | `direct-tcpip` targets are never passed to `net.Dial`; only exact workspace-suffix names on port 22 reach `coder ssh`; reverse and global forwarding rejected. | None known. |
| Inner protocol data leakage | Child stdout isolated from stderr; no packet logging or payload capture; metrics carry byte counts only; bounded, token-redacting stderr ring. | A compromised gateway can alter or terminate the stream; the inner SSH layer is trusted to detect tampering at its own boundary (section 6.3). |
| Denial of service | Admission semaphores across connections, handshakes, channels, and child processes; token-bucket rate limits (pre-auth per-IP, renewal per-account); bounded inputs and stderr; handshake deadlines; process-group kill escalation and reaping; global child cap; no unbounded goroutines. | Determined attackers can still consume the configured capacity; limits trade availability for containment. |
| Credential-replacement race | Generation compare-and-set on every replace/clear; per-account serialization; validate-before-store ordering; wrong-generation writes never overwrite. | None known. |
| Stale invalidation race | Credentials are marked invalid only when the generation still matches. | None known. |
| Secret leakage through diagnostics | Tokens never in argv; strict, enumerated log fields; token redaction in audit and child stderr; disabled core dumps; environment allowlist for child processes. | Go cannot guarantee erasure of copied strings or GC'd buffers (section 22.5); process memory access equals credential compromise. |

## Flat-file storage security notes

- All state lives under one `--state-dir`. Record files are mode 0600,
  directories 0700, applied with explicit chmod (umask-independent).
- Every mutation is write-temp, fsync, rename, fsync(dir); a crash leaves
  either the old or the new record, never a partial one.
- An exclusive `flock(2)` on `<state-dir>/lock` is held for the process
  lifetime (Linux-only). A second process fails fast. This is why
  deployments are single-replica and admin commands cannot overlap with a
  running server.
- Credential plaintext never persists: records store key version, nonce,
  and AES-256-GCM ciphertext only. The encryption key lives under
  `secrets/` (or an external mount), never inside a record.
- Audit logs are append-oriented JSONL, one file per day, with token-shaped
  values redacted before write.
- Backup discipline (section 22.4): back up the state dir and `secrets/`
  separately, into separately restricted storage. State without the key
  recovers nothing; the key without the state identifies nothing; together
  they recover everything.
- Go memory hygiene is best-effort (section 22.5): plaintext buffers are
  wiped where owned, but the runtime offers no erasure guarantee. Core
  dumps are disabled in the shipped systemd unit for this reason.

## Reporting a vulnerability

Please do not open public issues for security reports.

- Email: <security contact TBD — see the repository maintainer>
- Include: affected version/commit, reproduction steps, and impact.
- You can expect an acknowledgment within 72 hours.

Until a dedicated contact is published, report privately to the repository
maintainer through GitHub's private vulnerability reporting if enabled on
the repository.
