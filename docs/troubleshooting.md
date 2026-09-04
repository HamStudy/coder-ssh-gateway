# Troubleshooting — stable error codes

The gateway reports failures with stable detail codes (design section 44) so
support instructions never depend on raw Coder CLI messages. Codes appear in
structured logs and audit events as `detail_code`; useful companion fields
are `connection_id`, `peer_address`, `account_id`, `ssh_key_id`, `target`,
`credential_generation`, and `event_type`.

The `doctor` column names the check that applies; run it as
`coder-ssh-gateway --state-dir <dir> doctor [--account <uuid>]
[--probe-workspace <name>]`. `doctor` exits 1 only on a local FAIL; an
unreachable Coder deployment is WARN.

"New token helps?" means: can the user fix this by entering a fresh Coder
session token (renewal prompt or `ssh auth@<gateway>` maintenance session)?

## AUTH_* — authentication and credential validation

### AUTH_UNKNOWN_KEY
- **Likely cause:** the presented SSH key is not registered, is disabled,
  belongs to a different deployment, or is an SSH certificate while
  certificates are disabled. The outward rejection is deliberately generic
  (no key-existence oracle, section 35), so this one code covers all of
  these.
- **Retry safe?** Yes, but retrying with the same key changes nothing.
- **New token helps?** No. The client never reaches credential validation.
- **Log fields:** `event_type=ssh_auth_rejected`, `peer_address`,
  `connection_id`.
- **Fix:** verify the key is registered (`admin key list --account UUID`)
  and enabled; register it with `admin key add`.
- **Doctor:** not applicable (key registration is state, not health).

### AUTH_ACCOUNT_DISABLED
- **Likely cause:** the gateway account was disabled by an administrator.
- **Retry safe?** Yes, but futile until the account is re-enabled.
- **New token helps?** No.
- **Log fields:** `event_type=ssh_auth_rejected`, `account_id`,
  `peer_address`.
- **Fix:** `admin account enable --account UUID` (investigate why it was
  disabled first).
- **Doctor:** `doctor --account UUID` reports credential state; enablement
  shows in `admin account list`.

### AUTH_CREDENTIAL_MISSING
- **Likely cause:** no token stored for the account (never enrolled, or
  cleared). The user gets a renewal continuation after key auth.
- **Retry safe?** Yes. This is the normal first-enrollment and post-clear
  path.
- **New token helps?** Yes; that is the entire point of this state. Paste a
  fresh token at the prompt or in the maintenance session.
- **Log fields:** `event_type=ssh_credential_renewal`, `account_id`,
  `credential_generation`.
- **Doctor:** `doctor --account UUID` shows credential state `missing`.

### AUTH_CREDENTIAL_UNAUTHORIZED
- **Likely cause:** Coder answered 401: the stored token expired or was
  revoked.
- **Retry safe?** Yes. The stored credential is marked `invalid`; the user
  is offered renewal.
- **New token helps?** Yes. Renewal (automatic continuation or maintenance
  session) replaces the credential.
- **Log fields:** `event_type=ssh_credential_renewal` or
  `ssh_auth_rejected`, `account_id`, `credential_generation`.
- **Doctor:** `doctor --account UUID` revalidates the stored credential and
  reports `invalid`.

### AUTH_CREDENTIAL_FORBIDDEN
- **Likely cause:** Coder answered 403: the token is valid but the account
  lost permission (role change, suspension, license).
- **Retry safe?** The connection fails cleanly; retrying with the same
  token is futile. No automatic renewal is offered (section 11.4).
- **New token helps?** Usually no. A 403 means the Coder deployment refuses
  this identity, not this token. Resolve the account's standing in Coder
  first; a new token only helps after that.
- **Log fields:** `event_type=ssh_auth_rejected`, `account_id`.
- **Doctor:** `doctor --account UUID` classifies the stored credential.

### AUTH_WRONG_CODER_IDENTITY
- **Likely cause:** the submitted token belongs to a different Coder user
  than the account's bound UUID (wrong token pasted, or first-bind
  collision). Audited as a security event (`ssh_wrong_user_token`).
- **Retry safe?** The gateway does not offer another attempt for this
  error. Treat as a security signal, not a typo loop.
- **New token helps?** Only a token for the CORRECT Coder user; repeated
  wrong-user submissions are a red flag.
- **Log fields:** `event_type=ssh_wrong_user_token`, `account_id`,
  `peer_address`.
- **Doctor:** `doctor --account UUID` compares the stored credential's
  identity with the binding.

### AUTH_CODER_UNAVAILABLE
- **Likely cause:** Coder API unreachable: DNS, TLS, connect, timeout, 429,
  or 5xx. Classified retryable; the gateway never marks the credential
  invalid on this code.
- **Retry safe?** Yes. Nothing in local state changed; retry after Coder
  recovers.
- **New token helps?** No.
- **Log fields:** `event_type=ssh_auth_rejected` (or a failed channel
  open), `target`, `account_id`.
- **Fix:** check Coder deployment health, egress policy (section 31.5:
  API, proxies, DERP, DNS must all pass), TLS CA config.
- **Doctor:** `coder-tls`, `coder-buildinfo` checks. WARN (not FAIL) when
  Coder is unreachable.

### AUTH_CODER_INCOMPATIBLE
- **Likely cause:** Coder answered 404 on `/api/v2/users/me`, returned a
  malformed success body, or redirected (detail code suffix `:redirect`).
  The deployment is too old, is not Coder, or a proxy is mangling the API.
- **Retry safe?** The connection fails cleanly, but retrying changes
  nothing until the deployment is fixed.
- **New token helps?** No.
- **Log fields:** `event_type=ssh_auth_rejected`, `account_id`.
- **Fix:** verify `deployment.coder_url`, upgrade Coder, inspect
  intermediaries (proxies must pass the API path verbatim).
- **Doctor:** `coder-buildinfo`, `coder-binary` (CLI/server version match).

## ROUTE_* — workspace target validation

### ROUTE_INVALID_PAYLOAD
- **Likely cause:** malformed `direct-tcpip` payload (unparseable host
  field, empty host, lone root dot). Usually a non-OpenSSH client or an
  attack probe.
- **Retry safe?** Yes, with a corrected client command.
- **New token helps?** No.
- **Log fields:** `peer_address`, `connection_id`; the raw payload is never
  logged.
- **Doctor:** not applicable; this is client-side input.

### ROUTE_SUFFIX_DENIED
- **Likely cause:** the requested host is not under the configured
  `deployment.target_suffix` (label-boundary match required). Typos,
  wrong suffix, or proxy-abuse attempts land here.
- **Retry safe?** Yes, with a target under the correct suffix.
- **New token helps?** No.
- **Log fields:** `target` (the normalized display target only).
- **Fix:** use `<workspace>.<target_suffix>`, e.g.
  `dev.coder-gateway.example.com`.
- **Doctor:** `target-suffix` check validates the configured suffix.

### ROUTE_PORT_DENIED
- **Likely cause:** the client requested a port other than 22. The gateway
  proxies workspace SSH only.
- **Retry safe?** Yes, with port 22.
- **New token helps?** No.
- **Log fields:** `target`, `connection_id`.
- **Fix:** `ssh -J ... user@host` targets port 22 implicitly; explicit
  `-W host:PORT` must use 22.
- **Doctor:** not applicable.

### ROUTE_NAME_INVALID
- **Likely cause:** the target under the suffix violates the strict DNS
  grammar: wrong label count (1–3 allowed), label length over 63, illegal
  characters, punycode (`xn--`), non-ASCII, or total length over 253 bytes.
- **Retry safe?** Yes, with a valid workspace name.
- **New token helps?** No.
- **Log fields:** `target`.
- **Fix:** use the workspace's real name (lowercase, hyphens, digits).
- **Doctor:** `target-suffix` (config side only; per-name failures are
  client input).

## TUNNEL_* — workspace channel lifecycle

### TUNNEL_LIMIT_REACHED
- **Likely cause:** an admission semaphore is full: global connections,
  per-IP, per-key, per-account, channels, or `coder_processes`.
- **Retry safe?** Yes; retry once other connections close.
- **New token helps?** No.
- **Log fields:** `account_id`, `peer_address`, `connection_id`.
- **Fix:** find the holder (`admin disconnect --account UUID` for a
  runaway account) or raise the relevant `limits.*` field.
- **Doctor:** `process-limits` check reports configured vs. system limits.

### TUNNEL_PROCESS_START_FAILED
- **Likely cause:** the Coder CLI failed to spawn: bad
  `deployment.coder_binary` path, missing global-config dir, sandbox
  blocking exec.
- **Retry safe?** Yes, after fixing the spawn environment.
- **New token helps?** No.
- **Log fields:** `event_type=tunnel_start`, `result=failure`, `target`.
- **Fix:** verify the binary path and permissions; check systemd hardening
  (ProtectSystem, NoNewPrivileges) is not blocking the CLI.
- **Doctor:** `coder-binary`, `writable-dirs`.

### TUNNEL_START_TIMEOUT
- **Likely cause:** the spawned CLI produced no stdout byte within the
  startup timeout: workspace autostart taking too long, network blockage to
  DERP/proxies, or a hung CLI.
- **Retry safe?** Yes. If the workspace was autostarting, the next attempt
  usually connects faster.
- **New token helps?** No (a genuinely expired token is classified
  separately; see TUNNEL_CODER_EXITED).
- **Log fields:** `event_type=tunnel_start`, `target`,
  `credential_generation`; bounded child stderr tail in logs (redacted).
- **Fix:** check workspace status in Coder; validate egress per section
  31.5; raise `deployment.workspace_connect_timeout` for slow templates.
- **Doctor:** `--probe-workspace NAME` exercises this path end to end.

### TUNNEL_CODER_EXITED
- **Likely cause:** the CLI process exited before or during streaming.
  Common root cause: the stored token failed at the Coder layer after outer
  auth succeeded (section 19.8). The gateway rechecks the credential after
  this failure and marks it invalid on a 401, so the NEXT connection offers
  renewal.
- **Retry safe?** Yes. The post-failure recheck has already classified the
  credential.
- **New token helps?** Often yes: if the recheck marked the credential
  invalid, reconnect and complete the renewal prompt.
- **Log fields:** `event_type=tunnel_start`, `result=failure`, `target`,
  `credential_generation`; stderr tail (redacted).
- **Doctor:** `doctor --account UUID` shows the credential state after
  recheck; `--probe-workspace` for live diagnosis.

### TUNNEL_STREAM_FAILED
- **Likely cause:** mid-stream I/O error after the tunnel was up: network
  flap between gateway and Coder, relay drop, workspace restart.
- **Retry safe?** Yes; reconnect.
- **New token helps?** No.
- **Log fields:** `connection_id`, `target`, `duration_ms`, `bytes_up`,
  `bytes_down`.
- **Fix:** inspect network path (DERP relay health, direct UDP blocking per
  section 31.5).
- **Doctor:** `--probe-workspace` for a live path test.

### TUNNEL_CANCELLED
- **Likely cause:** the tunnel ended by policy, shutdown drain, client
  disconnect with a hung child (lingering past grace), or context
  cancellation. Frequently benign: a client closing its last channel shows
  here.
- **Retry safe?** Yes.
- **New token helps?** No.
- **Log fields:** `connection_id`, `target`, `duration_ms`.
- **Fix:** none needed for client-initiated closes; for shutdown-related
  cancellations, see the drain configuration (section 32).
- **Doctor:** not applicable.

## STORE_* / CRYPTO_* — state and encryption

### STORE_UNAVAILABLE
- **Likely cause:** the state dir is locked by another process (a second
  `serve` or a concurrent admin command: the flock is exclusive), a record
  is corrupt (JSON unmarshal failure), the VERSION file mismatches, or a
  uniqueness constraint was hit (duplicate key digest, duplicate bound
  Coder user).
- **Retry safe?** For lock conflicts, yes: wait for the other process or
  stop it. For corruption, no: restore from backup.
- **New token helps?** No.
- **Log fields:** `event_type` varies; look for store errors at startup or
  during admin operations.
- **Fix:** `fuser <state-dir>/lock` to find the holder; never run two
  gateway processes on one state dir; restore corrupt records from backup.
- **Doctor:** `state-dir` check (VERSION + flock probe).

### STORE_GENERATION_CONFLICT
- **Likely cause:** a compare-and-set lost a race: two concurrent credential
  replacements for the same account, or an admin `credential clear` against
  a stale generation. The loser sees this code; the winner's write stands.
- **Retry safe?** Yes. Retry the operation; it re-reads the current
  generation. During SSH renewal the conflict resolves itself as "already
  updated" and the client is told to reconnect.
- **New token helps?** Not directly; the conflict means someone already
  stored one.
- **Log fields:** `account_id`, `credential_generation`,
  `event_type=ssh_credential_renewal`.
- **Doctor:** `doctor --account UUID` shows the current generation.

### CRYPTO_KEY_UNAVAILABLE
- **Likely cause:** the encryption key file is missing, unreadable, wrong
  length (not 32 bytes raw or base64), or no key provider is configured.
  Startup and credential operations fail closed.
- **Retry safe?** No; fix the key material first.
- **New token helps?** No.
- **Log fields:** startup errors naming the key ID and path (never key
  material).
- **Fix:** restore `secrets/credential-key-<id>` from your separate secret
  backup; confirm mode 0600 and ownership; confirm
  `encryption.active_key_id` names a listed key.
- **Doctor:** `encryption-key` check (seal/open self-test).

### CRYPTO_DECRYPT_FAILED
- **Likely cause:** AES-GCM authentication failure on a stored credential:
  wrong key for the record's `key_version` (key rotated away too early,
  restored from a mismatched backup), or a tampered/transplanted ciphertext
  (AAD binds deployment, account, and generation). Fails closed; the
  credential is never used.
- **Retry safe?** No; decryption will fail identically until the correct
  key is present.
- **New token helps?** Yes, as recovery: `admin credential clear --account
  UUID` tombstones the undecryptable record, then the user enrolls a fresh
  token. The old ciphertext is unrecoverable without its key.
- **Log fields:** `account_id`, `credential_generation`; key ID only,
  never material.
- **Fix:** restore the key matching the record's `key_version` into
  `encryption.keys` (old IDs stay decryptable while listed). If the key is
  lost, clear and re-enroll affected accounts.
- **Doctor:** `encryption-key` self-test, `doctor --account UUID`. Note the
  self-test only proves the active key loads and round-trips; a WRONG key
  passes it too. The `--account` check is the one that decrypts a real
  record and exposes the mismatch.
