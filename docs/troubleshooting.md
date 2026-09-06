# Troubleshooting

Start with the symptom you're seeing. Each entry names the most likely
cause, what to try first, and where to look for confirmation. Stable
detail codes that show up in audit events and structured logs are
listed in [Detail codes](#detail-codes) at the bottom — match the code
you're seeing against the table for the exact failure path.

## What are you seeing?

- **"Connection refused" on the gateway port** — [Connection refused](#connection-refused)
- **"Connection timed out"** — [Connection timed out](#connection-timed-out)
- **"Permission denied (publickey)" or no auth methods left** —
  [Authentication rejected](#authentication-rejected)
- **"Host key verification failed"** — [Host key mismatch](#host-key-mismatch)
- **`ssh` hangs after the gateway banner** — [Hangs after banner](#hangs-after-banner)
- **Workspace connection drops mid-session** — [Workspace drops mid-session](#workspace-drops-mid-session)
- **`ssh: Could not resolve hostname` for the workspace** — [Workspace name not accepted](#workspace-name-not-accepted)
- **"No supported methods remain" after key was already accepted** —
  [Token expired](#token-expired)
- **`init@` rejected even though you typed a valid token** —
  [Self-enrollment rejected](#self-enrollment-rejected)
- **`doctor` reports FAIL** — [`doctor` FAIL](#doctor-fail)
- **`doctor` reports WARN, not FAIL** — [`doctor` WARN](#doctor-warn)
- **Container or Kubernetes pod won't start** —
  [Service won't start](#service-wont-start)

---

## Connection refused

What you're seeing: `ssh: connect to host gateway.example.com port 2222: Connection refused`.

Most likely cause: the gateway is not listening on that port, or
something is filtering traffic to it.

Try this in order:

1. **Is the gateway process running?** On systemd: `systemctl status
   coder-ssh-gateway`. On Docker: `docker ps | grep coder-ssh-gateway`.
   On Kubernetes: `kubectl -n coder-ssh-gateway get pods`.
2. **What port is it actually listening on?** From the gateway host:
   `ss -lntp | grep -E ':(22|2222)\b'`. The configured
   `listen.address` is `listen.address` in `config.yaml`; if it says
   `:2222`, that is the port you should connect to.
3. **Is a firewall in the way?** On the host:
   `sudo iptables -L -n | grep 2222` (or the equivalent for
   `nft`/`firewalld`/cloud security groups). On Kubernetes, check the
   Service and the LB security group: `kubectl -n coder-ssh-gateway
   describe svc coder-ssh-gateway`.
4. **Did you forget the port on the client side?** Native installs
   listen on `2222`, not `22`. If `ssh gateway.example.com` returns
   "Connection refused" but `ssh -p 2222 gateway.example.com` works,
   the issue is the client, not the gateway.

---

## Connection timed out

What you're seeing: `ssh: connect to host gateway.example.com port 2222: Connection timed out`.

Most likely cause: traffic is being dropped before it reaches the
gateway, or DNS is not resolving.

1. **DNS first.** `dig gateway.example.com` (or `nslookup`,
   `getent hosts gateway.example.com`). A wrong or missing A/AAAA
   record is the common cause.
2. **Path to the gateway.** `traceroute gateway.example.com` (or
   `mtr -rwc 30 gateway.example.com`). The timeout point tells you
   which segment is dropping the traffic.
3. **Cloud security groups / NACLs.** Public cloud gateways usually
   need port 22 (or 2222) explicitly opened to your source CIDR.
4. **Kubernetes LoadBalancer.** Confirm the LB was provisioned and is
   healthy: `kubectl -n coder-ssh-gateway get svc coder-ssh-gateway`.
   A `Pending` `EXTERNAL-IP` means the LB never came up.

---

## Authentication rejected

What you're seeing: `Permission denied (publickey).` or `no supported
methods remain` immediately after `ssh` connects.

Most likely cause: the SSH key is not registered, is disabled, or the
gateway account is disabled. The outward message is intentionally
generic — the gateway does not differentiate between "unknown key" and
"wrong username" or "disabled account" so it cannot be used as an
existence oracle.

1. **Operator check (if you are the user).** Ask your operator to
   confirm your account exists and is enabled. On a systemd host the
   operator stops `serve` first (admin and serve compete for the
   exclusive state lock), runs the admin command as the service user,
   then restarts `serve`:

   ```bash
   sudo systemctl stop coder-ssh-gateway
   sudo -u coder-ssh-gateway \
     coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway admin account list
   sudo systemctl start coder-ssh-gateway
   ```

   Look for your label; the `enabled` column must be true.
2. **Key check.** Same stop/run/restart lifecycle as above:

   ```bash
   sudo systemctl stop coder-ssh-gateway
   sudo -u coder-ssh-gateway \
     coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway \
       admin key list --account <uuid>
   sudo systemctl start coder-ssh-gateway
   ```

   Match the registered fingerprint against `ssh-keygen -lf
   ~/.ssh/coder-gateway.pub`.
3. **Did the key get disabled?** A registered key can be disabled
   without removing it. Re-enable with `admin key enable --key UUID`.
4. **Self-enrollment still available?** If you see this on `init@`,
   and your key is not yet registered, run the normal
   `ssh coder-gateway-init` flow instead — see
   [Client Setup → Initial enrollment](./client-setup.md#initial-enrollment-the-one-time-step).
5. **Audit log.** The gateway logs every rejection with a stable
   detail code under `<state-dir>/audit/audit-YYYY-MM-DD.jsonl`. Ask
   your operator for the most recent entry with `event_type=
   ssh_auth_rejected`; the `detail_code` column tells you exactly why.

See [Detail codes → AUTH_UNKNOWN_KEY](#auth_unknown_key) and
[AUTH_ACCOUNT_DISABLED](#auth_account_disabled).

---

## Host key mismatch

What you're seeing: `Host key verification failed.` on a target that
previously connected fine.

Most likely cause: the gateway's host key changed — typically because
the operator rotated the host key, or because you are connecting to a
different gateway than you thought.

1. **Confirm with your operator.** Ask whether the host key was
   rotated, and what the new fingerprint is. Compare against
   `ssh-keygen -lf <(ssh-keyscan -p 2222 gateway.example.com 2>/dev/null)`.
2. **If rotation was planned, update your `known_hosts`**:
   `ssh-keygen -R "[gateway.example.com]:2222"` and reconnect. Pin the
   new fingerprint only after confirming it with your operator.
3. **If you are connecting to the inner workspace agent**, the inner
   key follows Coder's own behavior and may rotate more often than the
   gateway's outer key. See [Host keys: what you are trusting](./client-setup.md#host-keys-what-you-are-trusting).

---

## Hangs after banner

What you're seeing: `ssh` connects, prints the gateway banner (or
nothing), then hangs without a prompt.

Most likely cause: the gateway is waiting for follow-up input (token,
`yes` confirmation) but your client does not permit the follow-up
authentication methods.

1. **Are you trying to enroll or renew?** For enrollment, the gateway
   prompts for a Coder token via `keyboard-interactive` (with a
   password-method parity path for clients that do not render
   `keyboard-interactive`). The dedicated host block at
   [Client Setup → Initial enrollment](./client-setup.md#initial-enrollment-the-one-time-step)
   enables those methods. Without it, OpenSSH silently gives up after
   the public-key check.
2. **Same host block, different user.** Use the same
   `PreferredAuthentications publickey,keyboard-interactive,password`
   block for the maintenance user (`auth`), not just `init`.
3. **Check audit logs.** Look for
   `event_type=ssh_credential_renewal` or
   `event_type=enrollment_rejected` to confirm whether the gateway is
   offering the prompt or not.
4. **Moshi-specific.** Moshi does not honor `ssh_config` blocks.
   Configure `PreferredAuthentications` and the related methods
   directly in the saved connection. See
   [Moshi (iPad)](./client-setup.md#moshi-ipad).

---

## Workspace drops mid-session

What you're seeing: `ssh` to the workspace connects, you run a command
or two, then the connection drops or hangs.

Most likely cause: the Coder CLI process exited (often because the
stored token expired or the workspace went away), or a network issue
between the gateway and Coder.

1. **Did the stored token expire mid-session?** The gateway rechecks
   the credential after a tunnel failure; if it was 401 at Coder, the
   next connection offers renewal. Reconnect through the maintenance
   user to replace the token. See
   [Credential maintenance](./client-setup.md#credential-maintenance).
2. **Is the workspace still running?** Check Coder — a stopped or
   rebuilding workspace disconnects any SSH session.
3. **Is the gateway-to-Coder path healthy?** The gateway needs HTTPS
   to Coder plus DERP relays (and possibly direct UDP) reachable. From
   the gateway host: `curl -fsS https://coder.example.com/api/v2/buildinfo`
   for a quick reachability check.
4. **Audit log details.** The most common code is
   `TUNNEL_CODER_EXITED` (CLI exited) or `TUNNEL_STREAM_FAILED` (mid-
   stream I/O error). Both are listed in [Detail codes](#detail-codes).

---

## Workspace name not accepted

What you're seeing: `ssh: Could not resolve hostname dev: Name or service not known`,
or the gateway rejects the connection with a route error.

Most likely cause: the workspace name is misspelled, does not exist in
Coder, or the requested target is not a supported Coder target.

Note: a valid enrolled key authenticates first. If the username parsed
from the SSH request fails the workspace grammar, the gateway rejects
the channel **after** the key was accepted — there is no separate "wrong
username" branch and the rejection text does not reveal whether the key
was known.

1. **Use a bare Coder target.** The router accepts `workspace`,
   `workspace.agent`, or `agent.workspace.owner`. Four labels, hostnames,
   IP literals, and arbitrary destinations are rejected.
2. **Does the workspace exist in Coder?** `coder ls` from a session
   authenticated directly against Coder.
3. **DNS side.** The gateway does not require DNS for the workspace
   hostname — it forwards the bare target to `coder ssh --stdio`. If you are getting the error from your LOCAL
   `ssh` client (not the gateway), check your local DNS.
4. **Allowed grammar.** Workspace labels must be lowercase, start and
   end with `[a-z0-9]`, contain only `[a-z0-9-]`, and be 1–63 bytes.
   No punycode (`xn--`), no non-ASCII, total length ≤ 253 bytes.

See [ROUTE_NAME_INVALID](#route_name_invalid).

---

## Token expired

What you're seeing: the gateway accepted your key, then closed the
connection without completing the workspace channel.

Most likely cause: the stored Coder session token is missing or
expired. The gateway offers a renewal prompt after key auth when this
happens.

1. **Reconnect through the maintenance user** to paste a fresh token:
   ```bash
   ssh -p 2222 auth@gateway.example.com
   ```
   The prompt is hidden. Paste the new token from
   `https://coder.example.com/cli-auth`.
2. **If your client doesn't render the prompt**, use the dedicated
   host block from
   [Credential maintenance](./client-setup.md#credential-maintenance)
   and re-attempt.
3. **Moshi users:** open the **Coder Gateway Auth** saved connection
   instead of the workspace connection.

The detail codes are `AUTH_CREDENTIAL_MISSING`,
`AUTH_CREDENTIAL_UNAUTHORIZED`, and (less commonly)
`AUTH_CREDENTIAL_FORBIDDEN`. See [Detail codes](#detail-codes).

---

## Self-enrollment rejected

What you're seeing: `ssh coder-gateway-init` (using the configured
host alias from [Client Setup](./client-setup.md#initial-enrollment-the-one-time-step))
rejects your key, prompts you but then rejects the token, or reports
a generic "key already linked" error.

> A bare `ssh -p 2222 init@gateway.example.com` does not work for
> enrollment on a typical OpenSSH install: the gateway port must be
> pinned on the jump block, the non-default key must be selected by
> `IdentityFile`/`IdentitiesOnly`, and the follow-up token prompt
> requires `PreferredAuthentications publickey,keyboard-interactive,password`.
> All three of those are set on the `coder-gateway-init` host block;
> without that block, OpenSSH silently falls back to the wrong key,
> the wrong port, or a single-method auth that bails after the
> public-key check. Use the configured alias, not the bare command.

Possible causes and what to try:

1. **Key is already linked to a different account.** Generate a fresh
   per-device key (`ssh-keygen -t ed25519 -f ~/.ssh/coder-gateway`) and
   try again with that. Ask your operator to remove the stale
   registration if you cannot replace the key.
2. **Token was for a different Coder user than expected.** This applies
   only on a *re-enrollment* of a key already linked to an account, or
   on a renewal session. The token must be for the Coder user that
   account is bound to; a token for a different user is rejected as
   `AUTH_WRONG_CODER_IDENTITY` without mutation. Open a fresh token at
   `https://coder.example.com/cli-auth` while signed in as that user.
   On a *fresh* enrollment with a never-before-seen key there is no
   wrong-identity rejection: the first valid token anchors whichever
   Coder identity owns it.
3. **Self-enrollment is disabled.** Your operator may have turned off
   the `init@` flow. Ask them to either re-enable it
   (`enrollment.enabled: true`) or provision your account and key
   out-of-band — see
   [Operator Guide → Enrolling a user out-of-band](./operator-guide.md#enrolling-a-user-out-of-band).
4. **Rate limit hit.** Per-IP pre-token gate plus per-connection and
   per-account bounds. Wait a minute and retry. If rejections
   continue, alert your operator — repeated rejections are a security
   signal.

Audit event types: `enrollment_success`, `enrollment_rejected`, plus
detail codes from [AUTH_*](#auth_unknown_key).

---

## `doctor` FAIL

`doctor` exits non-zero only on a local FAIL. The summary line names
the failing check; the table below maps each one to a fix.

| Failing check | Likely cause | Fix |
| --- | --- | --- |
| `config-parse` | `config.yaml` has an unknown key, bad value, or wrong type | The failure line names the file and the offending key; fix that line, rerun `doctor` |
| `state-dir` | Missing `VERSION` file, mismatched version, or another process holds the flock | Confirm the state dir was initialized; confirm no other gateway/admin process is running |
| `encryption-key` | Key file missing, wrong length, or wrong permissions | Restore the key from your secrets backup; confirm mode 0600; confirm `encryption.active_key_id` names a listed key |
| `host-key` | No host keys load | Confirm `ssh.host_keys` points to readable, mode-0600 files; `init` should have generated one |
| `writable-dirs` | `audit/` or `coder-config/` not writable by the service user | `sudo chown -R coder-ssh-gateway:coder-ssh-gateway <state-dir>`; check filesystem mount |
| `process-limits` | Configured limits exceed system `nofile` / `nproc` | Lower the relevant `limits.*` field, or raise the systemd unit's `LimitNOFILE` / shell `ulimit -n` |

---

## `doctor` WARN

`doctor` exits zero even with WARNs — they are non-blocking. WARNs
should be fixed before opening the gateway to users.

| Warning check | Likely cause | Fix |
| --- | --- | --- |
| `coder-tls` | Cannot dial Coder over HTTPS | Check DNS, egress firewall, proxy config; confirm `deployment.coder_url` is correct and HTTPS |
| `coder-buildinfo` | Coder answered but `/api/v2/buildinfo` failed or returned incompatible shape | Confirm the URL points at a Coder deployment (not a proxy that mangles the path); upgrade Coder if older than supported |
| `coder-binary` | `deployment.coder_binary` not found or wrong version | Install the CLI matching the Coder server version; rerun `doctor` |
| `credentials` (`--account`) | Stored token fails Coder validation | Have the user reconnect through the maintenance user and paste a fresh token |

---

## Service won't start

What you're seeing: the gateway process exits immediately, the systemd
unit goes to `failed`, or the Kubernetes pod stays in
`CrashLoopBackOff`.

1. **Read the journal logs.** Native: `journalctl -u
   coder-ssh-gateway -n 200 --no-pager`. Docker: `docker logs
   coder-ssh-gateway`. Kubernetes: `kubectl -n coder-ssh-gateway logs
   -p coder-ssh-gateway-<id>`.
2. **Common causes.**
   - State directory not initialized — run `init` first.
   - `state.dir` mismatch — the config lives in one directory but
     `--state-dir` (or `state.dir`) points at another. Align two
     things at once: the store directory the binary selects, AND
     where the config's explicit relative host-key,
     encryption-key, coder-config, and working-directory paths
     resolve against. Moving just the config's location, or just
     the store directory, is not enough.
   - `secrets/` missing or wrong permissions — restore from backup
     (secrets backup) or re-run `init --force`.
   - Port already bound — another process owns `:2222` (or `:22`).
     `ss -lntp` to find it.
   - Lock held — another live gateway process owns the state
     directory's exclusive flock. The flock is released as soon as a
     process exits; it is never "stale" across reboots. Find the
     holder with `fuser <state-dir>/lock` (or `lsof <state-dir>/lock`)
     and stop it; do NOT reboot just to clear a lock you have not
     investigated.
3. **Container-specific.** Distroless images have no shell, so all
   debugging goes through `docker logs` (or `kubectl logs`). Confirm
   the named volume was created and the `csgw-state` volume is
   attached.
4. **Kubernetes-specific.** Confirm `pvc.yaml` was applied and the PVC
   is `Bound`. Confirm `image:` in `deployment.yaml` is pullable from
   your registry. The Deployment uses `Recreate` strategy — a
   `Pending` rollout is normal during pod replacement, not a startup
   failure.

---

## Detail codes

Stable detail codes used in audit events (`<state-dir>/audit/audit-YYYY-MM-DD.jsonl`)
and structured logs. The `event_type`, `account_id`, `peer_address`,
`connection_id`, `target`, and `credential_generation` fields carry the
rest of the context. Use `coder-ssh-gateway --state-dir <dir> doctor
[--account UUID] [--probe-workspace NAME]` to exercise the path end
to end. `--probe-workspace NAME` requires `--account UUID`.

### AUTH_UNKNOWN_KEY
- **What it means:** the presented SSH key is not registered, is
  disabled, belongs to a different deployment, or is an SSH
  certificate while certificates are disabled. The gateway emits the
  same rejection for any of these cases; you cannot tell from the
  message which one applies.
- **Retry safe?** Yes, but retrying with the same key changes nothing.
- **New token helps?** No.
- **Fix:** verify the key is registered (`admin key list --account
  UUID`) and enabled; register it with `admin key add`.

### AUTH_ACCOUNT_DISABLED
- **What it means:** the gateway account was disabled by an
  administrator.
- **Retry safe?** Yes, but futile until the account is re-enabled.
- **New token helps?** No.
- **Fix:** `admin account enable --account UUID` (investigate why it
  was disabled first).

### AUTH_CREDENTIAL_MISSING
- **What it means:** no token stored for the account (never enrolled,
  or cleared). The user gets a renewal continuation after key auth.
- **Retry safe?** Yes. This is the normal first-enrollment and
  post-clear path.
- **New token helps?** Yes; that is the entire point. Paste a fresh
  token at the prompt or in the maintenance session.

### AUTH_CREDENTIAL_UNAUTHORIZED
- **What it means:** Coder answered 401 — the stored token expired or
  was revoked.
- **Retry safe?** Yes. The stored credential is marked `invalid`; the
  user is offered renewal.
- **New token helps?** Yes. Renewal (automatic continuation or
  maintenance session) replaces the credential.

### AUTH_CREDENTIAL_FORBIDDEN
- **What it means:** Coder answered 403 — the token is valid but the
  account lost permission (role change, suspension, license).
- **Retry safe?** The connection fails cleanly; retrying with the same
  token is futile. No automatic renewal is offered.
- **New token helps?** Usually no. A 403 means the Coder deployment
  refuses this identity, not this token. Resolve the account's
  standing in Coder first.

### AUTH_WRONG_CODER_IDENTITY
- **What it means:** the submitted token belongs to a different Coder
  user than the account's bound UUID (wrong token pasted, or
  first-bind collision).
- **Retry safe?** The gateway does not offer another attempt. Treat as
  a security signal, not a typo loop.
- **New token helps?** Only a token for the CORRECT Coder user;
  repeated wrong-user submissions are a red flag.

### AUTH_CODER_UNAVAILABLE
- **What it means:** Coder API unreachable — DNS, TLS, connect,
  timeout, 429, or 5xx. The gateway never marks the credential invalid
  on this code.
- **Retry safe?** Yes. Nothing in local state changed; retry after
  Coder recovers.
- **Fix:** check Coder deployment health, egress policy (HTTPS, DERP,
  proxies, DNS must all pass), TLS CA config.

### AUTH_CODER_INCOMPATIBLE
- **What it means:** Coder answered 404 on `/api/v2/users/me`,
  returned a malformed success body, or redirected (variant
  `AUTH_CODER_INCOMPATIBLE:redirect`). The deployment is too old, is
  not Coder, or a proxy is mangling the API.
- **Retry safe?** The connection fails cleanly, but retrying changes
  nothing until the deployment is fixed.
- **Fix:** verify `deployment.coder_url`, upgrade Coder, inspect
  intermediaries (proxies must pass the API path verbatim).

### ROUTE_INVALID_PAYLOAD
- **What it means:** malformed `direct-tcpip` payload (unparseable
  host field, empty host, lone root dot). Usually a non-OpenSSH client
  or an attack probe.
- **Retry safe?** Yes, with a corrected client command.
- **Fix:** use OpenSSH or a compatible client that constructs valid
  `direct-tcpip` requests.

### ROUTE_PORT_DENIED
- **What it means:** the client requested a port other than 22. The
  gateway proxies workspace SSH only.
- **Retry safe?** Yes, with port 22.
- **Fix:** `ssh -J ... user@host` targets port 22 implicitly; explicit
  `-W host:PORT` must use 22.

### ROUTE_NAME_INVALID
- **What it means:** the bare target violates the strict DNS grammar:
  wrong label count (1–3 allowed), label length over 63,
  illegal characters, punycode (`xn--`), non-ASCII, or total length
  over 253 bytes.
- **Retry safe?** Yes, with a valid workspace name.
- **Fix:** use the workspace's real name (lowercase, hyphens, digits).

### TUNNEL_LIMIT_REACHED
- **What it means:** an admission semaphore is full: global
  connections, per-IP, per-key, per-account, channels, or
  `coder_processes`.
- **Retry safe?** Yes; retry once other connections close.
- **Fix:** identify the holder from the log fields (`account_id`,
  `peer_address`, `connection_id`) and have that client disconnect
  normally to release the semaphore slot. `admin disconnect --account
  UUID` only blocks NEW SSH authentication for the account — it does
  NOT terminate established tunnels and does NOT release their
  semaphore slots. The only ways to release a slot are (a) the client
  disconnects, (b) the spawned `coder` process exits, or (c) the
  gateway restarts.
- **Do NOT raise `limits.*` as a workaround for one stuck holder.**
  Limits are capacity ceilings, measured against your real workload.
  Raising them to bypass a single stuck session trades a known leak
  (one session cannot close) for an unbounded one (more sessions can
  leak in parallel). A restart is the correct last-resort action when
  a holder will not close normally; it is operationally disruptive
  (drops every live tunnel), so prefer it only after normal close
  paths have failed. Capacity-driven limit increases should follow a
  capacity analysis of normal peak load, not an incident.

### TUNNEL_PROCESS_START_FAILED
- **What it means:** the Coder CLI failed to spawn: bad
  `deployment.coder_binary` path, missing global-config dir, sandbox
  blocking exec.
- **Retry safe?** Yes, after fixing the spawn environment.
- **Fix:** verify the binary path and permissions; check systemd
  hardening (ProtectSystem, NoNewPrivileges) is not blocking the CLI.

### TUNNEL_START_TIMEOUT
- **What it means:** the spawned CLI produced no stdout byte within the
  startup timeout: workspace autostart taking too long, network
  blockage to DERP/proxies, or a hung CLI.
- **Retry safe?** Yes. If the workspace was autostarting, the next
  attempt usually connects faster.
- **Fix:** check workspace status in Coder; validate egress (HTTPS,
  DERP, proxies); raise `deployment.workspace_connect_timeout` for
  slow templates. `doctor --account UUID --probe-workspace NAME`
  exercises this path end to end.

### TUNNEL_CODER_EXITED
- **What it means:** the CLI process exited before or during streaming.
  Common root cause: the stored token failed at the Coder layer after
  outer auth succeeded. The gateway rechecks the credential after this
  failure and marks it invalid on a 401, so the NEXT connection offers
  renewal.
- **Retry safe?** Yes. The post-failure recheck has already classified
  the credential.
- **New token helps?** Often yes: if the recheck marked the credential
  invalid, reconnect and complete the renewal prompt.

### TUNNEL_STREAM_FAILED
- **What it means:** mid-stream I/O error after the tunnel was up:
  network flap between gateway and Coder, relay drop, workspace
  restart.
- **Retry safe?** Yes; reconnect.
- **Fix:** inspect network path (DERP relay health, direct UDP
  blocking). `doctor --account UUID --probe-workspace NAME` for a
  live path test.

### TUNNEL_CANCELLED
- **What it means:** the tunnel ended by policy, shutdown drain,
  client disconnect with a hung child (lingering past grace), or
  context cancellation. Frequently benign: a client closing its last
  channel shows here.
- **Retry safe?** Yes.
- **Fix:** none needed for client-initiated closes; for
  shutdown-related cancellations, see the drain configuration
  (`terminationGracePeriodSeconds: 90` in Kubernetes; systemd unit
  restart behavior for native).

### STORE_UNAVAILABLE
- **What it means:** the state dir is locked by another process (a
  second `serve` or a concurrent admin command: the flock is
  exclusive), a record is corrupt (JSON unmarshal failure), the
  VERSION file mismatches, or a uniqueness constraint was hit
  (duplicate key digest, duplicate bound Coder user).
- **Retry safe?** For lock conflicts, yes: wait for the other process
  or stop it. For corruption, no: restore from backup.
- **Fix:** `fuser <state-dir>/lock` to find the holder; never run two
  gateway processes on one state dir; restore corrupt records from
  backup.

### STORE_GENERATION_CONFLICT
- **What it means:** a compare-and-set lost a race — two concurrent
  credential replacements for the same account, or an admin
  `credential clear` against a stale generation. The loser sees this
  code; the winner's write stands.
- **Retry safe?** Yes. Retry the operation; it re-reads the current
  generation.
- **Fix:** during SSH renewal the conflict resolves itself as "already
  updated" and the client is told to reconnect.

### CRYPTO_KEY_UNAVAILABLE
- **What it means:** the encryption key file is missing, unreadable,
  wrong length (not 32 bytes raw or base64), or no key provider is
  configured. Startup and credential operations fail closed.
- **Retry safe?** No; fix the key material first.
- **Fix:** restore `secrets/credential-key-<id>` from your separate
  secret backup; confirm mode 0600 and ownership; confirm
  `encryption.active_key_id` names a listed key.

### CRYPTO_DECRYPT_FAILED
- **What it means:** AES-GCM authentication failure on a stored
  credential: wrong key for the record's `key_version` (key rotated
  away too early, restored from a mismatched backup), or a
  tampered/transplanted ciphertext. Fails closed; the credential is
  never used.
- **Retry safe?** No; decryption will fail identically until the
  correct key is present.
- **New token helps?** Yes, as recovery: `admin credential clear
  --account UUID` tombstones the undecryptable record, then the user
  enrolls a fresh token. The old ciphertext is unrecoverable without
  its key.
- **Fix:** restore the key matching the record's `key_version` into
  `encryption.keys` (old IDs stay decryptable while listed). If the
  key is lost, clear and re-enroll affected accounts.
