# Operator Guide — coder-ssh-gateway

This guide covers installing, configuring, enrolling users, and operating a
single-instance coder-ssh-gateway. Paths and flags below reflect the shipped
CLI; the global flags `--state-dir` and `--config` come **before** the
subcommand in every invocation.

## Installation

### Binary (systemd host)

1. Build or install the binary and the pinned Coder CLI:

   ```bash
   go install github.com/taxilian/coder-ssh-gateway/cmd/coder-ssh-gateway@latest
   install -m 0755 coder-ssh-gateway /usr/local/bin/
   # Coder CLI, pinned to your deployment's version:
   # https://coder.com/docs/install/cli (verify the checksum; section 31.2)
   install -m 0755 coder /usr/local/bin/
   ```

2. Create a dedicated user and state directory:

   ```bash
   useradd --system --home /var/lib/coder-ssh-gateway \
     --shell /usr/sbin/nologin coder-ssh-gateway
   coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway init
   chown -R coder-ssh-gateway: /var/lib/coder-ssh-gateway
   ```

3. Install the unit from `deploy/systemd/coder-ssh-gateway.service`, then
   `systemctl enable --now coder-ssh-gateway`. The unit applies the section
   31.1 hardening set; validate that the Coder CLI can still reach DERP
   relays and direct UDP paths from inside the sandbox before exposing the
   service.

### Container

`deploy/Dockerfile` builds a multi-stage, non-root image (distroless; no
shell, no package manager). The Coder CLI version and sha256 are pinned in
the Dockerfile, so no build args are required (both remain overridable for
version bumps — pin BOTH together):

```bash
docker build -f deploy/Dockerfile -t coder-ssh-gateway:dev .
docker run --rm coder-ssh-gateway:dev version
```

One named volume holds everything (records, audit log, `secrets/`). The
ENTRYPOINT already passes `--state-dir`; the subcommand goes last:

```bash
docker volume create csgw-state
docker run --rm -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway:dev init
docker run --rm -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway:dev doctor
```

`init` writes a starter `config.yaml` with `listen.address: ":2222"`, which
works as-is for container port mapping. The runtime image is distroless —
there is no shell inside the container, so edit config on the host via
`docker cp`:

```bash
c=$(docker create -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway:dev version)
docker cp "$c:/var/lib/coder-ssh-gateway/config.yaml" ./config.yaml
# edit ./config.yaml, then:
docker cp ./config.yaml "$c:/var/lib/coder-ssh-gateway/config.yaml"
docker rm "$c"
```

Metrics and health default to `127.0.0.1` and are NOT reachable through
`-p` port mappings. Two ways to expose them — either set
`observability.metrics_address` / `health_address` to `:9090` / `:9091` in
config.yaml (per the procedure above), or leave the config untouched and
pass the environment overrides at run time (see "Environment overrides"
below; no config edit needed):

```bash
docker run -d --name coder-ssh-gateway \
  -p 2222:2222 -p 9090:9090 -p 9091:9091 \
  -e CSGW_METRICS_ADDRESS=0.0.0.0:9090 \
  -e CSGW_HEALTH_ADDRESS=0.0.0.0:9091 \
  -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway:dev serve
```

With enrollment enabled (the default) users self-enroll via
`ssh init@<gateway>` — the container enrollment below is the out-of-band
alternative for operators who disable self-enrollment.

Enroll (account, device key, credential) without exposing the token on
argv. `--bind-on-first-token` asks for a `yes` confirmation on stdin after
the token line:

```bash
docker run --rm -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway:dev admin account add --label "Laptop" --bind-on-first-token
# add a device key: bind-mount the .pub read-only and pass --file
docker run --rm -v csgw-state:/var/lib/coder-ssh-gateway \
  -v "$PWD/enroll:/mnt:ro" \
  coder-ssh-gateway:dev admin key add --account <UUID> --file /mnt/laptop.pub --label laptop
# store the Coder session token via stdin (token NEVER in argv):
{ cat ~/.config/coderv2/session; echo; echo yes; } | \
  docker run -i --rm -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway:dev admin credential set --account <UUID> --stdin
```

Serve and connect:

```bash
docker run -d --name coder-ssh-gateway -p 2222:2222 \
  -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway:dev serve
```

Client side, note that a ProxyJump host (`-J user@host:port`) spawns a
separate ssh child that does NOT inherit the parent's `-o` identity or
known-hosts options — define the jump in a config file instead:

```
Host csgw-jump
  HostName 127.0.0.1
  Port 2222
  User coder
  IdentityFile ~/.ssh/id_ed25519
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
```

```bash
ssh -J csgw-jump coder@<workspace>.<target-suffix> 'printf hello'
```

Teardown: `docker stop coder-ssh-gateway && docker rm coder-ssh-gateway`;
the state volume persists across container replacement and can be removed
with `docker volume rm csgw-state` when decommissioning.

Named volumes inherit the image's prepared ownership (uid 65532); a host
bind-mount must be chowned to 65532:65532 first. To keep secrets off the
data volume, mount them read-only (for example `/run/secrets`) and point
`ssh.host_keys` / `encryption.keys` at those paths. A read-only mounted
Coder CLI binary is a supported alternative to baking it into the image.

### Kubernetes

See `deploy/k8s/` and its `NOTES.md`. Summary: one replica, `Recreate`
strategy (the store flock makes a second writer fail fast), one RWO PVC at
`/var/lib/coder-ssh-gateway`, `Service` type `LoadBalancer` mapping 22 to
2222, probes on `/livez` and `/readyz`, `terminationGracePeriodSeconds: 90`.

## First boot: init and doctor

```bash
coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway init
coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway doctor
```

`init` creates the store layout, an Ed25519 host key, a 32-byte credential
encryption key (both mode 0600 under `secrets/`), and a starter
`config.yaml`. It is idempotent; `--force` still asks for an explicit
`overwrite` confirmation per artifact. Back up `secrets/` immediately
(section 22.4).

`doctor` prints PASS/WARN/FAIL per check and exits 1 only on a local FAIL.
An unreachable Coder deployment is WARN, not FAIL. Checks: config parse,
state dir (VERSION + flock), encryption key (seal/open self-test), host key
(fingerprints), Coder TLS dial, Coder `/api/v2/buildinfo`, Coder CLI binary
(version parse and CLI/server match), target suffix, writable dirs, process
limits. Optional: `--account UUID` also validates that account's stored
credential; `--probe-workspace NAME` runs a real `coder ssh --stdio` probe.

## Self-enrollment (init@)

With `enrollment.enabled: true` (the default), users onboard themselves:
`ssh init@<gateway>` from any device prompts for a Coder token, links that
device's SSH key to the caller's Coder account, stores the token, and
closes the connection. The next connection uses the normal transport path
(`coder@…`). The "Enrolling a user" section below remains available as the
out-of-band alternative.

### How it works

1. The client connects to the enrollment username (`init` by default) and
   proves possession of its private key. Proof of key possession always
   comes first — the gateway never prompts for a token before the key is
   verified.
2. Only then does it show the enrollment banner with the deployment's
   `/cli-auth` URL and prompt `Coder token: ` (keyboard-interactive, with a
   password-method parity path for clients that do not render
   keyboard-interactive prompts).
3. The submitted token is validated against Coder `/api/v2/users/me`. The
   returned Coder user UUID anchors the account: an existing account bound
   to that UUID is reused (and the new key added to it), otherwise a new
   account is created for that UUID. The token is stored (generation CAS,
   same as renewal) and the key is registered with the label
   `enrolled <timestamp> via init@`.
4. Success banner, one reconnect allowance, connection closed. The client
   must reconnect — the enrolled credential is live for the next transport
   connection immediately.

Idempotency: re-enrolling the same key with a token for the same Coder user
is a no-op success (the existing key record is recovered). A key already
linked to a *different* account is a hard rejection (`key_already_linked`
audit event, explanatory banner, no mutation) — this check runs before any
account creation, so a wrong-identity token cannot create an account.

### Security model

- **Token possession is enrollment authority.** Whoever presents a valid
  Coder token enrolls the presented key for that token's Coder user. The
  blast radius of a stolen token used this way is the same as the token
  itself: the attacker could already impersonate that user against Coder
  directly. See SECURITY.md.
- **Proof-before-prompt.** Key possession is verified before any token
  prompt, so unauthenticated scanners never reach the token path.
- **Rate limits.** Per-IP pre-token gate (the pre-auth unknown-key bucket)
  plus per-connection and per-account attempt bounds shared with the
  renewal flow. Refusals are audited.
- **Key-conflict policy.** Cross-account key reuse is rejected outright,
  never re-linked.
- **Audit + metrics.** Every outcome is an audit event
  (`enrollment_success` / `enrollment_rejected` with detail codes) and a
  `coder_ssh_gateway_enrollments_total{result}` counter increment
  (`success|rejected|key_conflict|rate_limited`). Alert on rejections.
- **No existence oracle.** With enrollment disabled — or for a client that
  fails key verification — the `init` username rejects byte-identically to
  any unknown username.

### Disabling self-enrollment

```yaml
enrollment:
  enabled: false
```

Disable it for closed memberships — deployments where the set of users is
fixed and provisioned out-of-band, where any holder of a valid Coder token
must NOT be able to attach a new key to their gateway account, or where
policy requires an administrator to approve every device key. With it off,
the `init` username behaves exactly like an unknown username and the
admin-driven flow below is the only enrollment path.

Note: this flow deliberately reverses design section 10.5 ("an unknown SSH
key must never be allowed to create an account simply by supplying a valid
Coder token"). That reversal is a product decision: token-anchored
self-enrollment is the primary onboarding path, secured by the controls
above rather than by prohibiting key-first account creation.

## Enrolling a user (out-of-band)

Enrollment is offline administration against the state dir; the gateway
does not have to be running, but it must NOT be running (the flock is
exclusive).

1. **Account.** Either bind to a known Coder user UUID or defer binding to
   the first valid token:

   ```bash
   coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway \
     admin account add --label "Ada" --bind-on-first-token
   # or: admin account add --label "Ada" --coder-user-id <uuid>
   ```

2. **Key.** Register the user's SSH public key (authorized_keys format):

   ```bash
   coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway \
     admin key add --account <account-uuid> --file ./ada.pub --label "ada-laptop"
   ```

3. **Credential.** Store the user's Coder session token. Tokens never
   travel on argv: use `--stdin` or the hidden TTY prompt (section 29).

   ```bash
   coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway \
     admin credential set --account <account-uuid> --stdin < token.txt
   ```

   The token is validated against Coder before storage. With
   `--bind-on-first-token`, this first valid token binds the account's
   Coder user UUID.

4. **Verify.**

   ```bash
   coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway \
     doctor --account <account-uuid>
   ```

Other admin operations: `admin account list`, `admin account
disable|enable --account UUID`, `admin key list --account UUID`,
`admin key disable|enable --key UUID`, `admin credential status --account
UUID` (state + generation), `admin credential clear --account UUID`
(tombstones the credential; it does NOT revoke the token in Coder),
`admin disconnect --account UUID` (terminates the account's active tunnels).

## Configuration reference

Config file: `<state-dir>/config.yaml` by default; override with `--config`.
Relative paths in the file resolve against the config file's directory.
Unknown keys are rejected. Durations are strings like `30s`, `5m`.

### Environment overrides

Three bind addresses can be overridden by environment variables, applied by
`serve` after config parse and before validation. Precedence is uniform:
**CLI flag > env var > config file > default**. An unset or empty variable
is ignored; an invalid value (not `host:port`, non-numeric or out-of-range
port) fails startup naming the variable, leaving the config unmutated.
Wildcard binds (`0.0.0.0`, `[::]`, empty host) are accepted — that is the
container use case. Applied overrides are logged at startup.

| Variable | Overrides | Typical container value |
| --- | --- | --- |
| `CSGW_LISTEN_ADDRESS` | `listen.address` | `0.0.0.0:2222` |
| `CSGW_METRICS_ADDRESS` | `observability.metrics_address` | `0.0.0.0:9090` |
| `CSGW_HEALTH_ADDRESS` | `observability.health_address` | `0.0.0.0:9091` |

Kubernetes example (see `deploy/k8s/deployment.yaml`): the health/metrics
Service ports and probes need a non-loopback bind, so set the env vars
instead of editing config.yaml:

```yaml
env:
  - name: CSGW_LISTEN_ADDRESS
    value: "0.0.0.0:2222"
  - name: CSGW_METRICS_ADDRESS
    value: "0.0.0.0:9090"
  - name: CSGW_HEALTH_ADDRESS
    value: "0.0.0.0:9091"
```

`doctor` never binds listeners, so the overrides only affect `serve`.

| Field | Default | Meaning |
| --- | --- | --- |
| `version` | `1` | Config schema version. |
| `listen.address` | `:22` | Outer SSH listen address (`:2222` in containers/dev). |
| `listen.handshake_timeout` | `30s` | Max time for the SSH handshake to complete. |
| `listen.renewal_auth_timeout` | `5m` | Handshake deadline extension while a credential renewal prompt is open. |
| `listen.tcp_keepalive` | `30s` | TCP keepalive on accepted connections (0 = OS defaults). |
| `listen.proxy_protocol` | `false` | Accept PROXY v1 headers. Enable only behind a trusted balancer; never auto-detected. |
| `ssh.transport_user` | `coder` | SSH username for workspace transport connections. |
| `ssh.maintenance_user` | `auth` | SSH username for the credential-maintenance session. |
| `ssh.server_version` | `SSH-2.0-CoderSSHGW_0.1` | SSH protocol version banner. |
| `ssh.host_keys` | `<state-dir>/secrets/ssh_host_ed25519_key` | Host private key paths. Multiple keys supported for rotation. Startup fails if none load. |
| `ssh.allow_ssh_certificates` | `false` | Accept SSH user certificates (section 10.3). |
| `state.dir` | (none) | State directory; `--state-dir` flag wins over this. |
| `state.audit_retention_days` | `90` | Days to retain `audit/audit-YYYY-MM-DD.jsonl` files. |
| `encryption.provider` | `file` | Key provider. Only `file` is implemented. |
| `encryption.active_key_id` | `v1` | Key ID used for new writes. |
| `encryption.keys` | `v1: <state-dir>/secrets/credential-key-v1` | Map of key ID to key file (raw 32 bytes or base64). Old IDs stay decryptable while listed. |
| `deployment.id` | `primary` | Deployment label. One deployment per gateway (MVP). |
| `deployment.coder_url` | (none) | Coder access URL. HTTPS only; HTTP is always rejected. |
| `deployment.target_suffix` | (none) | DNS suffix for workspace targets, e.g. `coder-gateway.example.com`. Lowercase labels, at least two labels. |
| `deployment.coder_binary` | `/usr/local/bin/coder` | Path to the pinned Coder CLI. |
| `deployment.coder_global_config` | `/var/lib/coder-ssh-gateway/coder-config` | Isolated Coder CLI global config dir (section 18.4). |
| `deployment.working_directory` | `/var/empty/coder-ssh-gateway` | Working directory for spawned CLI processes. |
| `deployment.autostart` | `true` | Allow `coder ssh` to autostart stopped workspaces. |
| `deployment.wait` | `auto` | `coder ssh --wait` mode: `yes`, `no`, or `auto`. |
| `deployment.workspace_connect_timeout` | `5m` | Bound on workspace connect/autostart waits. |
| `deployment.token_validation_timeout` | `10s` | HTTP timeout for token validation calls. |
| `deployment.token_validation_cache` | `15s` | TTL for cached validation results. |
| `deployment.tls.ca_file` | (none) | Custom CA bundle for the Coder deployment. |
| `deployment.tls.client_cert_file` | (none) | Client certificate for mTLS to Coder (with key). |
| `deployment.tls.client_key_file` | (none) | Client key for mTLS to Coder. |
| `deployment.network.disable_coder_telemetry` | `true` | Set `CODER_DISABLE_NETWORK_TELEMETRY` for spawned CLI. |
| `deployment.network.https_proxy` | (none) | HTTPS proxy for Coder API traffic. |
| `deployment.network.no_proxy` | (none) | NO_PROXY list. |
| `limits.unauthenticated_connections` | `128` | Max concurrent pre-auth connections. |
| `limits.handshakes` | `64` | Max concurrent in-progress handshakes. |
| `limits.connections_per_ip` | `16` | Max connections per source IP (also pre-auth rate burst). |
| `limits.connections_per_key` | `8` | Max connections per registered key. |
| `limits.connections_per_account` | `8` | Max connections per account. |
| `limits.channels_per_connection` | `4` | Max channels on one outer connection. |
| `limits.channels_per_account` | `8` | Max channels per account. |
| `limits.coder_processes` | `128` | Max concurrent spawned Coder CLI processes. |
| `limits.coder_api_requests` | `32` | Max concurrent Coder API requests. |
| `limits.renewal_attempts_per_connection` | `3` | Token submissions allowed per connection. |
| `limits.renewal_attempts_per_account_per_minute` | `5` | Renewal rate limit per account. |
| `limits.process_shutdown_grace` | `5s` | Grace between SIGTERM and SIGKILL for child processes. |
| `limits.stderr_buffer_bytes` | `65536` | Bounded ring for child stderr diagnostics. |
| `maintenance.enabled` | `true` | Enable the maintenance session (`auth` user). |
| `maintenance.session_timeout` | `5m` | Whole-session bound for maintenance. |
| `maintenance.input_timeout` | `2m` | Negotiation and per-keystroke bound. |
| `maintenance.bind_on_first_token_requires_admin_flag` | `true` | First-token binding only for accounts created with `--bind-on-first-token`. |
| `enrollment.enabled` | `true` | Enable the init@ token-anchored self-enrollment flow (see "Self-enrollment"). |
| `enrollment.user` | `init` | SSH username that triggers enrollment; must differ from transport and maintenance users. |
| `enrollment.max_attempts` | `3` | Token submissions allowed per enrollment connection. |
| `enrollment.timeout` | `5m` | Handshake deadline extension while an enrollment token prompt is open. |
| `observability.log_format` | `json` | `json` or `text`. |
| `observability.log_level` | `info` | `debug`, `info`, `warn`, `error`. |
| `observability.metrics_address` | `127.0.0.1:9090` | Prometheus metrics listen address. |
| `observability.health_address` | `127.0.0.1:9091` | Health endpoint listen address (`/livez`, `/readyz`). |

## State directory layout

Everything lives under one directory:

```text
<state-dir>/
  config.yaml                      # not store-managed
  secrets/                         # not store-managed; 0700
    ssh_host_ed25519_key           # 0600
    credential-key-v1              # 0600
  VERSION                          # "1"
  lock                             # flock(2) LOCK_EX|LOCK_NB, process lifetime
  deployments/<deployment-uuid>.json
  accounts/<account-uuid>.json
  keys/<sha256-hex-of-key-blob>.json
  credentials/<account-uuid>.json  # AES-256-GCM sealed token, per-account
  audit/audit-YYYY-MM-DD.jsonl     # audit events, one file per day
  coder-config/                    # Coder CLI global config (init starter)
  run/                             # working dir for spawned CLI (init starter)
```

All store mutations are write-temp, fsync, rename, fsync(dir). Record files
are 0600, directories 0700. The flock is held for the process lifetime, so
exactly one gateway process may use a state dir; admin commands and `serve`
cannot overlap on the same dir.

## Backup and restore

Back up the **whole state dir** (config, records, audit) and the
`secrets/` subdirectory **separately, to separately restricted storage**
(section 22.4):

- State dir without the encryption key cannot recover tokens.
- The encryption key without the state dir identifies nothing.
- Together they recover everything, so never store both in one backup
  bucket.

```bash
systemctl stop coder-ssh-gateway            # release the flock first
cp -a /var/lib/coder-ssh-gateway /backup/csgw-state-$(date +%F)
# copy secrets/ to your secure secret store separately
systemctl start coder-ssh-gateway
```

Restore is the reverse: stop, `cp -a` the tree back (preserve modes and
ownership), restore secrets, start. Restoring to the SAME path works as-is
and the copied dir boots unchanged. Restoring to a DIFFERENT path requires
rebasing the absolute paths in `config.yaml` (`state.dir`, `ssh.host_keys`,
`encryption.keys`, `deployment.coder_global_config`,
`deployment.working_directory`): `init` writes absolute paths into the
starter config, and explicit config values always win over `--state-dir`
conventions.

## Encryption-key rotation

Multiple key versions are supported: every entry under `encryption.keys`
stays available for decryption; `encryption.active_key_id` selects the key
for new writes (section 22.3).

1. Generate a new key and place it at `<state-dir>/secrets/credential-key-v2`
   (mode 0600).
2. Add `v2: <state-dir>/secrets/credential-key-v2` under `encryption.keys`
   and set `active_key_id: v2`.
3. Restart the gateway. New credential writes now use v2.
4. **Re-encrypt existing records:** the store implements transactional
   re-encryption (`ReencryptAll`), but the current CLI has no admin command
   wired to it. This is a known gap. Until an `admin credential reencrypt`
   command ships, step 4 requires a maintenance build calling
   `store.ReencryptAll`, or waiting for each credential to be replaced
   naturally (renewals and `admin credential set` re-seal with the active
   key).
5. Verify no records reference the old `key_version` (inspect
   `credentials/*.json` — ciphertext records carry a `key_version` field).
6. Retire the old key file only after your backup retention permits:
   backups taken before rotation still need it.

## Host-key rotation (section 30.2)

1. Generate the new key: `ssh-keygen -t ed25519 -f ssh_host_ed25519_key.new -N ''`.
2. Publish the new fingerprint through your trusted channel.
3. Add the new path to `ssh.host_keys` alongside the old one (the gateway
   loads and offers all listed keys) and restart.
4. Update clients and known_hosts records.
5. Remove the old key after a defined overlap period.

Client behavior during overlap varies; test Moshi specifically before
relying on seamless rotation. Never auto-generate a host key at startup:
with no configured keys the gateway fails to boot, deliberately.
