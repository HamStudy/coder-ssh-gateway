# Operator Guide — coder-ssh-gateway

How to install, configure, and operate the gateway on a single host
(native, container, or Kubernetes). Pick the section that matches your
deployment.

- [Choose a deployment shape](#choose-a-deployment-shape)
- [Native install (systemd)](#native-install-systemd)
- [Container (standalone Docker)](#container-standalone-docker)
- [Kubernetes](#kubernetes)
- [First boot: init and doctor](#first-boot-init-and-doctor)
- [Migrating from earlier releases](#migrating-from-earlier-releases)
- [Self-enrollment (`login@`)](#self-enrollment-login)
- [Enrolling a user out-of-band](#enrolling-a-user-out-of-band)
- [Configuration reference](#configuration-reference)
- [State directory layout](#state-directory-layout)
- [Backup and restore](#backup-and-restore)
- [Encryption-key rotation](#encryption-key-rotation)
- [Host-key rotation](#host-key-rotation)

Global flags (`--state-dir`, `--config`, `--listen-address`,
`--metrics-address`, `--health-address`) come **before** the subcommand in
every invocation. The example gateway uses the placeholders
`gateway.example.com` (gateway hostname), `coder.example.com` (Coder
deployment).
Replace each with your real values before use.

## Choose a deployment shape

| Deployment | External port on the network | Internal SSH port | Pros | Cons |
| --- | --- | --- | --- | --- |
| Native systemd host | `2222` (configurable) | `2222` | Single binary, host-managed | You maintain the host |
| Standalone Docker | `2222` (host publish) | `2222` | Reproducible image, no host deps | You maintain the host |
| Kubernetes | `22` on a LoadBalancer Service | `2222` in-pod | Public port 22, Helm chart, Secret-backed keys | Requires a cluster |

The port you publish externally is independent of the in-process listener
port. All three shapes listen on `2222` by default; the difference is how
that port reaches the network. In Kubernetes, the typical choice is to map
external 22 to in-pod 2222 so end users connect with plain `ssh host` and
no port flag.

## Native install (systemd)

This is the canonical secure native install.

### 1. Install the binary

```bash
git clone https://github.com/HamStudy/coder-ssh-gateway
cd coder-ssh-gateway
make
sudo install -m 0755 ./bin/coder-ssh-gateway /usr/local/bin/

# Coder CLI, pinned to your deployment's version (verify the checksum
# against the release page):
# https://coder.com/docs/install/cli
sudo install -m 0755 coder /usr/local/bin/coder

coder-ssh-gateway version
coder version
```

### 2. Create the service user and state directory

The service user owns everything the gateway writes. Pick a non-login
system user.

```bash
sudo useradd --system --home /var/lib/coder-ssh-gateway \
  --shell /usr/sbin/nologin coder-ssh-gateway
sudo install -d -o coder-ssh-gateway -g coder-ssh-gateway -m 0700 \
  /var/lib/coder-ssh-gateway
stat -c "%U:%G %a" /var/lib/coder-ssh-gateway   # coder-ssh-gateway:coder-ssh-gateway 700
```

### 3. Initialize the state directory

`init` requires the bare Coder domain and creates the layout, an Ed25519 host
key, a 32-byte credential encryption key, and a starter `config.yaml` with
that domain as its HTTPS `deployment.coder_url`. All secrets land under
`<state-dir>/secrets/` with mode `0600`.

```bash
sudo -u coder-ssh-gateway \
  coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway init coder.example.com
```

### 4. Edit the generated config

Open the generated `config.yaml` with `sudoedit`, which runs the editor
as you but saves the file in place — preserving the service-user owner
and mode without a separate `chown`/`chmod`:

```bash
sudoedit /var/lib/coder-ssh-gateway/config.yaml
```

The full annotated reference is at [`config.example.yaml`](../config.example.yaml).
Most keys ship with usable defaults, but `init` leaves the
`deployment.coder_url`, `deployment.coder_binary`, and `deployment.id`
fields for you to confirm — review the required `[REQUIRED]` and
`[DEPLOYMENT]` annotations and adjust any values that do not match your
environment before starting the service.

### 5. Verify before opening the port

```bash
sudo -u coder-ssh-gateway \
  coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway doctor
```

`doctor` prints PASS/WARN/FAIL per check. Exit code is non-zero only on a
local FAIL — an unreachable Coder deployment is WARN, not FAIL. Optional
flags:

- `--account UUID` — also validate that account's stored credential.
- `--probe-workspace NAME` — run a real `coder ssh --stdio` probe
  (requires `--account`).

### 6. Install the systemd unit

The unit at `deploy/systemd/coder-ssh-gateway.service` runs the gateway as
the service user under a hardened sandbox.

```bash
sudo install -m 0644 \
  deploy/systemd/coder-ssh-gateway.service \
  /etc/systemd/system/coder-ssh-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable --now coder-ssh-gateway
systemctl is-active coder-ssh-gateway   # expect: active
```

If the Coder CLI cannot reach workspaces after starting the unit (DERP
relays, direct UDP paths, proxies), the sandbox is the first thing to
suspect. Relax the minimum set of options in the unit, then re-verify
connectivity before exposing the service.

### 7. Hand users the four values

Tell each user:

1. Gateway hostname (`gateway.example.com`)
2. External SSH port (`2222` by default for native installs)
3. `/cli-auth` URL (`https://coder.example.com/cli-auth`)
4. Gateway host-key fingerprint (publish through a trusted channel; users
   verify on first connect)

## Container (standalone Docker)

The shipped image is multi-stage, distroless, non-root. The Coder CLI
version and sha256 are baked in; both are overridable via `--build-arg`
when you bump versions (pin both together).

### 1. Build the image

```bash
docker build -f deploy/Dockerfile -t coder-ssh-gateway:dev .
docker run --rm coder-ssh-gateway:dev version
```

### 2. Create a named volume and initialize

One named volume holds everything (records, audit log, `secrets/`). The
entrypoint already passes `--state-dir`; the subcommand goes last.

```bash
docker volume create csgw-state
docker run --rm -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway:dev init coder.example.com
```

`init` writes a starter `config.yaml` with `listen.address: ":2222"`,
which is the right value for container port mapping.

### 3. Edit config.yaml

The image is distroless (no shell inside). Use `docker cp` to copy the
file out, edit, and copy it back:

```bash
c=$(docker create -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway:dev version)
docker cp "$c:/var/lib/coder-ssh-gateway/config.yaml" ./config.yaml
# edit ./config.yaml, then:
docker cp ./config.yaml "$c:/var/lib/coder-ssh-gateway/config.yaml"
docker rm "$c"
```

Set at minimum:

```yaml
deployment:
  coder_url: https://coder.example.com
```

### 4. Verify

```bash
docker run --rm -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway:dev doctor
```

### 5. Serve (hardened)

This is the only `docker run ... serve` invocation you need. It publishes
the SSH listener to all host interfaces, keeps metrics and health on host
loopback only, and applies the standard four hardening flags
(`--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
`--tmpfs /tmp`):

```bash
docker run -d --name coder-ssh-gateway \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,size=64m,mode=1777 \
  -p 2222:2222 \
  -p 127.0.0.1:9090:9090 \
  -p 127.0.0.1:9091:9091 \
  -e CSGW_LISTEN_ADDRESS=0.0.0.0:2222 \
  -e CSGW_METRICS_ADDRESS=0.0.0.0:9090 \
  -e CSGW_HEALTH_ADDRESS=0.0.0.0:9091 \
  -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway:dev serve
```

Verify it came up:

```bash
docker logs coder-ssh-gateway 2>&1 | grep -m1 SHA256   # host-key fingerprint
curl -sf http://127.0.0.1:9091/livez                   # expect: ok
```

The `CSGW_*` overrides only apply to those three configured bind
addresses and only at `serve` time; they leave `config.yaml` untouched.
Precedence for those three values is **CLI flag > env var > config file >
default**. Environment variables remain the simplest option for containers
and Kubernetes.

Named volumes inherit the image's prepared ownership (uid 65532). A host
bind mount must be `chown 65532:65532` first.

### 6. Out-of-band enrollment (optional, if you disabled self-enrollment)

The serving container holds an exclusive lock on the state volume. Admin
containers cannot overlap the running serve container; the second writer
fails fast. Two safe orderings:

- Run the admin commands BEFORE the first `serve` (after `init` /
  `doctor`), so no serve container holds the volume.
- OR stop and remove the running serve container, run the admin commands
  against the same volume, then rerun the hardened serve command above
  to recreate it:

  ```bash
  docker stop coder-ssh-gateway && docker rm coder-ssh-gateway
  # run admin commands ...
  # rerun the hardened `docker run -d ... serve` from above
  ```

The full enrollment sequence (account, key, token via stdin) is in
[Enrolling a user out-of-band](#enrolling-a-user-out-of-band).

### 7. Teardown

```bash
docker stop coder-ssh-gateway && docker rm coder-ssh-gateway
```

The state volume persists across container replacement. Decommission only
when you no longer need the records:

```bash
docker volume rm csgw-state
```

### Things to know

- **One `docker run` per stage.** The serving container is the only
  long-running one.
- **Metrics and health default to `127.0.0.1`.** The serve command above
  exposes them via `CSGW_*` env vars and host loopback ports. If you
  prefer to set them in `config.yaml` instead, use `0.0.0.0:9090` and
  `0.0.0.0:9091` and skip the env vars.
- **External secrets.** To keep secrets off the data volume, mount them
  read-only (for example `/run/secrets`) and point `ssh.host_keys` and
  `encryption.keys` in `config.yaml` at those paths. A read-only mounted
  Coder CLI binary is a supported alternative to baking it into the
  image.

## Kubernetes

The Deployment self-initializes: an init container runs `init` on every
boot. On an empty PVC it creates the state layout; afterwards it no-ops
(`init` keeps existing files and exits 0). Two paths: Helm (recommended)
or the raw manifests.

Prerequisites:

- A namespace.
- A StorageClass with `ReadWriteOnce`. The state lock makes any second
  writer fail fast; never run more than one replica.
- TCP port 22 exposed via L4 load balancing. HTTP Ingress does not work
  for SSH.

### Option A: Helm (recommended)

The chart self-provisions: it generates the credential-encryption key on
install and injects it through the environment only (never written to
the state volume), and the init container generates the host key into
the state volume on first boot. Both survive upgrades and reinstalls;
supply your own via `secrets.hostKey` / `secrets.encryptionKey` when
you want out-of-band control:

From a checkout:

```bash
helm install coder-ssh-gateway deploy/helm/coder-ssh-gateway \
  --namespace coder-ssh-gateway --create-namespace \
  --set coder.domain=coder.example.com
kubectl -n coder-ssh-gateway rollout status deploy/coder-ssh-gateway
```

Or without cloning, from the OCI registry (every release publishes the
chart there):

```bash
helm install coder-ssh-gateway \
  oci://ghcr.io/hamstudy/charts/coder-ssh-gateway \
  --version 0.2.1 \
  --namespace coder-ssh-gateway --create-namespace \
  --set coder.domain=coder.example.com
```

`--version` pins the chart version and is recommended for repeatable
installs; without it Helm installs the latest chart it has cached or
pulls the latest published one. Each release tags the chart at its
version; list what's published with
`helm show chart oci://ghcr.io/hamstudy/charts/coder-ssh-gateway` or
check the
[releases page](https://github.com/HamStudy/coder-ssh-gateway/releases).
The release tarball is also attached to each release as a fallback, but
the registry is the supported path.

`coder.domain` is the hostname of your Coder deployment; the default,
`coder.com`, is Coder's public service. The chart renders `config.yaml`
from a ConfigMap and prints the LoadBalancer address. Verify:

```bash
kubectl -n coder-ssh-gateway get svc coder-ssh-gateway
kubectl -n coder-ssh-gateway logs deploy/coder-ssh-gateway \
  | grep -o 'SHA256:[A-Za-z0-9/+=-]*' | sort -u
```

Configuration changes are values changes. Any config key can be set or
overridden through `configOverride`, which is deep-merged over the
generated config (see `values.yaml`; the full key reference is
[config.example.yaml](../config.example.yaml)):

```bash
helm upgrade coder-ssh-gateway deploy/helm/coder-ssh-gateway \
  --namespace coder-ssh-gateway --reuse-values \
  --set configOverride.deployment.autostart=false
```

Key rotation: `helm upgrade` with the new key values, then
`kubectl -n coder-ssh-gateway rollout restart deploy/coder-ssh-gateway` —
key files reach the pod through subPath mounts, which do not update in
place.

### Option B: raw manifests

Edit two things in `deploy/k8s/deployment.yaml` before applying: the
`init` container's Coder domain argument and (if you build your own
image) the `image:` references. Then:

```bash
kubectl -n coder-ssh-gateway apply -f deploy/k8s/pvc.yaml
kubectl -n coder-ssh-gateway apply -f deploy/k8s/deployment.yaml
kubectl -n coder-ssh-gateway apply -f deploy/k8s/service.yaml
kubectl -n coder-ssh-gateway rollout status deploy/coder-ssh-gateway
kubectl -n coder-ssh-gateway logs deploy/coder-ssh-gateway \
  | grep -o 'SHA256:[A-Za-z0-9/+=-]*' | sort -u
```

Keys generated this way live on the PVC — back the volume up per
[Backup and restore](#backup-and-restore). The starter config holds
placeholder values beyond the domain argument; change them as described
below before users enroll.

### Maintenance: config edits and `doctor`

`serve` holds the exclusive state lock for its lifetime, so off-line
maintenance means scaling to zero, doing the work, scaling back:

```bash
kubectl -n coder-ssh-gateway scale deploy/coder-ssh-gateway --replicas=0
kubectl -n coder-ssh-gateway wait --for=delete pod \
  -l app=coder-ssh-gateway --timeout=120s
```

Edit `config.yaml` through a helper pod (the gateway image is distroless,
so `kubectl cp` has nothing to exec against):

```bash
kubectl -n coder-ssh-gateway apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: csgw-edit
spec:
  restartPolicy: Never
  securityContext:
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
  containers:
    - name: edit
      image: alpine:3.20
      command: ["sleep", "3600"]
      volumeMounts:
        - name: state
          mountPath: /state
  volumes:
    - name: state
      persistentVolumeClaim:
        claimName: coder-ssh-gateway
EOF
kubectl -n coder-ssh-gateway wait --for=condition=Ready pod/csgw-edit --timeout=60s
kubectl -n coder-ssh-gateway cp csgw-edit:/state/config.yaml ./config.yaml
$EDITOR ./config.yaml
kubectl -n coder-ssh-gateway cp ./config.yaml csgw-edit:/state/config.yaml
# tar inside `kubectl cp` may rewrite the mode; restore 0600 and verify.
kubectl -n coder-ssh-gateway exec pod/csgw-edit -- chmod 0600 /state/config.yaml
kubectl -n coder-ssh-gateway exec pod/csgw-edit -- \
  stat -c "expected 600; got %a" /state/config.yaml
kubectl -n coder-ssh-gateway delete pod csgw-edit
```

Run `doctor` with the checked-in Job (it mounts the PVC and matches the
deployment's UID):

```bash
kubectl -n coder-ssh-gateway apply -f deploy/k8s/csgw-doctor.Job.yaml
kubectl -n coder-ssh-gateway wait --for=condition=complete \
  --timeout=120s job/csgw-doctor
kubectl -n coder-ssh-gateway logs job/csgw-doctor
kubectl -n coder-ssh-gateway delete job csgw-doctor
kubectl -n coder-ssh-gateway scale deploy/coder-ssh-gateway --replicas=1
kubectl -n coder-ssh-gateway rollout status deploy/coder-ssh-gateway
```

A WARN on the Coder deployment means fix egress before exposing the
gateway; a FAIL means fix the listed check and re-run. Scaling to zero
preserves the Deployment definition, so restoring `--replicas=1` is all
the rollout needs.

### Egress network policy

Egress must permit more than the Coder API hostname, or workspace
connections degrade to relay-only or break:

- Coder access URL (HTTPS)
- Configured workspace proxies
- Configured DERP servers
- DNS
- NTP
- Direct peer UDP paths when Coder uses direct tailnet connectivity

Ingress: only the SSH listener (port 22 on the Service, mapping to 2222
in-pod) needs to admit traffic, and only from the load balancer.

### PROXY protocol

If your load balancer speaks PROXY v1, set `listen.proxy_protocol: true`
in `config.yaml` and restrict the Service to the balancer's source
ranges. The gateway never auto-detects PROXY headers; with the option
off, PROXY bytes are ignored and the socket peer is used.

## First boot: init and doctor

`init` is idempotent. `--force` asks for an explicit `overwrite`
confirmation per artifact (host key, encryption key, starter config).
Back up `secrets/` immediately — losing the active key orphans every
stored token. On Kubernetes the init container runs this for you on the
first boot; native and Docker operators run it themselves.

`doctor` checks: config parse, state dir (VERSION + flock), encryption
key (seal/open self-test), host key (fingerprints), Coder TLS dial, Coder
`/api/v2/buildinfo`, Coder CLI binary (version parse and CLI/server
match), writable directories, process limits. An
unreachable Coder deployment is WARN, not FAIL — it will not block a
rollout but you should still fix it before opening the port.

## Migrating from earlier releases

### Upgrading to 0.2.0 (breaking)

Two reserved usernames and their config keys are gone:

- Remove `transport_user:` and `maintenance_user:` from the `ssh:` block
  of `config.yaml` — unknown keys are rejected at startup.
- `auth@gateway` no longer exists. When a stored token expires, the next
  workspace connection prompts for a fresh token inline and continues
  into the workspace — no separate renewal connection, no reconnect.
- `coder@gateway` is no longer special. ProxyJump works with any
  username: `ssh -J you@gateway dev@workspace`.

### From a pre-`target_suffix` release


Apply before restarting `serve` — unknown config keys are
rejected at startup, so a leftover `deployment.target_suffix` will fail
the boot:

- Remove `deployment.target_suffix` from `config.yaml`. The gateway no
  longer rewrites the outer username (`<target>.<suffix>`) into Coder
  CLI argv; the inner username is always the configured transport user.
- Stop appending a gateway suffix to workspace targets. The Coder CLI's
  `--hostname-suffix` flag is no longer used; workspace hostnames are
  exactly what users pass: `dev`, `dev.main`, `main.dev.alice`
  (dotted: `workspace`, `workspace.agent`, `agent.workspace.owner`),
  or the cross-user forms `alice/dev` and `alice/dev/main`
  (`owner/workspace[/agent]`).

## Self-enrollment (`login@`)

With `enrollment.enabled: true` (the default), users onboard
themselves from any device. The exact SSH command they run depends on
their local `~/.ssh/config` — they must use the configured
`coder-gateway-login` host alias (defined in the
[Client Setup](./client-setup.md#initial-enrollment-the-one-time-step)
guide) so OpenSSH selects the correct key, permits follow-up auth
methods, and pins the gateway port. A bare `ssh -p 2222 login@<gateway>`
does not satisfy any of those on a typical OpenSSH install.

The gateway's behavior once the user connects to `login@`:

1. Verifies the device's public-key proof of possession.
2. Prompts for a Coder session token (input is hidden).
3. Validates the token against Coder's `/api/v2/users/me`. **The Coder
   identity that owns the token anchors the gateway account** — the
   account is created or reused for that Coder user UUID, and the
   presented key is added to it.
4. Stores the token, prints "Enrolled.", and closes the connection by
   design. Reconnect with the normal workspace entry
   (`<workspace>@<gateway>`).

Idempotency: re-enrolling the same key with a token for the same Coder
user is a no-op success. A key already linked to a *different* account
is a hard rejection — nothing is mutated. The same wrong-identity
rejection applies on later renewals (the maintenance session): a
bound account will refuse a token for any Coder user other than the one
the account is bound to. On a *fresh* enrollment key (no prior
binding), the first valid token wins and binds that key — there is no
"wrong identity" for a fresh key, because identity is exactly what the
fresh key is asking to acquire.

To disable self-enrollment for closed memberships:

```yaml
enrollment:
  enabled: false
```

With it off, the `init` username behaves exactly like an unknown
username and the out-of-band flow below is the only enrollment path.

Security model: see [SECURITY.md](../SECURITY.md) for the threat model,
what the gateway protects, and what it cannot.

## Enrolling a user out-of-band

Use this when self-enrollment is disabled, or when you need to provision
a user before handing them a token. The gateway does not need to be
running, but it must NOT be running — the store lock is exclusive. On a
systemd host, stop the gateway first, run every mutation as the service
user so on-disk records land owned correctly with the expected `0600` /
`0700` modes, and restart the gateway afterward.

Tokens never travel through argv or environment variables. They cross
stdin into the service-user process via `--stdin` (or a hidden TTY
prompt). Only the SSH public key file needs to be staged for the
service user, because `admin key add --file` opens the path as the
service user.

### 1. Stop the gateway

```bash
sudo systemctl stop coder-ssh-gateway
```

### 2. Stage the public key

```bash
sudo install -d -o coder-ssh-gateway -g coder-ssh-gateway -m 0750 \
  /etc/coder-ssh-gateway.d
sudo install -o coder-ssh-gateway -g coder-ssh-gateway -m 0640 \
  ./ada.pub /etc/coder-ssh-gateway.d/ada.pub
```

### 3. Create the account

Either bind to a known Coder user UUID, or defer binding to the first
valid token.

```bash
sudo -u coder-ssh-gateway \
  coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway \
    admin account add --label "Ada" --bind-on-first-token
# or: admin account add --label "Ada" --coder-user-id <uuid>
```

### 4. Register the SSH public key

```bash
sudo -u coder-ssh-gateway \
  coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway \
    admin key add --account <account-uuid> \
    --file /etc/coder-ssh-gateway.d/ada.pub --label "ada-laptop"
```

### 5. Store the Coder session token via stdin

The token is read by your operator shell and only the resulting bytes
cross stdin into the service-user process. The token never appears on
the service user's filesystem, on argv, in an environment variable, or
in a displayed command substitution. The pipeline below emits exactly
two logical lines on stdin (the token, then `yes`) regardless of whether
the source file ends in a trailing newline:

```bash
{ awk 'NR == 1 { sub(/[[:space:]]+$/, ""); print; exit }' ./token.txt; printf '%s\n' yes; } | \
  sudo -u coder-ssh-gateway \
    coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway \
      admin credential set --account <account-uuid> --stdin
```

The `yes` confirmation is only required with `--bind-on-first-token`
(the deferred-binding path); with `--coder-user-id <uuid>` the account
is bound immediately and `credential set` only needs the token on
stdin:

```bash
{ awk 'NR == 1 { sub(/[[:space:]]+$/, ""); print; exit }' ./token.txt; } | \
  sudo -u coder-ssh-gateway \
    coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway \
      admin credential set --account <account-uuid> --stdin
```

### 6. Verify and restart

```bash
sudo -u coder-ssh-gateway \
  coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway \
    doctor --account <account-uuid>
sudo systemctl start coder-ssh-gateway
```

### Other admin operations

- `admin account list`
- `admin account disable --account UUID` / `admin account enable --account UUID`
- `admin key list --account UUID`
- `admin key disable --key UUID` / `admin key enable --key UUID`
- `admin credential status --account UUID` (state + generation)
- `admin credential clear --account UUID` (tombstones the credential —
  does NOT revoke the token in Coder)
- `admin disconnect --account UUID` — disables the account so new SSH
  authentication is blocked immediately. Does **not** terminate
  established tunnels and does **not** release their admission
  semaphore slots; those release only when the client disconnects or
  the spawned `coder` process exits.

## Configuration reference

Config file: `<state-dir>/config.yaml` by default; override with `--config`.
Relative paths in the file resolve against the config file's directory.
Unknown keys are rejected. Durations are strings like `30s`, `5m`.

The full annotated key reference lives at
[`config.example.yaml`](../config.example.yaml). Use it as the starting
point for review and customization; `init` is the recommended way to
generate secrets and the state layout.

### Path resolution: where do relative paths start?

The exact rule: **every explicit relative path in `config.yaml`
resolves against the directory containing `config.yaml`**, not
against `--state-dir`. `--state-dir` supplies only the store
directory (records, lock, audit); it does NOT choose where
`secrets/` lives — the secrets/ layout is determined by the
relative `ssh.host_keys` / `encryption.keys` paths. `--state-dir`
fills in those path fields only when they are UNSET; explicit
non-empty configured paths are NEVER rebased.

Concretely:

- **Generated config omits `state.dir`.** `init` writes the starter
  config WITHOUT a `state.dir` key. The state dir is then determined
  by, in order: `--state-dir` CLI flag → `state.dir` YAML value →
  the directory containing `config.yaml` (parser fallback to the
  config's parent). When `init` lays down the config inside the
  state directory it just created, that fallback is exactly the
  state dir, and the relative paths below resolve correctly.
- **Generated relative paths are config-file-relative.** `secrets/...`,
  `coder-config`, and `run` paths written by `init` resolve against
  the directory containing `config.yaml`. They do NOT depend on
  `--state-dir` or on your current shell.
- **`--state-dir` does not rebase configured paths.** If the config
  sits outside the state directory and `ssh.host_keys` /
  `encryption.keys` / `deployment.coder_global_config` /
  `deployment.working_directory` are explicit non-empty relative
  paths, those paths resolve against the config's parent regardless
  of `--state-dir`. The fix is one of: move the config file INSIDE
  the state directory; rewrite those four fields relative to the
  config's parent; or rewrite them as absolute paths. Setting
  `state.dir` to a different absolute path, or pairing
  `--state-dir` with `--config`, does NOT make those relative
  entries point at the state directory.
- **`init` writes no absolute state-owned paths.** Every path `init`
  emits is config-file-relative: `secrets/ssh_host_ed25519_key`,
  `secrets/credential-key-v1`, `coder-config`, `run`. There is no
  step in `init` that fills in absolute paths; if you see absolute
  paths in a YAML you wrote or edited yourself, those are
  operator-authored and need rebasing on a path change.

### Bind-address overrides

Three bind addresses can be overridden at `serve` time, after config
parse and before validation. Precedence for these three values is **CLI
flag > env var > config file > default**. An unset or empty environment
variable is ignored. Wildcard binds (`0.0.0.0`, `[::]`, empty host) are
accepted — that is the container use case. Applied CLI overrides are logged
at startup with their field, source, and non-secret address value.

| Global CLI flag | Environment variable | Overrides | Typical container value |
| --- | --- | --- | --- |
| `--listen-address` | `CSGW_LISTEN_ADDRESS` | `listen.address` | `0.0.0.0:2222` |
| `--metrics-address` | `CSGW_METRICS_ADDRESS` | `observability.metrics_address` | `0.0.0.0:9090` |
| `--health-address` | `CSGW_HEALTH_ADDRESS` | `observability.health_address` | `0.0.0.0:9091` |

Global flags must precede the subcommand. For example:

```bash
coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway \
  --listen-address 0.0.0.0:2222 \
  --metrics-address 0.0.0.0:9090 \
  --health-address 0.0.0.0:9091 serve
```

`doctor` never binds listeners, so address overrides only affect `serve`.
Use `--state-dir` to override the state directory; that flag always
wins over both `state.dir` in YAML and any default.

### Field reference

| Field | Default | Meaning |
| --- | --- | --- |
| `version` | `1` | Config schema version. |
| `listen.address` | `:22` | Outer SSH listen address (`:2222` in containers/dev). |
| `listen.handshake_timeout` | `30s` | Max time for the SSH handshake to complete. |
| `listen.renewal_auth_timeout` | `5m` | Handshake deadline extension while a credential renewal prompt is open. |
| `listen.tcp_keepalive` | `30s` | TCP keepalive on accepted connections. Must be positive; 0 is rejected at startup. |
| `listen.proxy_protocol` | `false` | Accept PROXY v1 headers. Enable only behind a trusted balancer; never auto-detected. |
| `ssh.server_version` | `SSH-2.0-CoderSSHGW_0.1` | SSH protocol version banner. |
| `ssh.host_keys` | `secrets/ssh_host_ed25519_key` (config-file-relative) | Host private key paths. Multiple keys supported for rotation. Startup fails if none load. |
| `ssh.allow_ssh_certificates` | `false` | Reserved for schema compatibility; `true` is rejected at startup. |
| `state.dir` | (none) | State directory; `--state-dir` flag wins over this. |
| `state.audit_retention_days` | `90` | Days to retain `audit/audit-YYYY-MM-DD.jsonl` files. |
| `encryption.provider` | `file` | Key provider. Only `file` is implemented. |
| `encryption.active_key_id` | `v1` | Key ID used for new writes. |
| `encryption.keys` | `v1: secrets/credential-key-v1` (config-file-relative) | Map of key ID to key file (raw 32 bytes or base64). Old IDs stay decryptable while listed. |
| `deployment.id` | `primary` | Deployment label. One deployment per gateway. |
| `deployment.coder_url` | (none) | Coder access URL. HTTPS only; HTTP is always rejected. |
| `deployment.coder_binary` | `/usr/local/bin/coder` | Path to the pinned Coder CLI. |
| `deployment.coder_global_config` | `coder-config` (config-file-relative) | Isolated Coder CLI global config dir. |
| `deployment.working_directory` | `run` (config-file-relative) | Working directory for spawned CLI processes. |
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
| `enrollment.enabled` | `true` | Enable the login@ token-anchored self-enrollment flow. |
| `enrollment.user` | `login` | SSH username that triggers enrollment. |
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

All store mutations are write-temp, fsync, rename, fsync(dir). Record
files are 0600, directories 0700. The flock is held for the process
lifetime, so exactly one gateway process may use a state dir; admin
commands and `serve` cannot overlap on the same dir.

## Backup and restore

Back up the state dir and the `secrets/` subdirectory **separately, to
separately restricted storage**:

- State dir without the encryption key cannot recover tokens.
- The encryption key without the state dir identifies nothing.
- Together they recover everything, so never store both in one backup
  bucket.

Two archives produced by separate `tar` invocations on disjoint paths so
a single bucket never holds both halves:

```bash
sudo systemctl stop coder-ssh-gateway            # release the flock first
# Ordinary state: EXCLUDE secrets/ so this archive is safe to drop in
# standard storage without exposing the encryption key.
sudo tar --exclude='./secrets' -C /var/lib/coder-ssh-gateway \
  -czf /backup/csgw-state-$(date +%F).tgz .
# Secrets: write to a separately restricted location (different bucket,
# different ACL, ideally different machine). NEVER in the same directory
# tree as the state archive.
sudo tar -C /var/lib/coder-ssh-gateway/secrets \
  -czf /secure-store/csgw-secrets-$(date +%F).tgz .
sudo systemctl start coder-ssh-gateway
```

### Restore

Restore is the reverse: stop the service, move the existing state tree
aside to a timestamped quarantine path (so a failed restore can be
recovered), create a clean `0700` target directory and a clean
`$STATE/secrets` subdirectory owned by the service user, extract the
ordinary state archive and the secrets archive separately as root with
`--no-same-owner`, chown the extracted tree to the service user,
normalize the canonical modes, and start the service.

The two archives MUST come from the same backup point; mismatched dates
will produce a tree where the encryption key belongs to a different
state version than the encrypted credentials.

```bash
set -euo pipefail
sudo systemctl stop coder-ssh-gateway            # release the flock first
STATE=/var/lib/coder-ssh-gateway
TS=$(date -u +%Y%m%dT%H%M%SZ)
# Move the current tree aside so an overlay restore can never leave a
# mixed snapshot behind. Keep the quarantine until the restored gateway
# boots and `doctor` passes.
if [ -d "$STATE" ]; then
  sudo mv "$STATE" "${STATE}.quarantine.${TS}"
fi
sudo install -d -o coder-ssh-gateway -g coder-ssh-gateway -m 0700 "$STATE"
sudo install -d -o coder-ssh-gateway -g coder-ssh-gateway -m 0700 "$STATE/secrets"
sudo tar -C "$STATE" --no-same-owner --preserve-permissions \
  -xzf /backup/csgw-state-<date>.tgz
sudo tar -C "$STATE/secrets" --no-same-owner --preserve-permissions \
  -xzf /secure-store/csgw-secrets-<date>.tgz
sudo chown -R coder-ssh-gateway:coder-ssh-gateway "$STATE"
sudo find "$STATE" -type d -exec chmod 0700 {} +
sudo find "$STATE" -type f -exec chmod 0600 {} +
sudo systemctl start coder-ssh-gateway
# After a successful first boot and `doctor` run, the quarantined tree
# can be deleted: sudo rm -rf "${STATE}.quarantine.${TS}".
```

After restore, run `doctor --account <uuid>` for one known account to
confirm the recovered credentials decrypt with the recovered key.

### Rebasing after a restore to a different path

`init` writes no absolute state-owned paths. Every path the starter
config contains is config-file-relative (`secrets/...`, `coder-config`,
`run`), so a config restored INSIDE its target state directory
re-resolves correctly with no edits — `state.dir` (if you set one)
becomes the only path you need to update.

If you restore to a different absolute path (different host, same path
no longer applies), edit the explicit operator-authored absolute
fields. `init` did not write these — they are values you added to
the YAML after `init` finished:

- `state.dir` (only if you set it explicitly)
- `ssh.host_keys` (only if you changed any entry to an absolute path)
- `encryption.keys` (only if you changed any entry to an absolute path)
- `deployment.coder_global_config` (only if you changed it from the
  shipped config-file-relative default)
- `deployment.working_directory` (only if you changed it from the
  shipped config-file-relative default)

Move each to its new absolute location; the relative default paths
keep working as long as the config file lives under the state
directory.

### Container and Kubernetes

The same split-archive principle holds, with paths adjusted:

- **Standalone Docker:** the named volume is the state dir. Stop the
  serve container, run a one-shot helper image (`busybox`, `alpine`,
  `debian:bookworm-slim`) with the volume mounted, and `tar` the two
  halves out to separate destinations. Restore the other way: stop the
  serve container, run a one-shot helper with the volume mounted,
  extract the two archives to the right paths inside the volume, then
  start the serve container. The distroless gateway image itself has
  no shell or `tar`, so it cannot serve as the helper.
- **Kubernetes:** PVC snapshot or `kubectl cp` for ordinary state. The
  distroless gateway image has no `tar`, so the extraction side of a
  restore needs a sidecar pod (for example the same busybox or alpine
  image) running with the PVC mounted read-write. Back up the two
  archives separately (for example a Velero schedule on the PVC plus
  an out-of-band copy of the encryption key Secret if you used a split
  mount).

## Encryption-key rotation

Multiple key versions are supported: every entry under
`encryption.keys` stays available for decryption while it remains
listed; `encryption.active_key_id` selects the key for new writes.
Until you remove the old key ID (or the key file), existing records
encrypted with the old key continue to decrypt. Removing the key file
is what breaks old records, not adding a new one.

1. Generate a new 32-byte key and place it at
   `<state-dir>/secrets/credential-key-v2` (mode 0600, owned by the
   service user).
2. Add `v2: <state-dir>/secrets/credential-key-v2` under
   `encryption.keys` alongside `v1`, and set `active_key_id: v2`.
3. Restart the gateway. New credential writes (renewals, `admin
   credential set`) now use v2 automatically. Verify with `doctor`: the
   encryption-key seal/open self-test must PASS.
4. Old records stay readable as long as `v1` stays under
   `encryption.keys`. The shipping CLI does not currently provide a
   built-in command to re-encrypt existing records in place; old
   records will progressively migrate as users renew their tokens.
   This is a deliberate gap: forcing a bulk re-encryption requires
   coordinated downtime, and any tool that re-writes ciphertexts at
   rest deserves operator review before shipping. Plan rotations
   accordingly.
5. Retire the old key ONLY after every record either references the
   new key version or has been deleted, AND after your oldest backup
   that still needs the old key has aged out. Inspect
   `credentials/*.json` — the `key_version` field names the key used
   to seal each record.
6. To retire the old key, remove its entry from `encryption.keys` AND
   delete its file under `<state-dir>/secrets/`. Do this in one
   maintenance window: stopping the gateway before editing config and
   restarting after, so you can roll back if a record fails to decrypt.

## Host-key rotation

1. Generate the new key:
   `ssh-keygen -t ed25519 -f ssh_host_ed25519_key.new -N ''`.
2. Publish the new fingerprint through your trusted channel.
3. Add the new path to `ssh.host_keys` alongside the old one (the gateway
   loads and offers all listed keys) and restart. Verify with `doctor`:
   it fingerprints every configured key, so both must appear.
4. Update clients and known_hosts records.
5. Remove the old key after a defined overlap period.

Client behavior during overlap varies; test Moshi specifically before
relying on seamless rotation. The gateway never auto-generates a host
key at startup: with no configured keys the gateway fails to boot,
deliberately.
