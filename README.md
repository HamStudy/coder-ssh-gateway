# Coder SSH Gateway

> **Unofficial community project. Not affiliated with Coder.**

A small SSH gateway that lets any SSH client reach a Coder workspace by
hostname, with no extra software on the client side. The primary direct
flow is `ssh dev@gateway.example.com`: your enrolled key authenticates
first, then the outer username selects a bare Coder target (the
workspace, agent, or owner-qualified name). Direct mode forwards shell,
exec, PTY, environment, window-change, and signals to the inner Coder
session. ProxyJump remains available as the advanced raw-transport path
for clients that need full inner SSH features (SFTP, subsystem requests,
agent forwarding, port forwarding).

The gateway authenticates each device with the device's SSH public key, holds
an encrypted per-user Coder session token (one per gateway account), and
forwards each workspace channel to the official Coder CLI. Because the
gateway stores those tokens on your behalf, treat it as a high-value
credential broker and the host as a credential-storage target.

## What you can do

- **Connect from any SSH client.** Desktop, laptop, iPad, jump host. Same
  workflow once the client block is set up.
- **Self-enroll in one command.** Add a `coder-gateway-init` host
  block, then run `ssh coder-gateway-init` with a Coder session token.
  Your device is registered and the gateway links it to the Coder
  identity that owns the token. No operator action needed.
- **Use the gateway on port 22 or 2222.** Native installs default to 2222 so
  the host's sshd can keep port 22. Kubernetes exposes 22 on the public
  Service, mapping to 2222 inside the cluster.
- **Renew tokens interactively.** When the stored token expires, reconnect
  through the maintenance user and paste a fresh one.

## Pick your path

- **Deploy and operate the gateway** — [Operator Guide](./docs/operator-guide.md)
- **Connect from an SSH client (OpenSSH, Moshi, others)** — [Client Setup](./docs/client-setup.md)
- **Something broke** — [Troubleshooting](./docs/troubleshooting.md)
- **Threat model, secure deployment, incident response** — [SECURITY.md](./SECURITY.md)

## What the operator hands you

Before your first `ssh`, your operator sends you four values. Pin the host
key fingerprint in `known_hosts` before trusting the connection.

| Value | Example | What it is |
| --- | --- | --- |
| Gateway hostname | `gateway.example.com` | The DNS name (or IP) of the gateway. |
| External SSH port | `2222` (native) or `22` (Kubernetes) | The port you connect to. |
| `/cli-auth` URL | `https://coder.example.com/cli-auth` | Where you get your session token. |
| Host-key fingerprint | `SHA256:…` (Ed25519) | The gateway's outer host key, verified once. |

If your operator disabled self-enrollment, send your operator your SSH
**public key** (one file per device) and an account label. They will provision
your account and key out-of-band; you skip the `init@gateway` flow.

## Quick start (operators, native install)

The five-step path on a single Linux host. Full details, every flag, and
backup/restore live in the [Operator Guide](./docs/operator-guide.md).

```bash
# 1. Build the binary.
make
sudo install -m 0755 ./bin/coder-ssh-gateway /usr/local/bin/

# 2. Create the state directory and a dedicated service user.
sudo useradd --system --home /var/lib/coder-ssh-gateway \
  --shell /usr/sbin/nologin coder-ssh-gateway
sudo install -d -o coder-ssh-gateway -g coder-ssh-gateway -m 0700 \
  /var/lib/coder-ssh-gateway

# 3. Lay down the store, host key, credential encryption key, and starter
#    config for the named Coder deployment.
sudo -u coder-ssh-gateway \
  coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway init coder.example.com

# 4. Review the generated config. Its Coder URL came from init.
#    sudoedit runs as root but preserves the existing file's owner
#    and mode on save (no chown/chmod needed afterward).
sudoedit /var/lib/coder-ssh-gateway/config.yaml

# 5. Verify, then hand control to systemd (see next block). Do NOT
#    foreground `serve` in an unattended install — the next ssh in
#    will not start until that terminal closes.
sudo -u coder-ssh-gateway \
  coder-ssh-gateway --state-dir /var/lib/coder-ssh-gateway doctor
```

To run under systemd instead, install the unit shipped at
`deploy/systemd/coder-ssh-gateway.service` after step 4 and enable it:

```bash
sudo install -m 0644 \
  deploy/systemd/coder-ssh-gateway.service \
  /etc/systemd/system/coder-ssh-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable --now coder-ssh-gateway
sudo systemctl status coder-ssh-gateway   # confirm "active (running)"
```

The unit applies a hardened sandbox and uses the same `--state-dir`.

## Quick start (operators, container or Kubernetes)

- **Standalone Docker:** build with `docker build -f deploy/Dockerfile`,
  create a named volume, run `init` and `doctor` against it, edit
  `config.yaml` via `docker cp`, then start the hardened serve container.
  Full command sequence: [Operator Guide → Container](./docs/operator-guide.md#container-standalone-docker). The container story is one `docker run` per lifecycle stage.
- **Kubernetes:** a Helm chart at `deploy/helm/coder-ssh-gateway` —
  Secret-backed keys, a self-initializing Deployment, and one
  `coder.domain` value. Raw manifests (no Helm) live under
  `deploy/k8s/`. End-to-end sequences from an empty cluster:
  [Operator Guide → Kubernetes](./docs/operator-guide.md#kubernetes).

## Quick start (users, first connect)

```bash
# 1. Generate a dedicated key on this device, if you don't have one.
ssh-keygen -t ed25519 -f ~/.ssh/coder-gateway

# 2. Add an init host block FIRST — it lets the enrollment prompt
#    render after the public-key check. Without these follow-up
#    methods, OpenSSH silently gives up before the token prompt.
cat >> ~/.ssh/config <<'EOF'
Host coder-gateway-init
    HostName gateway.example.com
    Port 2222
    User init
    IdentitiesOnly yes
    IdentityFile ~/.ssh/coder-gateway
    PreferredAuthentications publickey,keyboard-interactive,password
    KbdInteractiveAuthentication yes
    PasswordAuthentication yes
EOF

# 3. Run the enrollment. The gateway accepts your newly generated key
#    and then prompts for a Coder token; the Coder identity that owns
#    that token becomes your gateway account.
ssh coder-gateway-init
#   -> open https://coder.example.com/cli-auth, copy the token,
#      paste it at the hidden prompt.
#   -> the gateway validates, links the key, prints "Enrolled.",
#      and disconnects by design.

# 4. Add the daily-use config (separate from the init block).
cat >> ~/.ssh/config <<'EOF'
Host gateway.example.com
    HostName gateway.example.com
    Port 2222
    IdentitiesOnly yes
    IdentityFile ~/.ssh/coder-gateway
EOF

# 5. Connect to a workspace.
ssh dev@gateway.example.com
```

Full client setup, Moshi configuration, and renewal flow:
[Client Setup](./docs/client-setup.md).

## Critical warnings

- **Single replica, by design.** Two writers on the same state directory
  fight over an exclusive lock and the second one fails. Native: one
  systemd unit. Kubernetes: `replicas: 1` and `Recreate` strategy. Do not
  scale.
- **Back up the state directory and the `secrets/` directory separately.**
  State without the encryption key recovers nothing. The encryption key
  without state identifies nothing. Together they recover everything — so
  they must NEVER share a backup bucket. Procedure:
  [Operator Guide → Backup and restore](./docs/operator-guide.md#backup-and-restore).
- **Treat the gateway host as a high-value credential broker.** It holds
  encrypted Coder session tokens. Harden the host, restrict access, and
  monitor audit logs. See [SECURITY.md](./SECURITY.md).
- **The Coder session token is short-lived.** When it expires, reconnect
  through the maintenance user and paste a new one — the gateway never
  accepts tokens on the command line. Renewal:
  [Client Setup → Credential maintenance](./docs/client-setup.md#credential-maintenance).
- **Verify the gateway host key on first connect.** Operators publish the
  fingerprint through a trusted channel. Pin it in `known_hosts` before
  answering `yes` to the prompt.

## Configuration reference

Every key the gateway accepts, with annotations marking required edits,
defaults, security-sensitive settings, and runtime overrides:
[`config.example.yaml`](./config.example.yaml).

## Migrating from earlier releases

Two surface changes affect operators upgrading from a pre-`target_suffix`
release:

- `deployment.target_suffix` is gone. The gateway no longer rewrites the
  outer username (`<target>.<suffix>`) into Coder CLI argv; the inner
  username is always the configured transport user. Remove the field
  from `config.yaml` if it is still present — unknown keys are rejected
  at startup.
- The Coder CLI's `--hostname-suffix` flag is no longer used. The
  workspace hostname is exactly what the operator passes (`dev`,
  `dev.main`, or `main.dev.alice` — one, two, or three labels in the
  form `workspace`, `workspace.agent`, or `agent.workspace.owner`).
  Do not append a gateway suffix to your workspace targets.

## Development

```bash
make test          # go test ./... -count=1
make test-race     # go test ./... -race -count=1
make lint          # go vet + staticcheck
make vuln          # govulncheck
make ci            # test, test-race, lint, vuln
```

## License

[`LICENSE`](./LICENSE). This is an unofficial community project, not
affiliated with Coder. Coder is a trademark of its respective owners;
references to Coder, `coder ssh`, and the Coder CLI describe compatibility
with that product, not endorsement.
