# Coder SSH Gateway

> **Unofficial community project. Not affiliated with Coder.**

## SSH is everywhere. The Coder CLI isn't.

[Coder workspaces](https://coder.com) give you a fresh, consistent dev
environment on demand. Using one from your laptop is easy: install the
`coder` CLI, log in, and `coder ssh` you're in.

But the CLI has to be installed and authenticated *on every machine you
want to work from* — and those machines aren't always yours to install
things on. An iPad with a keyboard case. A borrowed laptop. A locked-down
work machine. A client's server you're debugging from.

All of those devices already speak SSH. This gateway sits in front of
your Coder deployment and speaks plain SSH to them: your SSH key proves
which device you are, and **the workspace name is the username**:

```
ssh general@gateway.example.com
```

That's the whole client-side story. No Coder CLI, no extensions, no
sync apps — any SSH client from the last decade works, including mobile
apps like Blink and Termius.

## What it looks like

You set up a host block once ([client setup](./docs/client-setup.md)),
then connect with the special `login` user. The gateway proves your key,
asks for a Coder token, and links the two:

```console
$ ssh login@gateway.example.com
New device enrollment. Provide your Coder token to link this key.
Coder SSH Gateway
New device enrollment.
Open https://coder.example.com/cli-auth, sign in, and paste the token below.
The token links this key to your Coder account. After verification
this connection will close; reconnect with your workspace connection.
Coder token:
Enrolled. Coder user alicia — key linked, token saved.
Reconnect using your workspace connection (<workspace>@<gateway>).
Enrollment complete. This connection will now close;
reconnect with your workspace connection (<workspace>@<gateway>).
Connection to gateway.example.com closed.
```

The token is never echoed and never touches your command line or shell
history. Now every workspace is just a username:

```console
$ ssh general@gateway.example.com
coder@alicia-general ~/code % whoami
coder
coder@alicia-general ~/code % uname -sm
Linux x86_64
coder@alicia-general ~/code % exit
Connection to gateway.example.com closed.
```

It's your workspace — your shell, your dotfiles, your files. When a
stored token eventually expires, a quick reconnect through the `auth`
user lets you paste a fresh one ([renewal](./docs/client-setup.md#credential-maintenance)).

## Installing

Three paths, simplest first. All of them take a few minutes.

### Docker

Build the image (or pull a published one), then run one container per
lifecycle step: `init` once to lay down keys and config, `doctor` to
verify, `serve` to run:

```bash
docker build -f deploy/Dockerfile -t coder-ssh-gateway .
docker run --rm -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway init coder.example.com
docker run --rm -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway doctor
docker run -d -p 2222:2222 -v csgw-state:/var/lib/coder-ssh-gateway \
  coder-ssh-gateway serve
```

Full walkthrough including config edits:
[Operator Guide → Container](./docs/operator-guide.md#container-standalone-docker).

### Kubernetes (Helm)

The chart self-provisions — it generates the encryption key (injected
via the environment, never written to disk next to your data), and the
host key is generated into the state volume on first boot:

```bash
helm install csgw deploy/helm/coder-ssh-gateway -n csgw --create-namespace \
  --set coder.domain=coder.example.com
```

Chart values, upgrades, and maintenance:
[Operator Guide → Kubernetes](./docs/operator-guide.md#kubernetes).

### Native (systemd)

Build a single static binary, initialize a state directory, and hand it
to the systemd unit:

```bash
make && sudo install -m 0755 bin/coder-ssh-gateway /usr/local/bin/
sudo useradd --system --home /var/lib/coder-ssh-gateway \
  --shell /usr/sbin/nologin coder-ssh-gateway
sudo install -d -o coder-ssh-gateway -g coder-ssh-gateway -m 0700 \
  /var/lib/coder-ssh-gateway
sudo -u coder-ssh-gateway coder-ssh-gateway \
  --state-dir /var/lib/coder-ssh-gateway init coder.example.com
sudo install -m 0644 deploy/systemd/coder-ssh-gateway.service \
  /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now coder-ssh-gateway
```

Host hardening, backups, and every flag:
[Operator Guide → Native install](./docs/operator-guide.md#native-install-systemd).

## How does it work?

One paragraph per moving part:

- **Your SSH key identifies the device.** On first connect, the gateway
  verifies you possess the key, then asks for a one-time Coder token and
  binds the two together. After that, the key alone logs you in — no
  token prompt, no passwords.
- **Tokens are stored encrypted.** The gateway keeps one Coder session
  token per user, encrypted at rest with a key that lives in the state
  directory's `secrets/` folder. That makes the gateway a
  credential broker: [treat the host accordingly](./SECURITY.md).
- **Each session becomes a Coder session.** For every accepted SSH
  channel the gateway spawns an isolated
  `coder ssh --stdio` child and bridges your terminal to it. Shell,
  exec, PTY, signals, and window changes all pass through (direct
  mode); ProxyJump is available when a client needs exotic inner-SSH
  features like SFTP or agent forwarding.
- **The username routes the connection.** `general` is your workspace,
  `general.main` names a specific agent. To reach a teammate's
  workspace, prefix the owner: `alicia/general` or
  `alicia/general/main` (owner/workspace/agent). The gateway never
  decides access — Coder's own permissions do. Details in
  [client setup](./docs/client-setup.md#daily-use-config).

## Things worth knowing before you go live

- **One instance per state directory.** A second writer fails on
  startup by design. In Kubernetes: `replicas: 1` and `Recreate` — the
  chart sets both.
- **Back up state and secrets separately.** State without the
  encryption key recovers nothing; together they recover everything, so
  they must never share a bucket.
  [Backup procedure](./docs/operator-guide.md#backup-and-restore).
- **Pin the host key fingerprint** before the first client connects.
  `init` prints it; publish it through a channel you trust.
- **Every key the gateway accepts** is documented, with defaults and
  security annotations, in [`config.example.yaml`](./config.example.yaml).

## Development

```bash
make test          # go test ./... -count=1
make test-race     # go test ./... -race -count=1
make ci            # test, race, vet, staticcheck, govulncheck
```

## License

[`LICENSE`](./LICENSE). Unofficial community project, not affiliated
with Coder. Coder is a trademark of its respective owners; references
to `coder ssh` and the Coder CLI describe compatibility, not
endorsement.
