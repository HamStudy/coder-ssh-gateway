# Client Setup — coder-ssh-gateway

How to connect to the gateway from any SSH client. The examples below
use these placeholders:

- `gateway.example.com` — the gateway's external hostname
- `coder.example.com` — your Coder deployment

Replace each with the values your operator gave you before use. The
gateway listens on port `2222` by default on native installs. In
Kubernetes, the typical deployment exposes external port 22 on a
LoadBalancer Service; if your operator chose that mapping, drop the
`-p 2222` from the examples and just use `ssh host`.

## What your operator hands you

Before your first `ssh`, you need four things:

1. **Gateway hostname** — the DNS name or IP of the gateway.
2. **External SSH port** — `2222` for native/container, `22` for the
   typical Kubernetes LoadBalancer.
3. **`/cli-auth` URL** — `https://coder.example.com/cli-auth` in the
   examples. Open it in a browser to copy a short-lived session token.
4. **Gateway host-key fingerprint** — verify this on first connect
   before answering `yes`.

## Initial enrollment (the one-time step)

Run this once from every machine that will connect. Generate a key if
needed:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/coder-gateway
```

For the inline token prompt to render, the client must permit the
follow-up authentication methods. A dedicated host block does this
without touching your workspace entries:

```sshconfig
Host coder-gateway-login
    HostName gateway.example.com
    Port 2222
    User login
    IdentitiesOnly yes
    IdentityFile ~/.ssh/coder-gateway
    PreferredAuthentications publickey,keyboard-interactive,password
    KbdInteractiveAuthentication yes
    PasswordAuthentication yes
```

Then:

```bash
ssh coder-gateway-login
```

What happens:

1. Your SSH client proves possession of `~/.ssh/coder-gateway`.
2. The gateway shows the deployment's `/cli-auth` URL and prompts
   `Coder token:` (input is hidden).
3. Open `https://coder.example.com/cli-auth` in a browser, copy the
   session token, and paste it at the prompt.
4. The gateway validates the token against Coder, links this machine's
   key to your Coder account, stores the token, prints a confirmation,
   and **closes the connection by design**.

The disconnect is intentional. Reconnect with your normal workspace
entry. Repeat on every new device — each device's key lands on the
same account as long as you paste a token for the same Coder user.

A key already linked to a *different* account is rejected with an
explanatory banner and no mutation. Use a per-device key, or ask your
operator to remove the stale registration.

> The `password` method here does not enable token-only login — your
> public key is always required first. The password method only lets the
> hidden token prompt render after the key is accepted.

If your operator disabled self-enrollment, you will instead receive
confirmation that your SSH public key and account were provisioned
out-of-band. Skip ahead to the per-client sections below.

## OpenSSH (desktop/laptop)

### Daily-use config

The primary flow is a direct workspace username:
`ssh dev@gateway.example.com` (with the configured gateway port or
host alias). Your enrolled public key authenticates the gateway account
first; the outer username (`dev`) is then the strict bare Coder target
the gateway forwards to `coder ssh --stdio`. Malformed or missing
workspace targets fail after authentication — the gateway never reveals
whether the username, key, or account was wrong.

```sshconfig
Host gateway.example.com
    Port 2222
    IdentitiesOnly yes
    IdentityFile ~/.ssh/coder-gateway
```

Then connect directly:

```bash
ssh dev@gateway.example.com
```

Workspace target forms the username accepts:

- `dev` — your workspace (default agent)
- `dev.main` — your workspace, named agent
- `alice/dev`, `alice/dev/main` — a teammate's workspace
  (`owner/workspace[/agent]`)

The gateway only forwards the target; Coder's own permissions decide
whether your account may connect to it.

### What direct mode supports

The direct flow bridges a constrained session channel to a fresh inner
`coder ssh --stdio` session:

- shell (default)
- `exec` (single command)
- `pty-req` (allocate a PTY)
- `env` (forward environment variables)
- `window-change` (terminal resize)
- signals (the inner CLI process exits cleanly on hangup)
- subsystems — `sftp` (so `sftp`, GUI SFTP clients, and modern `scp` work)
- agent forwarding (`ssh -A`): the workspace reaches your local agent
- port forwarding: `-L` (local), `-R` (remote), and `-D` (dynamic/SOCKS)

Port-forwarding targets resolve inside the workspace network, exactly as
if you were connected to the workspace directly: `-L 8080:localhost:8080`
reaches the dev server running in your workspace. Targets shaped like a
workspace (`workspace:22`) instead open a jump tunnel to that workspace,
so ProxyJump keeps working on the same connection.

### ProxyJump — raw inner SSH transport

`ProxyJump` (`-J`) carries your own OpenSSH session through the gateway
as a transport hop and lands on the inner Coder workspace SSH server.
Everything above already works without it; the jump remains available
for exotic inner-SSH features the gateway does not bridge (for example
stream-local forwarding) or when a client wants the gateway treated as a
plain jump host:

```sshconfig
Host csgw-jump
    HostName gateway.example.com
    Port 2222
    User coder
    IdentitiesOnly yes
    IdentityFile ~/.ssh/coder-gateway

Host dev
    User coder
    ProxyJump csgw-jump
```

Connect to a workspace:

```bash
ssh dev
```

`-J` flags spawn a separate ssh child that does not inherit the
parent's `-o` options, so keep the jump in your config file.

### More explicit form

If you prefer each setting on its own line:

```sshconfig
Host coder-jump
    HostName gateway.example.com
    User coder
    Port 2222
    IdentitiesOnly yes
    IdentityFile ~/.ssh/coder-gateway

Host dev
    User coder
    ProxyJump coder-jump
```

### First connection (verification)

1. `ssh coder-gateway-login` and compare the displayed host-key
   fingerprint against the one your operator published **before
   answering `yes`**.
2. Paste your Coder session token at the `Coder token:` prompt, wait
   for the "Enrolled." confirmation, and let the connection close.
3. `ssh dev`.

Step 2 stores the token. You only repeat it when the token expires (see
[Credential maintenance](#credential-maintenance)).

## Moshi (iPad)

Moshi does not run `ssh_config`; configure three saved connections. The
first one is for enrollment.

### Enrollment connection

```text
Name:             Coder Gateway Init
Connection type:  SSH
Host:             gateway.example.com
Port:             2222
Username:         login
Authentication:   this device's SSH key
Jump host:        none
```

Open it once: the gateway prompts for your Coder token (paste it from
`https://coder.example.com/cli-auth`), links this iPad's key to your
Coder account, confirms, and disconnects. Repeat on each new device.

On first connect, **compare the host-key fingerprint shown by Moshi
against the fingerprint your operator published** before accepting the
prompt.

### Workspace connection

```text
Name:             Coder - dev
Connection type:  SSH
Host:             dev
Port:             22
Username:         coder
Jump host:        gateway.example.com
Jump port:        2222
Jump username:    coder
Jump auth:        registered SSH key
```

The inner port (`22`) is the Coder workspace agent SSH port, set by
Coder, not the gateway. The outer port (`2222`) is the gateway's
external SSH listener.

### Expired-token workflow

1. Open the workspace connection as usual.
2. The gateway reports the stored credential is expired and shows the
   hidden `Coder token:` prompt. Open the displayed `/cli-auth` URL in
   a browser, create a token, and paste it.
3. The gateway validates, stores, and continues straight into the
   workspace — no reconnect.

If Moshi does not render the second authentication method, add the
follow-up methods to the workspace connection (see
[Credential maintenance](#credential-maintenance)).

## Credential maintenance

When the stored token expires, your next workspace connection prompts
you for a fresh token inline — same connection, same key, no special
username. Paste it once and you land straight in the workspace.

For the prompt to render, the workspace connection must allow the
follow-up authentication methods (your key is still verified first;
enabling password here does not enable token-only gateway login):

```sshconfig
Host gateway.example.com
    Port 2222
    IdentitiesOnly yes
    IdentityFile ~/.ssh/coder-gateway
    PreferredAuthentications publickey,keyboard-interactive,password
    KbdInteractiveAuthentication yes
    PasswordAuthentication yes
```

The flow: connect as usual; the gateway tells you the stored credential
is expired and shows the hidden `Coder token:` prompt; paste a fresh
token from the `/cli-auth` page; the connection continues straight into
your workspace. The token is never echoed and never touches your
command line or shell history.

## Host keys: what you are trusting

Each connection authenticates TWO different SSH servers:

- `gateway.example.com` — the gateway's outer host key. Its fingerprint
  is published by your operator; verify it on first connect and pin it
  in `known_hosts`.
- `dev` — the inner Coder workspace agent
  host key, which follows Coder's own SSH behavior.

Do not disable host-key checking globally. If the inner agent keys
churn too often for your taste, scope any lenient policy to the exact
workspace targets you use, for example:

```sshconfig
Host dev
    StrictHostKeyChecking accept-new
```

This trusts new inner host keys on first use for Coder workspace names
only and leaves checking fully enforced everywhere else, including the
gateway hop itself. Understand the trade: an `accept-new` inner policy
means the first connection to a given workspace name is not
authenticated against a known key; you are trusting Coder's inner layer
exactly as you would when using `coder ssh` directly.

## Common client mistakes

- **Forgetting the gateway port.** If your operator chose 2222 (the
  native default), `ssh gateway.example.com` connects to the host's own
  sshd, not the gateway. Set `Port 2222` on the jump block or pass
  `-p 2222`.
- **Using a key that's already linked elsewhere.** Each device needs its
  own key. Generate one with `ssh-keygen` per device.
- **Pasting the wrong token.** The token must be a working Coder
  session token. On a *fresh* enrollment (no prior binding) the first
  valid token anchors whichever Coder identity owns it, so any token
  you can issue works. On an *inline renewal* (expired stored token),
  or on a *re-enrollment* of a key already linked to an account, the
  token must be for the Coder user that account is bound to;
  otherwise the gateway rejects it as `AUTH_WRONG_CODER_IDENTITY`
  and closes without mutation. If you see that error on a renewal,
  fetch a fresh token from `https://coder.example.com/cli-auth`
  while signed in as your own Coder user.
- **Mixing up the inner and outer ports.** The gateway listens on the
  outer port (2222 native, 22 in many Kubernetes deployments). The
  inner Coder workspace agent always listens on 22, regardless of the
  gateway's port.
- **Disabling password auth "for security".** The inline renewal flow uses
  a `password` method prompt only to render the hidden token input.
  Disabling it disables token renewal, not just password login.

## What to read next

- Something broke — [Troubleshooting](./troubleshooting.md)
- Operator-side configuration — [Operator Guide](./operator-guide.md)
