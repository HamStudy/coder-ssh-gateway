# Client Setup — coder-ssh-gateway

Adapted from design section 45 to a gateway at `gateway.example.com` serving
the workspace suffix `coder-gateway.example.com` (Coder deployment
`https://example.test`). Substitute your own hostnames.

You will receive from your operator:

- the gateway hostname and port;
- the gateway's outer host-key fingerprint (verify it on first connect).

You do NOT need the operator to pre-register anything: the gateway enrolls
your key itself on first connect (see the next section). If your operator has
disabled self-enrollment, you will instead receive confirmation that your SSH
public key and account were provisioned out-of-band; in that case skip to the
per-client sections.

## Initial enrollment (primary onboarding path)

Run this once from **every** machine that will connect. From any system with
an SSH client:

```bash
ssh init@gateway.example.com
```

What happens:

1. Your SSH client proves possession of this machine's private key (the key
   must exist — generate one with `ssh-keygen -t ed25519` if needed).
2. The gateway answers with a banner ("New device enrollment…") and prompts
   `Coder token: `.
3. Open `https://example.test/cli-auth` in a browser, copy the session
   token shown there, and paste it at the prompt (input is hidden).
4. The gateway validates the token against Coder, links this machine's key
   to your Coder account, stores the token, prints a confirmation
   ("Enrolled. Coder user …"), and closes the connection.

That is the whole enrollment. The connection closes by design — reconnect
with your normal workspace connection (`coder@…`, below). Repeat from every
device; each device's key lands on the same account as long as you paste a
token for the same Coder user.

For the inline token prompt to render, the client must permit the follow-up
authentication methods. A dedicated host block does this without touching
your workspace entries:

```sshconfig
Host coder-gateway-init
    HostName gateway.example.com
    User init
    IdentitiesOnly yes
    IdentityFile ~/.ssh/coder-gateway
    PreferredAuthentications publickey,keyboard-interactive,password
    KbdInteractiveAuthentication yes
    PasswordAuthentication yes
```

Then `ssh coder-gateway-init`. Enabling `password` here does not enable
token-only login — your public key is always required first; the password
method only lets the hidden token prompt render after the key is accepted.

A key that is already linked to a *different* account is rejected with an
explanatory banner and nothing is changed; use a per-device key, or ask your
operator to remove the stale key registration.

## OpenSSH (desktop/laptop)

### Basic per-host configuration

```sshconfig
Host *.coder-gateway.example.com
    User coder
    ProxyJump coder@gateway.example.com
    IdentitiesOnly yes
    IdentityFile ~/.ssh/coder-gateway
```

The first `User coder` is the inner SSH username at the workspace. The jump
username in `ProxyJump` is the gateway's transport user (`coder` by
default).

### More explicit form

```sshconfig
Host coder-jump
    HostName gateway.example.com
    User coder
    Port 22
    IdentitiesOnly yes
    IdentityFile ~/.ssh/coder-gateway

Host *.coder-gateway.example.com
    User coder
    ProxyJump coder-jump
```

### Credential maintenance entry

```sshconfig
Host coder-gateway-auth
    HostName gateway.example.com
    User auth
    Port 22
    IdentitiesOnly yes
    IdentityFile ~/.ssh/coder-gateway
```

Daily use:

```bash
ssh dev.coder-gateway.example.com    # workspace
ssh coder-gateway-auth           # token maintenance session
```

### Renewal-friendly variant

The gateway can offer a token prompt inline when your stored credential has
expired. For that continuation to work, the client must permit the
follow-up methods:

```sshconfig
Host coder-jump
    PreferredAuthentications publickey,keyboard-interactive,password
    KbdInteractiveAuthentication yes
    PasswordAuthentication yes
```

The server still requires your public key first. Enabling password here
does not enable token-only gateway login; it only lets the hidden token
prompt render after your key is accepted.

### First connection

1. `ssh coder-gateway-init` (or `ssh init@gateway.example.com`) and compare
   the displayed host-key fingerprint against the one your operator
   published before answering `yes`.
2. Paste your Coder session token at the `Coder token:` prompt, wait for
   the "Enrolled." confirmation, and let the connection close.
3. `ssh dev.coder-gateway.example.com`.

Step 2 stores the token; you only repeat it when the token expires (see the
maintenance entry above).

## Moshi (iPad)

Moshi does not run `ssh_config`; configure three saved connections. The
first one is for enrollment.

### Enrollment connection

```text
Name:             Coder Gateway Init
Connection type:  SSH
Host:             gateway.example.com
Port:             22
Username:         init
Authentication:   this device's SSH key
Jump host:        none
```

Open it once: the gateway prompts for your Coder token (from
`https://example.test/cli-auth`), links this iPad's key to your Coder
account, confirms, and disconnects. Repeat on each new device.

### Workspace connection

```text
Name:             Coder - dev
Connection type:  SSH
Host:             dev.coder-gateway.example.com
Port:             22
Username:         coder
Jump host:        gateway.example.com
Jump port:        22
Jump username:    coder
Jump auth:        registered SSH key
```

### Maintenance connection

```text
Name:             Coder Gateway Auth
Connection type:  SSH
Host:             gateway.example.com
Port:             22
Username:         auth
Authentication:   same registered SSH key
Jump host:        none
```

### Expired-token workflow

1. Open the workspace connection.
2. If Moshi renders the gateway's second authentication step, open the
   displayed `/cli-auth` URL in a browser, create a token, and paste it at
   the prompt.
3. The gateway validates, stores, confirms, and closes the connection.
4. Reopen the workspace connection.
5. If Moshi does not render the second authentication method, open the
   **Coder Gateway Auth** connection instead, paste the token there, wait
   for the confirmation and disconnect, then reopen the workspace
   connection.

## Host keys: what you are trusting

Each connection authenticates TWO different SSH servers:

- `gateway.example.com`: the gateway's outer host key. Its fingerprint is
  published by your operator; verify it on first connect and pin it in
  `known_hosts`.
- `dev.coder-gateway.example.com`: the inner Coder workspace agent host key,
  which follows Coder's own SSH behavior.

Do not disable host-key checking globally. If the inner agent keys churn
too often for your taste, scope any lenient policy to the workspace suffix
only, for example:

```sshconfig
Host *.coder-gateway.example.com
    StrictHostKeyChecking accept-new
```

This trusts new inner host keys on first use for Coder workspace names only
and leaves checking fully enforced everywhere else, including the gateway
hop itself. Understand the trade: an `accept-new` inner policy means the
first connection to a given workspace name is not authenticated against a
known key; Coder's agent keys are not pinned by the gateway, so you are
trusting Coder's inner layer exactly as you would when using `coder ssh`
directly.
