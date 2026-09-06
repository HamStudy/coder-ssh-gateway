# Direct-TCP/IP Jump Design

**Status:** Accepted

## Context

The gateway must preserve full SSH semantics (PTY, exec, Herdr/tmux/Zellij discovery, SFTP, agent forwarding, port forwarding) without implementing a terminal emulator or protocol translator.

## Decision

Use SSH `direct-tcpip` channels as the sole transport mechanism. Do not accept `session` channels for workspace connections. The `direct-tcpip` target hostname carries workspace routing information; the inner SSH session is opaque bytes through `coder ssh --stdio`.

## Rationale

- `direct-tcpip` already contains the required routing information (target host, port) per RFC 4254 §7.2.
- The inner SSH connection stays end-to-end encrypted; the gateway forwards opaque bytes.
- All Moshi/SSH client features (multiplexer discovery, PTY, exec, forwarding) work without gateway awareness.
- The alternative—terminating the outer SSH session and translating session requests—would put terminal plaintext at the gateway and require reimplementing significant SSH semantics.

## Consequences

- Only `direct-tcpip` is accepted for transport mode; `session` channels are rejected.
- The `auth` maintenance mode uses a restricted `session` channel for a built-in credential-repair interface.
- Channel rejection uses RFC 4254 reason codes: `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`, `SSH_OPEN_UNKNOWN_CHANNEL_TYPE`, `SSH_OPEN_RESOURCE_SHORTAGE`, `SSH_OPEN_CONNECT_FAILED`.
