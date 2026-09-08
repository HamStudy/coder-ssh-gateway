# internal/server

Outer SSH listener: admission control, limits, handshake, auth callback installation, channel dispatch, shutdown/drain.

## WHERE TO LOOK
| Task | Location |
|------|----------|
| Listener + server config (no top-level KI/password) | listener.go |
| Per-connection admission → dispatch | connection.go `handleConn` |
| Channel admission rules | channels.go `dispatchWorkspaceChannels` |
| Restricted keymanagement dispatch (one session, no workspaceContext, no global transports) | keymanagement.go `dispatchKeyManagement` |
| Admission tests + limit races | listener_test.go, server_fixture_test.go, keymanagement_test.go |

## MODEL
- Admission order: pre-auth IP check → global/IP/handshake limits → optional PROXY-v1 → deadlines → handshake → auth callbacks → authenticated (account/key) limits → dispatch.
- Dispatch is mode-driven (the verified-key callback's permissions carry the mode). Workspace mode: ONE session channel per connection (`served` flag) + concurrent direct-tcpip channels, each handled in its own goroutine so multiplexing never blocks (session bridges included). Keymanagement mode: exactly one session channel running the account-scoped key-management UI (`internal/keymgmt`); every other channel type and every forwarding request refused at DEBUG with a logged reason. The post-auth block in `handleConn` constructs the `workspaceContext` and starts the workspace-backed global-requests goroutine **only** inside the `ModeWorkspace` branch — neither runs on keymanagement connections (a `workspaceContext` would let `tcpip-forward` reach the workspace transport, which violates the mode's hard rule).
- direct-tcpip routing (workspace mode): workspace-shaped :22 targets take the dedicated jump-tunnel path (TunnelStarter); every other target relays through the connection's workspace transport (ssh -L/-D). tcpip-forward/cancel global requests (ssh -R) also ride the transport. A nil WorkspaceTransports factory rejects relays and sessions but preserves jump tunnels.
- Channel admission happens BEFORE the slow child spawn; credential is reloaded/revalidated at channel open (generation-checked), not trusted from auth time. The session channel is accepted first, then `tunnel.BridgePendingSession` serves it while `bindTransport` starts concurrently (§19.9 optimistic acks — mobile clients time out on delayed pty/shell replies).
- Keymanagement dispatch refuses `direct-tcpip` / `forwarded-tcpip` / `x11` / `tcpip-forward` and every global request except `keepalive@openssh.com`. The kept key (`s.cfg.Auth.Store.(keymgmt.Store)`) is the same real store; `service.Run` holds the UI loop on the channel until quit, EOF, or successful account deletion, then exit-status 0 + close.
- Shutdown: listener close → drain period → connection cancellation → (children killed in internal/tunnel).
- Rejections are never silent: unsupported channel types WARN (post-auth, so they are incompatibility signals, not scanner noise); relay/enrollment/keymanagement request drains log every refusal at DEBUG; global requests log type at DEBUG with unknowns explicitly refused false.

## ANTI-PATTERNS
- No top-level password or keyboard-interactive auth — KI continuations are installed by sshauth after verified pubkey only.
- Do not widen channel admission without a limit to match (per-account channels/processes exist in internal/limits).
- Do not import `internal/keymgmt` from connection.go beyond the type assertion at shell time; the UI is its own package and its own lifecycle.
- Do not start a `coder ssh --stdio` child or load a credential on a keymanagement connection — there is no workspaceContext, no transport, and a child spawn would violate the mode's hard rule.

## TESTING
- Accept-backlog order is NOT dial order: tests that need a specific connection accepted first must wait for its banner byte before dialing the next (see TestAdmissionGlobalUnauthLimit).
- keymanagement_test.go covers: UI session reachable over an in-process ssh client; second session / direct-tcpip / tcpip-forward / exec / subsystem each refused with both the wire rejection and the DEBUG/INFO log line; fake coder records ZERO spawns during the whole scenario; workspace-mode regression tests still pass unchanged.
- leakCheck mirrors internal/sshauth (goleak ignoring HTTP persistConn).
