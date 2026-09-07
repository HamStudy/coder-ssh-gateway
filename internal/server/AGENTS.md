# internal/server

Outer SSH listener: admission control, limits, handshake, auth callback installation, channel dispatch, shutdown/drain.

## WHERE TO LOOK
| Task | Location |
|------|----------|
| Listener + server config (no top-level KI/password) | listener.go |
| Per-connection admission → dispatch | connection.go `handleConn` |
| Channel admission rules | channels.go `dispatchWorkspaceChannels` |
| Admission tests + limit races | listener_test.go, server_fixture_test.go |

## MODEL
- Admission order: pre-auth IP check → global/IP/handshake limits → optional PROXY-v1 → deadlines → handshake → auth callbacks → authenticated (account/key) limits → dispatch.
- Dispatch admits workspace permissions only: ONE session channel per connection (`served` flag) + concurrent direct-tcpip channels, each handled in its own goroutine so multiplexing never blocks (session bridges included).
- direct-tcpip routing: workspace-shaped :22 targets take the dedicated jump-tunnel path (TunnelStarter); every other target relays through the connection's workspace transport (ssh -L/-D). tcpip-forward/cancel global requests (ssh -R) also ride the transport. A nil WorkspaceTransports factory rejects relays and sessions but preserves jump tunnels.
- Channel admission happens BEFORE the slow child spawn; credential is reloaded/revalidated at channel open (generation-checked), not trusted from auth time. The session channel is accepted first, then `tunnel.BridgePendingSession` serves it while `bindTransport` starts concurrently (§19.9 optimistic acks — mobile clients time out on delayed pty/shell replies).
- Shutdown: listener close → drain period → connection cancellation → (children killed in internal/tunnel).
- Rejections are never silent: unsupported channel types WARN (post-auth, so they are incompatibility signals, not scanner noise); relay/enrollment request drains log every refusal at DEBUG; global requests log type at DEBUG with unknowns explicitly refused false.

## ANTI-PATTERNS
- No top-level password or keyboard-interactive auth — KI continuations are installed by sshauth after verified pubkey only.
- Do not widen channel admission without a limit to match (per-account channels/processes exist in internal/limits).

## TESTING
- Accept-backlog order is NOT dial order: tests that need a specific connection accepted first must wait for its banner byte before dialing the next (see TestAdmissionGlobalUnauthLimit).
- leakCheck mirrors internal/sshauth (goleak ignoring HTTP persistConn).
