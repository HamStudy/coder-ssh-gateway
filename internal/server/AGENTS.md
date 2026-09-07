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
- Dispatch admits workspace permissions only: ONE session channel per connection (`served` flag) + concurrent direct-tcpip channels. Direct-tcpip admission runs in separate goroutines so one slow target never blocks multiplexing.
- Channel admission happens BEFORE the slow child spawn; credential is reloaded/revalidated at channel open (generation-checked), not trusted from auth time.
- Shutdown: listener close → drain period → connection cancellation → (children killed in internal/tunnel).

## ANTI-PATTERNS
- No top-level password or keyboard-interactive auth — KI continuations are installed by sshauth after verified pubkey only.
- Do not widen channel admission without a limit to match (per-account channels/processes exist in internal/limits).

## TESTING
- Accept-backlog order is NOT dial order: tests that need a specific connection accepted first must wait for its banner byte before dialing the next (see TestAdmissionGlobalUnauthLimit).
- leakCheck mirrors internal/sshauth (goleak ignoring HTTP persistConn).
