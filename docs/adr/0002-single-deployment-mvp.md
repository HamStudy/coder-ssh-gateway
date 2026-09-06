# Single Deployment MVP

**Status:** Accepted

## Context

SSH user authentication completes before the client opens a `direct-tcpip` channel, so at the moment the gateway must validate a stored Coder token it does not yet know the requested workspace target hostname.

## Decision

Each gateway listener has exactly one active Coder deployment. A public key maps unambiguously to one account in that deployment.

## Rationale

There is no TLS-SNI-like target name in the initial SSH transport handshake. A single listener cannot safely select among multiple Coder deployments solely from the later target suffix. Adding deployment selection to the outer username or a dedicated listener is deferred to post-MVP work.

## Consequences

- One `--coder-url`, one token store, one set of account bindings per listener.
- Multi-deployment routing requires explicit selectors (outer username suffix, dedicated listener, dedicated port/IP, or unique-key mapping) deferred to future work.
- The storage schema includes `deployment_id` now so a future migration is possible without a schema change.
