# Subprocess Boundary

**Status:** Accepted

## Context

The gateway invokes the official `coder` CLI as a subprocess (`coder ssh --stdio`) rather than importing Coder's internal Go packages or reproducing Coder's tailnet/DERP/workspace-resolution logic.

## Decision

Use the CLI subprocess boundary exclusively.

## Rationale

- The CLI is the stable integration boundary Coder itself uses for OpenSSH `ProxyCommand`.
- Importing Coder's internal packages would couple the project to AGPL-licensed internal APIs.
- The subprocess boundary cleanly separates licensing concerns and avoids importing Coder's AGPL code.
- The CLI handles workspace autostart, DERP relay, connection retries, and agent selection—none of which should be reimplemented.

## Consequences

- The gateway requires a compatible `coder` binary on the PATH or a configured path.
- The subprocess is constructed with an explicit argv array; no shell interpolation.
- The token is passed via environment (`CODER_SESSION_TOKEN`), never on the command line.
- The stdin/stdout pipes carry the raw SSH protocol; stderr is collected for diagnostics only.

## References

- Design §18 "Coder CLI bridge"
- Design §40 "Licensing boundary"
