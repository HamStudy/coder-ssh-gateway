# 4. Shared-state multi-instance

Date: 2026-09-07
Status: Accepted (supersedes the single-instance stance of
[ADR-0002](0002-single-deployment-mvp.md) and the direct-tcpip-era lock
description in [ADR-0003](0003-direct-tcpip-jump-design.md))

## Context

The store originally took an exclusive `flock(LOCK_EX)` on
`<state-dir>/lock` for the process lifetime: a second process failed fast
with `ErrStoreLocked`, making the gateway single-replica by construction.
Two problems fell out of that:

1. Admin commands (`admin credential …`, account management) could not
   run while the gateway served — the operator had to stop the gateway to
   manage it.
2. Kubernetes deployments could not run more than one replica, so
   upgrades restarted the listener and there was no HA path.

## Decision

- `store.Open` takes a **shared** `flock(LOCK_SH)` for the process
  lifetime. Any number of instances may hold the state directory open at
  once; only an exclusive holder (an older offline admin build) still
  blocks `Open` with `ErrStoreLocked`.
- Correctness under concurrency comes from the existing durability
  design, not from the lock: every mutation is temp-file → fsync →
  rename → fsync-dir (readers always see one whole record), and
  credential replacement is compare-and-swap on the credential
  generation (`ReplaceCredential` + `ExpectedGeneration`), so two
  writers racing on one account resolve with
  `ErrGenerationConflict` instead of corruption.
- The flock is **advisory**: on filesystems with unreliable locks (many
  NFS servers, some Gluster volumes) deployments run on atomic-rename +
  CAS alone. `stray *.tmp` cleanup only reaps files older than 10
  minutes so a live peer's in-flight write is never deleted.
- Audit files gain an instance suffix
  (`audit-<date>.<instance>.jsonl`; `CSGW_AUDIT_INSTANCE`, else
  `HOSTNAME`) so concurrent instances never share an append target; the
  retention sweep parses the date before the suffix.
- The Helm chart exposes `replicaCount` (default 1) and rolls with
  `RollingUpdate`.

## Consequences

- Admin commands work against a live gateway; `admin credential set`
  while serving is last-writer-wins with respect to concurrent renewals
  (the CAS resolves the race).
- Connection/rate limits are enforced **per instance**; global limits
  are the sum across replicas. Size them accordingly.
- The state directory must be on a volume with POSIX-atomic rename
  (NFSv4, Gluster, CephFS qualify). Write-after-rename visibility of
  config changes is per-connection: instances reload credentials per
  channel open, so an admin change propagates without restarts.
- `doctor`'s state-dir check no longer reports "lock acquirable"; it
  reports accessibility and VERSION.
