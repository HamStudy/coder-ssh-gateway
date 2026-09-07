# deploy/helm/coder-ssh-gateway

Application chart for the gateway. Versioning is coupled to git tags by the publish pipeline — read this before any release.

## RELEASE LOCKSTEP (enforced, fails CI publish)
- Bump `Chart.yaml` `version` AND `appVersion` to the same semver BEFORE tagging `vX.Y.Z`.
- publish.yml guard: release fails if `appVersion` ≠ tag. Templates default the image tag to `.Chart.appVersion`, so a released chart always points at its built image.
- Chart is packaged with `--version` and `--app-version` set from the tag, pushed to the ghcr.io OCI registry at `oci://ghcr.io/<org>/charts/coder-ssh-gateway` (the documented install path), and the tarball attached to the GitHub Release as a fallback.

## INVARIANTS (do not template around these)
- Single replica, `Recreate` strategy: the store takes an exclusive lock; no HA parallel paths.
- Encryption key is env-only: injected as `CSGW_ENCRYPTION_KEY_V1` (or `env:` file source via configOverride), never written beside state.
- PVC and generated Secret carry `helm.sh/resource-policy: keep` — deletion loses host key/enrollments and rotation forces re-enrollment.
- `configOverride` deep-merges over the generated config: the supported escape hatch for any gateway setting the chart doesn't expose.

## SURFACE
- Install path: `oci://ghcr.io/<org>/charts/coder-ssh-gateway` (pushed by publish.yml on release tags); the GitHub Release tarball is the fallback asset.
- Service: LoadBalancer, external 22 → container 2222. Metrics service off by default. `terminationGracePeriodSeconds: 90` for tunnel drain.
- Values keys: image, coder, gateway, configOverride, secrets, service, metrics, persistence, resources, scheduling knobs.
- Changing generated config shape → update templates/configmap.yaml AND docs/operator-guide.md migration notes together.
