# Kubernetes notes — coder-ssh-gateway

These manifests adapt design section 31.7 to the flat-file store. They are
an architectural example, not a drop-in chart: image, storage class, secret
management, and addresses must be adapted to your cluster.

## What differs from the design example

The design assumed SQLite. The shipped store is flat files under ONE state
directory (`/var/lib/coder-ssh-gateway`), which changes the volume story:

- **One PVC, not several.** Records, audit log, and the default secret
  location all live under the single state dir. `pvc.yaml` requests a single
  `ReadWriteOnce` volume mounted at `/var/lib/coder-ssh-gateway`.
- **Secrets default to inside the state dir.** `init` writes the host key and
  credential encryption key to `<state-dir>/secrets/` with mode 0600. If you
  accept that model, no Kubernetes Secrets are required at all: the PVC alone
  preserves identity and decryptability across pod restarts.
- **Split-mount alternative.** If your policy requires Kubernetes Secrets,
  create two Secrets (host key, encryption key), mount them read-only (e.g.
  at `/run/secrets/host-key` and `/run/secrets/encryption-key`, defaultMode
  0400), and point `ssh.host_keys` and `encryption.keys` in `config.yaml` at
  those paths. The PVC then holds only non-secret records and audit logs.
  Either way, back up the encryption key separately from the PVC (design
  section 22.4): state dir plus key together recover everything; each alone
  recovers nothing.

## Single replica, on purpose

`strategy.type: Recreate` plus `replicas: 1` is required, not a default. The
store holds an exclusive flock on `<state-dir>/lock` for the process
lifetime; a second pod mounting the same PVC fails fast at startup. Do not
scale this Deployment. There is no midstream failover: active tunnels die
with the pod and clients reconnect.

## Config and bootstrap

`config.yaml` lives in the state dir by default (the CLI resolves
`--config` to `<state-dir>/config.yaml`). Two ways to get it there:

1. Run `init` once against the mounted volume (a short-lived Job or
   `kubectl exec` into the first pod before `serve` starts), then edit.
2. Maintain `config.yaml` as a ConfigMap mounted read-only over
   `/var/lib/coder-ssh-gateway/config.yaml`, and pass `--config
   /path/to/config.yaml` before `serve` in the container args.

## Health probes

`/livez` and `/readyz` are served on `observability.health_address`
(default `127.0.0.1:9091`; set it to `:9091` in config so the kubelet can
reach them). Liveness means the process and store lock are healthy;
readiness additionally means the deployment config is usable. During
SIGTERM shutdown readiness flips false while active tunnels drain, so pair
`terminationGracePeriodSeconds: 90` with your configured drain period.

## Network policy (design section 31.5)

Egress must permit more than the Coder API hostname, or workspace
connections degrade to relay-only or break:

- Coder access URL (HTTPS);
- configured workspace proxies;
- configured DERP servers;
- DNS;
- NTP (time sync);
- direct peer UDP paths when Coder uses direct tailnet connectivity.

Ingress: only the SSH listener (2222) needs to admit traffic, and only from
the load balancer. There is no HTTP ingress; the metrics (9090) and health
(9091) ports are scraped/probed from inside the cluster.

## PROXY protocol

If your load balancer speaks PROXY v1, set `listen.proxy_protocol: true` in
`config.yaml` and restrict the Service to the balancer's source ranges. The
gateway never auto-detects PROXY headers (design section 31.4); with the
option off, PROXY bytes are ignored and the socket peer is used.
