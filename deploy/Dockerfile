# coder-ssh-gateway container image (design section 31.2).
#
# Multi-stage: build the gateway from source, fetch a checksummed Coder CLI,
# assemble a minimal non-root runtime image (distroless: no shell, no package
# manager, no compiler).
#
# Build:
#   docker build -f deploy/Dockerfile -t coder-ssh-gateway:dev .
#
# CODER_SHA256 below pins coder_${CODER_VERSION#v}_linux_amd64.tar.gz and is
# baked in; override both args together when bumping the Coder CLI:
#   curl -sSL https://github.com/coder/coder/releases/download/v2.35.2/coder_2.35.2_linux_amd64.tar.gz | sha256sum
# (release asset names: https://github.com/coder/coder/releases)
#
# The pinned Go toolchain mirrors go.mod's toolchain directive. Bump
# GO_VERSION when go.mod moves.

ARG GO_VERSION=1.26.6

# ---------- builder ----------
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
    -o /out/coder-ssh-gateway ./cmd/coder-ssh-gateway

# Empty state dir staged here because the runtime image is distroless (no
# shell, no mkdir); COPY --chown then hands it to the runtime uid.
RUN mkdir -p /out/state

# ---------- coder cli fetch ----------
FROM debian:bookworm-slim AS codercli

ARG CODER_VERSION=v2.35.2
# sha256 of coder_${CODER_VERSION#v}_linux_amd64.tar.gz, baked in and
# verified against the v2.35.2 release. Overridable via --build-arg for
# version bumps; the build still fails closed on empty or mismatch
# (section 31.2: verify checksums).
ARG CODER_SHA256=907017ffefae1af67bd6533b6c9ddd6b975e39ea9ef9340deba3dc72231b209c

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    [ -n "$CODER_SHA256" ] || { echo "CODER_SHA256 build arg is required" >&2; exit 1; }; \
    ver="${CODER_VERSION#v}"; \
    curl -fsSL -o /tmp/coder.tar.gz \
      "https://github.com/coder/coder/releases/download/${CODER_VERSION}/coder_${ver}_linux_amd64.tar.gz"; \
    echo "${CODER_SHA256}  /tmp/coder.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/coder.tar.gz -C /usr/local/bin ./coder; \
    chmod 0755 /usr/local/bin/coder

# ---------- runtime ----------
# static-debian12:nonroot: uid/gid 65532, CA certificates included, no shell.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/coder-ssh-gateway /usr/local/bin/coder-ssh-gateway
COPY --from=codercli /usr/local/bin/coder /usr/local/bin/coder

# Pre-create the state dir owned by the runtime user so a mounted named
# volume inherits usable ownership on first boot. The dir is staged empty
# in the builder (distroless has no shell for mkdir/chown at runtime).
COPY --from=builder --chown=65532:65532 /out/state /var/lib/coder-ssh-gateway

USER nonroot

# 2222: outer SSH (unprivileged). 9090: metrics. 9091: health (metrics and
# health default to 127.0.0.1 in config; bind explicitly to expose them).
EXPOSE 2222 9090 9091

VOLUME ["/var/lib/coder-ssh-gateway"]

# Global flags come FIRST: --state-dir precedes the subcommand.
ENTRYPOINT ["/usr/local/bin/coder-ssh-gateway", "--state-dir", "/var/lib/coder-ssh-gateway"]
CMD ["serve"]

# First-run bootstrap (state dir contains no config.yaml yet):
#   docker run --rm -it -v csgw-state:/var/lib/coder-ssh-gateway \
#     IMAGE init
# then edit config.yaml inside the volume and start with the default CMD.
#
# Secrets: init writes host key + encryption key under
# /var/lib/coder-ssh-gateway/secrets/ (0600). To keep secrets off the data
# volume, mount them read-only from elsewhere (e.g. /run/secrets) and point
# ssh.host_keys / encryption.keys at those paths in config.yaml.
#
# Alternative to baking the Coder CLI in: mount a pinned binary read-only,
#   docker run -v /opt/coder-cli/coder:/usr/local/bin/coder:ro ...
# and keep deployment.coder_binary pointed at /usr/local/bin/coder.
