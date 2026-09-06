# coder-ssh-gateway container image.
#
# Multi-stage: build the gateway from source, fetch a checksummed Coder CLI,
# assemble a minimal non-root runtime image (distroless: no shell, no package
# manager, no compiler).
#
# Build:
#   docker build -f deploy/Dockerfile -t coder-ssh-gateway:dev .
#
# CODER_SHA256_AMD64 / CODER_SHA256_ARM64 below pin
# coder_${CODER_VERSION#v}_linux_{amd64,arm64}.tar.gz and are baked in;
# override all three args together when bumping the Coder CLI:
#   curl -sSL https://github.com/coder/coder/releases/download/v2.35.2/coder_2.35.2_checksums.txt
# (release asset names: https://github.com/coder/coder/releases)
#
# The pinned Go toolchain mirrors go.mod's toolchain directive. Bump
# GO_VERSION when go.mod moves.
#
# Version metadata: build with --build-arg VERSION=x.y.z COMMIT=<sha>
# DATE=<rfc3339>; the published images do. Unset, `version` reports dev.

ARG GO_VERSION=1.26.6

# ---------- builder ----------
FROM golang:${GO_VERSION}-bookworm AS builder

# TARGETARCH is provided by Docker/buildx; cross-compile for it natively
# (Go needs no emulation) so multi-arch builds stay fast.
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=dev
ARG DATE=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w \
      -X github.com/HamStudy/coder-ssh-gateway/internal/version.Version=${VERSION} \
      -X github.com/HamStudy/coder-ssh-gateway/internal/version.Commit=${COMMIT} \
      -X github.com/HamStudy/coder-ssh-gateway/internal/version.Date=${DATE}" \
    -o /out/coder-ssh-gateway ./cmd/coder-ssh-gateway

# Empty state dir staged here because the runtime image is distroless (no
# shell, no mkdir); COPY --chown then hands it to the runtime uid.
RUN mkdir -p /out/state

# ---------- coder cli fetch ----------
FROM debian:bookworm-slim AS codercli

ARG CODER_VERSION=v2.35.2
# sha256 of coder_${CODER_VERSION#v}_linux_${TARGETARCH}.tar.gz, baked in.
# The build fails closed on empty or mismatched checksum, or an
# unsupported TARGETARCH.
ARG CODER_SHA256_AMD64=907017ffefae1af67bd6533b6c9ddd6b975e39ea9ef9340deba3dc72231b209c
ARG CODER_SHA256_ARM64=12e4fbd607321cb2464a0625c021e8cfdcb109fe73d3c42c70cd86d7702796b5

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    arch="${TARGETARCH:-$(uname -m)}"; \
    case "${arch}" in \
      amd64|x86_64) arch=amd64; want="${CODER_SHA256_AMD64}" ;; \
      arm64|aarch64) arch=arm64; want="${CODER_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture: ${arch}" >&2; exit 1 ;; \
    esac; \
    [ -n "${want}" ] || { echo "checksum build arg is required for ${TARGETARCH}" >&2; exit 1; }; \
    ver="${CODER_VERSION#v}"; \
    curl -fsSL -o /tmp/coder.tar.gz \
      "https://github.com/coder/coder/releases/download/${CODER_VERSION}/coder_${ver}_linux_${arch}.tar.gz"; \
    echo "${want}  /tmp/coder.tar.gz" | sha256sum -c -; \
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

# First-run bootstrap (state dir contains no config.yaml yet).
# `init` requires exactly one bare Coder DNS domain argument; it writes
# `https://<domain>` into the starter `config.yaml`:
#   docker run --rm -it -v csgw-state:/var/lib/coder-ssh-gateway \
#     IMAGE init coder.example.com
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
