# Flight Recorder container image.
#
# The eBPF object is regenerated in the builder rather than trusted from the
# repository, so the image's kernel probe provably corresponds to the C source
# in this tree.
#
# The runtime stage is distroless/static: no shell, no package manager, no libc.
# This container runs with CAP_SYS_PTRACE on every node in the cluster; an
# attacker who reaches it should find nothing to work with.

ARG GO_VERSION=1.24
ARG DISTROLESS_TAG=nonroot

# -----------------------------------------------------------------------------
# Builder
# -----------------------------------------------------------------------------
FROM golang:${GO_VERSION}-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        make \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependencies first: this layer only invalidates when go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=0.1.0-dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETARCH=amd64

# Regenerate the eBPF bindings from source.
RUN BPF_CLANG=clang \
    BPF_CFLAGS="-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" \
    go generate ./pkg/probe/...

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags "-s -w \
        -X github.com/Unspekable1654/flight-recorder/pkg/version.Version=${VERSION} \
        -X github.com/Unspekable1654/flight-recorder/pkg/version.Commit=${COMMIT} \
        -X github.com/Unspekable1654/flight-recorder/pkg/version.BuildDate=${BUILD_DATE}" \
      -o /out/flight-recorder ./cmd/flight-recorder

# Fail the build rather than ship a binary that cannot start.
RUN /out/flight-recorder version

# -----------------------------------------------------------------------------
# Runtime
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:${DISTROLESS_TAG}

LABEL org.opencontainers.image.title="Flight Recorder" \
      org.opencontainers.image.description="Forensic preservation for ephemeral compute: eBPF-triggered memory capture with cryptographic sealing and CASE/UCO export" \
      org.opencontainers.image.source="https://github.com/Unspekable1654/flight-recorder" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Flight Recorder"

COPY --from=builder /out/flight-recorder /usr/local/bin/flight-recorder

# Runs as root by default: loading eBPF programs and reading other processes'
# memory require it. The DaemonSet drops every capability except the four that
# are genuinely needed (SYS_PTRACE, BPF, PERFMON, SYS_RESOURCE).
USER 0:0

ENTRYPOINT ["/usr/local/bin/flight-recorder"]
CMD ["start"]
