# =============================================================================
# Stage 1: Build the toprf-node binary (same as standard Dockerfile)
# =============================================================================
FROM rust:1.88-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./

COPY crates/core/Cargo.toml crates/core/Cargo.toml
COPY crates/keygen/Cargo.toml crates/keygen/Cargo.toml
COPY crates/node/Cargo.toml crates/node/Cargo.toml
COPY crates/proxy/Cargo.toml crates/proxy/Cargo.toml
COPY crates/seal/Cargo.toml crates/seal/Cargo.toml
COPY crates/monitor/Cargo.toml crates/monitor/Cargo.toml

RUN mkdir -p crates/core/src crates/keygen/src crates/node/src crates/proxy/src && \
    echo "// stub" > crates/core/src/lib.rs && \
    echo "fn main() {}" > crates/keygen/src/main.rs && \
    echo "fn main() {}" > crates/node/src/main.rs && \
    echo "fn main() {}" > crates/proxy/src/main.rs && \
    mkdir -p crates/seal/src && echo "" > crates/seal/src/lib.rs && \
    mkdir -p crates/seal/src/bin && echo "fn main(){}" > crates/seal/src/bin/toprf-measure.rs && echo "fn main(){}" > crates/seal/src/bin/toprf-seal.rs && \
    mkdir -p crates/monitor/src && echo "fn main(){}" > crates/monitor/src/main.rs

RUN cargo build --release -p toprf-node 2>/dev/null || true

COPY crates/ crates/

RUN touch crates/core/src/lib.rs \
    crates/node/src/main.rs \
    crates/keygen/src/main.rs \
    crates/proxy/src/main.rs

RUN cargo build --release -p toprf-node

# =============================================================================
# Stage 2: Runtime for AWS Nitro Enclaves
# =============================================================================
FROM amazonlinux:2023 AS runtime

RUN dnf install -y \
        ca-certificates \
        aws-nitro-enclaves-cli \
        iproute \
        shadow-utils \
    && dnf clean all

# Install gosu for dropping privileges after network setup
# TODO: Verify this SHA256 hash against the official gosu 1.17 release for amd64
#       https://github.com/tianon/gosu/releases/tag/1.17
RUN curl -fsSL "https://github.com/tianon/gosu/releases/download/1.17/gosu-amd64" \
        -o /usr/local/bin/gosu \
    && echo "bbc4136d03ab138b1ad66fa4fc051bafc6cc7ffae632b069a53657279a450de3  /usr/local/bin/gosu" | sha256sum -c - \
    && chmod +x /usr/local/bin/gosu \
    && gosu --version

# Create non-root user
RUN groupadd --gid 1001 toprf && \
    useradd --uid 1001 --gid toprf --shell /bin/false --create-home toprf

COPY --from=builder /build/target/release/toprf-node /usr/local/bin/toprf-node

# Copy the vsock proxy entry script
COPY docker/nitro/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Directory for TLS certificates
RUN mkdir -p /etc/toprf/certs && chown -R toprf:toprf /etc/toprf

# =============================================================================
# Nitro Enclave networking:
#
# Nitro Enclaves do NOT have standard TCP/IP networking. Communication between
# the parent EC2 instance and the enclave happens over vsock (virtio socket).
#
# The vsock-proxy running on the parent instance forwards TCP traffic into the
# enclave. Inside the enclave the node listens on a vsock CID+port instead of
# a TCP address.
#
# Environment variables consumed by entrypoint.sh:
#   VSOCK_CID       - Context ID for the enclave (default: 16, assigned by hypervisor)
#   VSOCK_PORT      - Port on the vsock to listen on (default: 3001)
#   NODE_INDEX      - Index of this node in the threshold group
#   THRESHOLD       - Minimum signers required (t in t-of-n)
#   TOTAL_NODES     - Total number of nodes (n)
# =============================================================================

ENV VSOCK_CID=16 \
    VSOCK_PORT=3001 \
    NODE_INDEX=0 \
    THRESHOLD=2 \
    TOTAL_NODES=3

EXPOSE 3001

LABEL org.opencontainers.image.title="toprf-node-nitro" \
      org.opencontainers.image.description="Threshold OPRF node for AWS Nitro Enclaves" \
      org.opencontainers.image.vendor="ruonid"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
