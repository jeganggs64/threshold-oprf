# Threshold OPRF

A distributed threshold Oblivious Pseudorandom Function (OPRF) system. The OPRF key is split into 3 shares using 2-of-3 Shamir secret sharing, with each share running inside an AMD SEV-SNP Trusted Execution Environment on a different cloud provider (GCP, Azure, AWS). No single provider holds enough shares to evaluate the function.

## Architecture

```
Mobile App
    |  HTTPS
    v
ALB / Load Balancer
    |
    v
Express API (port 3002)        ← device attestation, rate limiting
    |  HTTP (internal)
    v
Rust TOPRF Proxy (port 3000)   ← fans out to TEE nodes, DLEQ verification
    |  mTLS
    +── Node 1 (GCP,   Confidential VM, SEV-SNP)
    +── Node 2 (Azure, Confidential VM, SEV-SNP)
    +── Node 3 (AWS,   SEV-SNP instance)
```

The proxy collects partial evaluations from any 2 of 3 nodes, verifies DLEQ proofs, and returns verified partials to the client. The client performs Lagrange interpolation and unblinding locally — the proxy never sees the unblinded result.

## Repository Structure

```
crates/
  core/      Threshold OPRF cryptography (Shamir, partial eval, DLEQ, combine)
  node/      Stateless TEE node server — loads key share, serves /partial-evaluate
  proxy/     Orchestrator — fans out to nodes, verifies DLEQ proofs, rate limits
  keygen/    Offline ceremony tool — generates OPRF key, splits into admin + node shares
  seal/      AMD SEV-SNP key sealing/unsealing via hardware-derived keys
  monitor/   GCP maintenance event monitor with webhook alerts
deploy/      Dockerfiles, docker-compose for local dev, TEE-specific configs
scripts/     Integration tests, deployment automation
```

### Crates

| Crate | Description |
|-------|-------------|
| **toprf-core** | Core cryptographic library: Shamir secret sharing, hash-to-curve, partial OPRF evaluation, DLEQ proofs, share combination. Built on FROST secp256k1 and k256. |
| **toprf-node** | Axum server that loads one key share and evaluates OPRF requests. Supports three key loading modes: init-seal (attested TLS injection), auto-unseal (hardware-sealed blob from cloud storage), and key-file (dev/test). |
| **toprf-proxy** | Single entry point for clients. Issues challenge nonces, validates device attestation (Apple App Attest / Google Play Integrity), fans out to nodes over mTLS, verifies DLEQ proofs, enforces per-device rate limits. |
| **toprf-keygen** | Offline ceremony tool. Generates a new OPRF key and produces admin shares (3-of-5 for vault storage) and node shares (2-of-3 for TEE deployment). Also supports re-deriving node shares from admin shares. |
| **toprf-seal** | Hardware key sealing using AMD SEV-SNP `MSG_KEY_REQ`. Seals/unseals key material with measurement-bound derived keys. Includes attestation report fetching and verification. |
| **toprf-monitor** | Daemon that polls GCP metadata for scheduled host maintenance events and sends webhook alerts. Critical for `TERMINATE_ON_HOST_MAINTENANCE` Confidential VMs. |

## Quick Start

### Build

```bash
cargo build --release
```

### Test

```bash
# Unit tests
cargo test --release

# Integration tests (builds binaries, starts 3 nodes + proxy, runs E2E OPRF evaluation)
bash scripts/integration-test.sh
```

### Local Development

```bash
# Generate mTLS certificates
bash scripts/gen-certs.sh

# Start 3 nodes + proxy with Docker Compose
docker compose -f deploy/docker-compose.yml up --build
```

Proxy available at `https://localhost:3000`. Nodes are only reachable within the Docker network.

## Key Ceremony

Run on an air-gapped machine. After the ceremony, destroy the machine.

```bash
# Generate OPRF key → admin shares (3-of-5) + node shares (2-of-3)
cargo run --release -p toprf-keygen -- init \
    --admin-threshold 3 --admin-shares 5 \
    --node-threshold 2 --node-shares 3 \
    --output-dir ./ceremony

# Re-derive node shares from admin shares (infrastructure migration)
cargo run --release -p toprf-keygen -- node-shares \
    --admin-share admin-1.json --admin-share admin-3.json --admin-share admin-5.json \
    --node-threshold 2 --node-shares 3 \
    --output-dir ./new-node-shares
```

## Deployment

Three TEE VMs (one per cloud provider) run the node binary. An ECS Fargate service runs the Express API + Rust proxy behind an ALB.

### Prerequisites

- 3 AMD SEV-SNP VMs provisioned (GCP Confidential VM, Azure DCasv5, AWS C6a)
- IAM roles / managed identities / instance profiles attached
- Key ceremony completed
- `gcloud`, `az`, `aws` CLIs authenticated locally

### Deploy

```bash
cd scripts/deploy
cp config.env.example config.env
# Fill in VM IPs, bucket names, regions, etc.

# Full TEE node deployment
./deploy.sh all

# ECS Fargate + ALB for the API proxy
./setup-ecs.sh all
```

See [scripts/deploy/README.md](scripts/deploy/README.md) for step-by-step usage and [DEPLOYMENT.md](DEPLOYMENT.md) for the full deployment guide.

## Security Properties

- **No single point of compromise** — key shares split across 3 cloud providers, each below the 2-of-3 threshold
- **Hardware-bound sealing** — sealed blobs encrypted with SEV-SNP measurement-derived keys; cloud providers cannot decrypt
- **TEE attestation** — key injection verified against hardware attestation reports
- **mTLS** — proxy-to-node communication authenticated with mutual TLS
- **Device attestation** — Apple App Attest and Google Play Integrity validation before OPRF evaluation
- **Proxy-blind** — proxy verifies DLEQ proofs but never sees unblinded points or final output

## CI

GitHub Actions runs on push/PR to `main`:

1. **Format & Lint** — `cargo fmt --check` + `cargo clippy` (warnings are errors)
2. **Unit Tests** — `cargo test --release`
3. **Build** — `cargo build --release`
4. **Integration Tests** — Full E2E with 3 nodes + proxy

## License

See [LICENSE](LICENSE).
