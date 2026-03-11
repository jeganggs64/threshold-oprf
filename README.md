# Threshold OPRF

A distributed threshold Oblivious Pseudorandom Function (OPRF) system. The OPRF key is split into 3 shares using 2-of-3 Shamir secret sharing, with each share running inside an AMD SEV-SNP Trusted Execution Environment on a separate AWS region. No single region holds enough shares to evaluate the function.

## Architecture

```
Mobile App
    |  HTTPS
    v
API Gateway (TLS, rate limiting)
    |  VPC Link
    v
NLB (eu-west-1) → Node 1 or Node 2 (coordinator)
                      |  AWS PrivateLink (private)
                      +── Peer Node (same or cross-region)
```

Each node can act as **coordinator**: it receives the client's blinded point, computes its own partial evaluation, forwards to a peer node via PrivateLink, verifies the peer's DLEQ proof, combines both partials via Lagrange interpolation, and returns the final OPRF evaluation. No separate proxy service needed.

Node-to-node communication uses AWS PrivateLink — each node sits behind a Network Load Balancer with a VPC Endpoint Service, and peer nodes reach each other via Interface VPC Endpoints over AWS's private backbone. No public internet exposure, no TLS certificate management.

Each node's sealed key blob is stored in S3, encrypted with a hardware-derived key via `MSG_KEY_REQ` — even AWS cannot decrypt it.

## Repository Structure

```
crates/
  core/       Threshold OPRF cryptography (Shamir, partial eval, DLEQ, combine)
  node/       TEE node server — coordinator + peer mode, serves /evaluate and /partial-evaluate
  keygen/     Offline ceremony tool — generates OPRF key, splits into shares
  seal/       AMD SEV-SNP key sealing/unsealing via hardware-derived keys
  monitor/    Maintenance event monitor with webhook alerts
docker/       Dockerfiles, docker-compose, SEV-SNP config
deploy/       Deployment automation (provision.sh, deploy.sh, setup-ecs.sh)
scripts/      Dev utilities (integration-test.sh)
```

### Crates

| Crate | Description |
|-------|-------------|
| **toprf-core** | Core cryptographic library: Shamir secret sharing, hash-to-curve, partial OPRF evaluation, DLEQ proofs, share combination. Built on FROST secp256k1 and k256. |
| **toprf-node** | Axum server that loads one key share and evaluates OPRF requests. Acts as both coordinator (receives client request, calls a peer, combines partials) and peer (computes partial evaluation). Supports three key loading modes: init-seal (S3-mediated ECIES key injection with attestation), auto-unseal (hardware-sealed blob from S3), and key-file (dev/test). |
| **toprf-keygen** | Offline ceremony tool. Generates a new OPRF key and produces admin shares (3-of-5 for vault storage) and node shares (2-of-3 for TEE deployment). Also supports re-deriving node shares from admin shares. |
| **toprf-seal** | Hardware key sealing using AMD SEV-SNP `MSG_KEY_REQ`. Seals/unseals key material with measurement-bound derived keys. Includes attestation report fetching and verification. |
| **toprf-monitor** | Daemon that polls for scheduled host maintenance events and sends webhook alerts. |

## Quick Start

### Build

```bash
cargo build --release
```

### Test

```bash
# Unit tests
cargo test --release

# Integration tests (builds binaries, starts 3 nodes, runs E2E OPRF evaluation)
bash scripts/integration-test.sh
```

### Local Development

```bash
# Start 3 nodes with Docker Compose
docker compose -f docker/docker-compose.yml up --build
```

Any node can act as coordinator. Node 1 is exposed at `http://localhost:3001/evaluate`.

## Key Management

Key management has two separate steps: creating admin shares (one-time) and deriving node shares (repeatable). Both should be run on an air-gapped machine.

### 1. Create admin shares (one-time)

Generates the OPRF key and splits it into 5 admin shares with a 3-of-5 threshold. Store these in physically separate secure locations (bank vaults, safes, etc).

```bash
cargo run --release -p toprf-keygen -- init \
    --admin-threshold 3 --admin-shares 5 \
    --output-dir ./admin-shares
```

### 2. Derive node shares (per deployment)

Bring 3 of the 5 admin shares together to produce 2-of-3 node shares for TEE deployment. Run this for every fresh deployment or key rotation.

```bash
cargo run --release -p toprf-keygen -- node-shares \
    --admin-share admin-1.json --admin-share admin-3.json --admin-share admin-5.json \
    --node-threshold 2 --node-shares 3 \
    --output-dir ./node-shares
```

Output: `node-shares/node-{1,2,3}-share.json` + `node-shares/public-config.json`. Point `NODE_SHARES_DIR` in `deploy/config.env` to this directory.

## Deployment

Three TEE VMs (one per AWS region) run the node binary. Each node can act as coordinator — receiving client requests, calling a peer via PrivateLink, and returning the combined OPRF evaluation. Clients reach nodes via API Gateway → NLB.

### Prerequisites

- `aws` CLI authenticated locally
- `jq`, `openssl`, `curl` installed locally
- SSH key pairs created in each AWS region
- Key ceremony completed

### VM Provisioning (`deploy/provision.sh`)

Provisions Amazon Linux 2023 instances with AMD SEV-SNP across AWS regions. Nodes can be provisioned individually.

```bash
cd deploy
cp config.env.example config.env
# Fill in KEY_NAMEs, SSH_KEYs, S3_BUCKETs
# IAM_INSTANCE_PROFILE is auto-created by provision.sh

./provision.sh 1          # Provision node 1 (eu-west-1)
./provision.sh 2          # Provision node 2 (eu-west-1)
./provision.sh 3          # Provision node 3 (us-east-2)
./provision.sh all        # Or all at once
```

### TEE Node Deployment (`deploy/deploy.sh`)

Pulls the node image from ghcr.io (built by CI), creates S3 buckets, handles init-seal key injection, starts nodes, and sets up AWS PrivateLink.

```bash
# Auto-populate IPs, SGs, VPC IDs, Subnet IDs from provisioned VMs:
./deploy.sh auto-config

./deploy.sh all           # Full deployment

# Or step by step
./deploy.sh setup-vms     # Install Docker on VMs
./deploy.sh pull           # Pull node image from ghcr.io
./deploy.sh storage        # Create S3 buckets for sealed blobs
./deploy.sh init-seal      # Interactive: S3-mediated ECIES key injection (attested)
./deploy.sh start          # Start nodes in normal mode
./deploy.sh privatelink    # Create NLBs, Endpoint Services, VPC Endpoints
./deploy.sh coordinator-config  # Generate per-node coordinator configs
./deploy.sh verify         # Health check all nodes (via SSH)
./deploy.sh e2e            # End-to-end: OPRF evaluate via coordinator

# Utilities
./deploy.sh show-ips       # Fetch VM IPs from all regions
./deploy.sh redeploy       # Pull latest image + restart nodes
```

### ECS Fargate + ALB (`deploy/setup-ecs.sh`)

Provisions the API server infrastructure: VPC with NAT Gateway, ALB, ECS Fargate cluster.

```bash
./setup-ecs.sh all          # Full infrastructure setup

# Or step by step
./setup-ecs.sh vpc          # VPC, subnets, IGW, NAT Gateway
./setup-ecs.sh security     # Security groups
./setup-ecs.sh alb          # Application Load Balancer
./setup-ecs.sh cert         # ACM certificate request
./setup-ecs.sh roles        # IAM roles
./setup-ecs.sh ecr          # ECR repo for API server
./setup-ecs.sh cluster      # ECS Fargate cluster
./setup-ecs.sh task         # Task definition
./setup-ecs.sh service      # ECS service

# Operations
./setup-ecs.sh status        # Show NAT EIP, ALB DNS, service health
./setup-ecs.sh redeploy      # Force new deployment
```

### Node Replacement (`deploy/replace-node.sh`)

Replaces a single failed node without touching the other nodes. The replacement reuses the same key share and the same PrivateLink endpoint — peers don't need any config changes.

```bash
./replace-node.sh 3 --share-file ../ceremony/node-shares/node-3-share.json
```

See `deploy/README.md` for full options (`--skip-provision`, `--skip-init-seal`).

### Zero-Downtime Key Rotation

Key rotation deploys to fresh nodes rather than resealing existing ones. The old nodes keep serving traffic until the new ones are verified, so there is no downtime.

1. **Derive new node shares** (air-gapped machine):
   ```bash
   toprf-keygen node-shares \
       --admin-share admin-1.json --admin-share admin-3.json --admin-share admin-5.json \
       --node-threshold 2 --node-shares 3 \
       --output-dir ./node-shares-v2
   ```

2. **Provision 3 new VMs**:
   ```bash
   ./provision.sh all
   ```

3. **Update `deploy/config.env`** with the new VM IPs and `NODE_SHARES_DIR=./node-shares-v2`. Run `./deploy.sh auto-config` to fill in IPs automatically.

4. **Deploy to new nodes**:
   ```bash
   ./deploy.sh all
   ```

5. **Verify new nodes** are healthy:
   ```bash
   ./deploy.sh verify
   ```

6. **Set up PrivateLink for new nodes** and update coordinator configs:
   ```bash
   ./deploy.sh privatelink
   ./deploy.sh coordinator-config
   ./deploy.sh start
   ```
   Restart nodes to pick up the new coordinator configs.

7. **Decommission old VMs**:
   ```bash
   ./provision.sh all --terminate
   ```

## Security Properties

- **No single point of compromise** — key shares split across 3 AWS regions, each below the 2-of-3 threshold
- **Hardware-bound sealing** — sealed blobs encrypted with SEV-SNP measurement-derived keys; AWS cannot decrypt
- **TEE attestation** — key injection verified against hardware attestation reports
- **Network isolation** — nodes only reachable via AWS PrivateLink; traffic never crosses the public internet
- **Device attestation** — Apple App Attest and Google Play Integrity validation (via API Gateway)

## CI

GitHub Actions runs on push/PR to `main`:

1. **Format & Lint** — `cargo fmt --check` + `cargo clippy` (warnings are errors)
2. **Unit Tests** — `cargo test --release`
3. **Build** — `cargo build --release`
4. **Integration Tests** — Full E2E with 3 nodes

## License

See [LICENSE](LICENSE).
