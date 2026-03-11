# Threshold OPRF

A distributed threshold Oblivious Pseudorandom Function (OPRF) system. The OPRF key is split into 3 shares using 2-of-3 Shamir secret sharing, with each share running inside an AMD SEV-SNP Trusted Execution Environment on a separate AWS region. No single region holds enough shares to evaluate the function.

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
    |  TLS (VPC peering)
    +── Node 1 (AWS ap-southeast-1, SEV-SNP)
    +── Node 2 (AWS us-east-1, SEV-SNP)
    +── Node 3 (AWS eu-west-1, SEV-SNP)
```

The proxy collects partial evaluations from any 2 of 3 nodes, verifies DLEQ proofs, and returns verified partials to the client. The client performs Lagrange interpolation and unblinding locally — the proxy never sees the unblinded result.

Each node's sealed key blob is stored in S3, encrypted with a hardware-derived key via `MSG_KEY_REQ` — even AWS cannot decrypt it.

## Repository Structure

```
crates/
  core/       Threshold OPRF cryptography (Shamir, partial eval, DLEQ, combine)
  node/       Stateless TEE node server — loads key share, serves /partial-evaluate
  proxy/      Orchestrator — fans out to nodes, verifies DLEQ proofs, rate limits
  keygen/     Offline ceremony tool — generates OPRF key, splits into shares
  seal/       AMD SEV-SNP key sealing/unsealing via hardware-derived keys
  monitor/    Maintenance event monitor with webhook alerts
docker/       Dockerfiles, docker-compose, SEV-SNP config
deploy/       Deployment automation (provision.sh, deploy.sh, setup-ecs.sh)
scripts/      Dev utilities (gen-certs.sh, integration-test.sh)
```

### Crates

| Crate | Description |
|-------|-------------|
| **toprf-core** | Core cryptographic library: Shamir secret sharing, hash-to-curve, partial OPRF evaluation, DLEQ proofs, share combination. Built on FROST secp256k1 and k256. |
| **toprf-node** | Axum server that loads one key share and evaluates OPRF requests. Supports three key loading modes: init-seal (attested TLS injection), auto-unseal (hardware-sealed blob from S3), and key-file (dev/test). |
| **toprf-proxy** | Single entry point for clients. Issues challenge nonces, validates device attestation (Apple App Attest / Google Play Integrity), fans out to nodes over TLS, verifies DLEQ proofs, enforces per-device rate limits. |
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

# Integration tests (builds binaries, starts 3 nodes + proxy, runs E2E OPRF evaluation)
bash scripts/integration-test.sh
```

### Local Development

```bash
# Generate TLS certificates
bash scripts/gen-certs.sh

# Start 3 nodes + proxy with Docker Compose
docker compose -f docker/docker-compose.yml up --build
```

Proxy available at `http://localhost:3000`. Nodes are only reachable within the Docker network.

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

Three TEE VMs (one per AWS region) run the node binary. An ECS Fargate service runs the Express API + Rust proxy behind an ALB. The proxy connects to nodes via VPC peering over private IPs.

### Prerequisites

- `aws` CLI authenticated locally
- `jq`, `openssl`, `curl` installed locally
- SSH key pairs created in each AWS region
- Key ceremony completed

### VM Provisioning (`deploy/provision.sh`)

Provisions Amazon Linux 2023 instances with AMD SEV-SNP across 3 AWS regions. Nodes can be provisioned individually.

```bash
cd deploy
cp config.env.example config.env
# Fill in KEY_NAMEs, SSH_KEYs, S3_BUCKETs, IAM_INSTANCE_PROFILE

./provision.sh 1          # Provision node 1 (ap-southeast-1)
./provision.sh 2          # Provision node 2 (us-east-1)
./provision.sh 3          # Provision node 3 (eu-west-1)
./provision.sh all        # Or all at once
```

### TEE Node Deployment (`deploy/deploy.sh`)

Pulls the node image from ghcr.io (built by CI), creates S3 buckets, generates TLS certs, handles init-seal key injection, and starts nodes.

```bash
# Auto-populate IPs, SGs, VPC IDs from provisioned VMs:
./deploy.sh auto-config

./deploy.sh all           # Full deployment

# Or step by step
./deploy.sh setup-vms     # Install Docker on VMs
./deploy.sh pull           # Pull node image from ghcr.io
./deploy.sh storage        # Create S3 buckets for sealed blobs
./deploy.sh certs          # Generate TLS certs + distribute to VMs
./deploy.sh init-seal      # Interactive: inject key shares via attested TLS
./deploy.sh start          # Start nodes in normal mode
./deploy.sh firewall       # Allow port 3001 from proxy VPC CIDR
./deploy.sh peering        # Set up VPC peering (proxy ↔ node VPCs)
./deploy.sh proxy-config   # Generate proxy-config.production.json
./deploy.sh verify         # Health check all nodes

# Utilities
./deploy.sh show-ips       # Fetch VM IPs from all regions
./deploy.sh redeploy       # Pull latest image + restart nodes
```

### ECS Fargate + ALB (`deploy/setup-ecs.sh`)

Provisions the API proxy infrastructure: VPC with NAT Gateway, ALB, ECS Fargate cluster.

```bash
./setup-ecs.sh all          # Full infrastructure setup

# Or step by step
./setup-ecs.sh vpc          # VPC, subnets, IGW, NAT Gateway
./setup-ecs.sh security     # Security groups
./setup-ecs.sh alb          # Application Load Balancer
./setup-ecs.sh cert         # ACM certificate request
./setup-ecs.sh roles        # IAM roles
./setup-ecs.sh config-bucket # S3 bucket for proxy config
./setup-ecs.sh ecr          # ECR repo for API server
./setup-ecs.sh cluster      # ECS Fargate cluster
./setup-ecs.sh task         # Task definition
./setup-ecs.sh service      # ECS service

# Operations
./setup-ecs.sh upload-config # Upload proxy config + CA cert to S3
./setup-ecs.sh status        # Show NAT EIP, ALB DNS, service health
./setup-ecs.sh redeploy      # Force new deployment
```

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

6. **Switch proxy to new nodes** — regenerate and upload the proxy config, then redeploy ECS:
   ```bash
   ./deploy.sh proxy-config
   ./setup-ecs.sh upload-config
   ./setup-ecs.sh redeploy
   ```
   Traffic switches to new nodes instantly on ECS redeploy.

7. **Decommission old VMs**:
   ```bash
   ./provision.sh all --terminate
   ```

## Security Properties

- **No single point of compromise** — key shares split across 3 AWS regions, each below the 2-of-3 threshold
- **Hardware-bound sealing** — sealed blobs encrypted with SEV-SNP measurement-derived keys; AWS cannot decrypt
- **TEE attestation** — key injection verified against hardware attestation reports
- **Network isolation** — nodes only reachable from proxy VPC via VPC peering; security groups restrict port 3001
- **Server TLS** — proxy-to-node communication encrypted with CA-signed TLS certificates
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
