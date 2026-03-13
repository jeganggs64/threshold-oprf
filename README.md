# Threshold OPRF

A distributed threshold Oblivious Pseudorandom Function (OPRF) system. The OPRF key is split into shares using T-of-N Shamir secret sharing, with each share running inside an AMD SEV-SNP Trusted Execution Environment on a separate AWS instance. No single node holds enough shares to evaluate the function.

Node count and threshold are configurable — deploy 2-of-3, 3-of-5, 4-of-7, or any T-of-N split.

## Architecture

```
Mobile App → API Gateway (TLS) → Lambda (VPC) → NLB
                                                  ↓
                                          Coordinator Node
                                                  ↓ AWS PrivateLink
                                          (threshold-1) Peer Nodes
```

Each node can act as **coordinator**: it receives the client's blinded point, computes its own partial evaluation, forwards to threshold-1 peer nodes via PrivateLink, verifies each peer's DLEQ proof, combines all partials via Lagrange interpolation, and returns the final OPRF evaluation.

Node-to-node communication uses **AWS PrivateLink** — each node sits behind a Network Load Balancer with a VPC Endpoint Service, and peer nodes reach each other via Interface VPC Endpoints over AWS's private backbone. No public internet exposure, no TLS certificate management.

Each node runs in a Docker container on an AMD SEV-SNP Confidential VM. Key shares are sealed to the hardware and stored encrypted in S3 — AWS cannot read them.

The API server (developer registration, billing, admin, webhooks) runs as Lambda functions behind API Gateway — see `ruonid-frontend/` for that infrastructure.

## Repository Structure

```
crates/
  core/       Threshold OPRF cryptography (Shamir, partial eval, DLEQ, combine, share recovery)
  node/       TEE node server — coordinator + peer mode, serves /evaluate, /partial-evaluate, /reshare
  keygen/     Offline ceremony tool — generates OPRF key, splits into shares
  seal/       AMD SEV-SNP key sealing/unsealing, ECIES encryption, attestation
docker/       Dockerfiles, docker-compose, SEV-SNP config
deploy/       Deployment automation (provision.sh, deploy.sh)
scripts/      Dev utilities (integration-test.sh)
```

### Crates

| Crate | Description |
|-------|-------------|
| **toprf-core** | Core cryptographic library: Shamir secret sharing, hash-to-curve, partial OPRF evaluation, DLEQ proofs, share combination, and single-node share recovery via Lagrange interpolation. Built on FROST secp256k1 and k256. |
| **toprf-node** | Axum server that loads one key share and evaluates OPRF requests. Acts as both coordinator (receives client request, calls threshold-1 peers, combines partials) and peer (computes partial evaluation). Exposes `/reshare` for donor-side share recovery. Supports four boot modes: init-seal (S3-mediated ECIES key injection with attestation), init-reshare (receive a recovered share from donor nodes), auto-unseal (hardware-sealed blob from S3), and key-file (dev/test). Uploads attestation reports bound to verification shares for public verifiability. |
| **toprf-keygen** | Offline ceremony tool. Generates a new OPRF key and produces admin shares (3-of-5 for vault storage) and node shares (T-of-N for TEE deployment). Also supports re-deriving node shares from admin shares. |
| **toprf-seal** | Hardware key sealing using AMD SEV-SNP `MSG_KEY_REQ`. Seals/unseals key material with measurement-bound derived keys. Includes ECIES encryption, attestation report fetching, and verification. |

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
# Start nodes with Docker Compose
docker compose -f docker/docker-compose.yml up --build
```

Any node can act as coordinator. Node 1 is exposed at `http://localhost:3001/evaluate`.

---

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

Bring 3 of the 5 admin shares together to produce T-of-N node shares for TEE deployment. The threshold and node count are configurable — set them to match your deployment:

```bash
# 2-of-3 (default)
cargo run --release -p toprf-keygen -- node-shares \
    --admin-share admin-1.json --admin-share admin-3.json --admin-share admin-5.json \
    --node-threshold 2 --node-shares 3 \
    --output-dir ./node-shares

# 3-of-5
cargo run --release -p toprf-keygen -- node-shares \
    --admin-share admin-1.json --admin-share admin-3.json --admin-share admin-5.json \
    --node-threshold 3 --node-shares 5 \
    --output-dir ./node-shares
```

Output: `node-shares/node-{1..N}-share.json` + `node-shares/public-config.json`. Point `NODE_SHARES_DIR` in `deploy/config.env` to this directory.

The threshold and node count in `nodes.json` must match the keygen ceremony.

---

## Deployment

### Configuration

Two config files in `deploy/`:

- **`config.env`** — Global settings (instance type, ceremony path). IAM roles/profiles are auto-created.
- **`nodes.json`** — Per-node config (regions, threshold). IPs, keys, S3 buckets, SGs are auto-populated.

```bash
cd deploy
cp config.env.example config.env
cp nodes.json.example nodes.json
# Set regions and threshold in nodes.json, then provision + auto-config:
```

To change the threshold or node count, edit `nodes.json`: set `threshold` and add/remove entries in the `nodes` array (only `id` and `region` are required — everything else is auto-populated). The keygen ceremony must match.

### Prerequisites

- `aws` CLI authenticated locally
- `jq`, `openssl`, `curl` installed locally
- Key ceremony completed (node shares + public config)
- Node image available at `ghcr.io/<owner>/toprf-node:latest` (built by CI)

### Step 1: Provision TEE Nodes (`provision.sh`)

Launches AMD SEV-SNP virtual machines across AWS regions.

Requires `nodes.json` with node regions filled in. Everything else is auto-created:
- **IAM role + instance profile** — created automatically with per-node S3 policies
- **EC2 key pairs** — created per node, `.pem` files saved locally
- **S3 bucket names** — auto-generated as `toprf-sealed-<account>-node-<id>` if empty
- **Security groups, VPCs, subnets** — populated by `auto-config` after provisioning

For each node:
1. Auto-fills `key_name` and `s3_bucket` in `nodes.json` if empty
2. Creates the IAM role and instance profile (if they don't exist)
3. Creates an EC2 key pair in the node's region (saves `.pem` locally)
4. Finds the latest Amazon Linux 2023 AMI
5. Launches a `c6a.large` instance with SEV-SNP enabled
6. Sets IMDS hop limit to 2 (for Docker)
7. Attaches the IAM instance profile

```bash
./provision.sh all        # All nodes
./provision.sh 1          # Just node 1

./provision.sh 2 --status      # Check node 2
./provision.sh 3 --terminate   # Terminate node 3 + clear sealed blob
```

After provisioning, run `./deploy.sh auto-config` to populate IPs, SGs, and VPC IDs in `nodes.json`.

### Step 2: Deploy OPRF Nodes (`deploy.sh`)

Installs Docker, injects key shares, and starts the OPRF service on each node.

**Phase 1: `pre-seal`** (automated)

| Step | What it does |
|------|-------------|
| `setup-vms` | Installs Docker on each VM |
| `pull` | Pulls the node image from ghcr.io |
| `storage` | Creates S3 buckets for sealed key blobs |
| `measure` | Fetches the SEV-SNP measurement from a running node, saves to `config.env` |

**Phase 2: `init-seal`** (interactive, S3-mediated ECIES)

For each node:
1. Starts a temporary container in init-seal mode — node generates an X25519 keypair, gets an attestation report binding the public key, and uploads both to S3
2. Downloads the attestation report and public key from S3
3. Verifies the SEV-SNP attestation (measurement from `config.env` + AMD certificate chain) and confirms the public key is bound to the report via REPORT_DATA
4. Encrypts the key share using ECIES (X25519 ECDH + HKDF-SHA256 + AES-256-GCM) to the attested public key
5. Uploads the encrypted share to S3 — node picks it up, decrypts with its private key, seals to hardware, verifies the seal round-trips, and uploads the sealed blob

**Phase 3: `post-seal`** (automated)

| Step | What it does |
|------|-------------|
| `privatelink` | Creates NLBs, Endpoint Services, and VPC Endpoints |
| `coordinator-config` | Generates per-node coordinator configs with peer PrivateLink endpoints |
| `start` | Starts nodes in coordinator mode (auto-unseal + peer config) |
| `verify` | Health-checks all nodes via SSH |
| `cloudwatch` | Creates CloudWatch alarms for unhealthy node detection |

```bash
# Full deployment
./deploy.sh all

# Or step by step
./deploy.sh pre-seal         # setup-vms → pull → storage → measure
./deploy.sh init-seal        # Interactive — one node at a time recommended
./deploy.sh post-seal

# Or individual steps
./deploy.sh setup-vms
./deploy.sh pull
./deploy.sh storage
./deploy.sh measure          # Auto-detect SEV-SNP measurement
./deploy.sh init-seal
./deploy.sh privatelink
./deploy.sh coordinator-config
./deploy.sh start
./deploy.sh verify
./deploy.sh e2e              # End-to-end OPRF evaluation via coordinator
```

### Step 3: Lock Nodes (`deploy.sh lock`)

Removes SSH access permanently. Nodes become stateless black boxes — only reachable on port 3001 through PrivateLink.

For each node:
1. Removes `authorized_keys` from the VM
2. Stops and disables `sshd`
3. Deletes the EC2 key pair from AWS
4. Deletes the local `.pem` file

```bash
./deploy.sh lock
```

This is irreversible. If a node fails after locking, terminate it (`./provision.sh <N> --terminate`) and reprovision from scratch.

### Common Operations

```bash
./deploy.sh redeploy                # All nodes (requires SSH — before lock)
./deploy.sh --nodes 2 redeploy     # Single node
./deploy.sh verify                  # Health-check nodes
./deploy.sh show-ips                # Fetch node IPs from AWS
```

---

## Automated Monthly Rotation

Nodes are rotated monthly via an AWS Lambda / Step Functions workflow — no admin ceremony or human intervention required. The rotation uses the **share recovery protocol** so that the existing quorum produces shares for each new node without ever reconstructing the secret.

### How it works

The rotation Lambda runs on a monthly schedule (EventBridge cron) and rotates nodes **one at a time**:

```
For each node to rotate (1..N):
  1. Provision a new SEV-SNP VM (same region, fresh instance)
  2. Install Docker, pull the node image
  3. Start the new node in init-reshare mode
     → Node generates X25519 keypair, gets attestation report, uploads to S3
  4. Download the new node's attestation report + pubkey from S3
  5. Send POST /reshare to each donor node (the other N-1 nodes)
     → Donors verify attestation, compute L_i(new_id) * k_i, ECIES-encrypt
     → Upload encrypted contributions to the new node's S3 bucket
  6. New node collects contributions, decrypts, verifies, combines → new share
  7. New node seals share to hardware, uploads sealed blob
  8. Restart new node in normal mode (auto-unseal)
  9. Health-check the new node
  10. Update NLB target: swap old node for new node
  11. Terminate the old VM, clean up old S3 artifacts
```

After all nodes are rotated, each node has a fresh VM and a new share on the **same polynomial** — the group public key and OPRF function are unchanged.

### Unhealthy node detection

CloudWatch alarms monitor each node's NLB target health. If a target is unhealthy for 3 consecutive minutes, the alarm fires to an SNS topic. The rotation Lambda is subscribed to this topic and automatically triggers single-node recovery for the failed node.

```bash
# Set up alarms after deployment
./deploy.sh cloudwatch

# Subscribe rotation Lambda to the SNS topic
aws sns subscribe \
  --topic-arn arn:aws:sns:<region>:<account>:toprf-node-alerts \
  --protocol lambda \
  --notification-endpoint arn:aws:lambda:<region>:<account>:function:toprf-rotation
```

The NLB health check polls `GET /health` every 30 seconds. A node is marked unhealthy after 2 consecutive failures (60s). The CloudWatch alarm requires 3 consecutive unhealthy data points at 1-minute resolution (3 minutes total) before alerting — this avoids false alarms from transient issues.

### Why no admin ceremony?

Traditional rotation requires bringing admin shares together to derive new node shares. With share recovery, the existing live nodes **are** the ceremony — they produce shares for each replacement node via the `/reshare` endpoint. The admin shares (stored in vaults) are only needed if the entire quorum is lost simultaneously.

### Manual fallback

If the Lambda fails or you need manual control, the same per-node replacement can be driven manually: provision a new VM, start it in `--init-reshare` mode, trigger `/reshare` on the donor nodes, then swap the NLB target once the new node is healthy.

---

## Share Recovery (Single-Node Replacement)

When a node needs to be replaced (hardware failure, rotation), the remaining quorum produces a new share for the replacement node without reconstructing the secret. The new share lies on the **same polynomial** as the existing shares — no full reshare or new key generation required.

### Protocol

1. The new node boots in **init-reshare** mode: generates an ephemeral X25519 keypair, gets an AMD attestation report binding the public key, and uploads both to S3.
2. An orchestrator (Lambda) sends each donor node a `/reshare` request containing the new node's attestation report, cert chain, and public key.
3. Each donor node **independently verifies** the attestation (AMD signature chain + measurement + REPORT_DATA binding to public key), then computes its recovery contribution: `L_i(new_node_id) * k_i` (Lagrange basis polynomial evaluated at the new node's ID, times the donor's share). The contribution is ECIES-encrypted to the verified public key.
4. The new node collects contributions from S3, ECIES-decrypts each one, verifies each sub-share against the donor's verification share, verifies the group public key via Lagrange reconstruction, and sums the sub-shares to obtain its new key share.
5. The new node seals the share to hardware and uploads the sealed blob.

### Security

- **Donor is the trust anchor** — each donor independently verifies the target's attestation. Even a fully compromised orchestrator cannot extract sub-shares for an unattested target.
- **Sub-share verification** — the new node verifies each contribution: `g^{s_i} == V_i^{L_i(new_node_id)}` where `V_i` is the donor's verification share.
- **GPK verification** — the new node reconstructs the group public key from donor verification shares: `GPK == ∏ V_i^{L_i(0)}`.
- **No secret reconstruction** — individual sub-shares reveal nothing about the original secret or other nodes' shares.

---

## Public Verifiability

Each node generates an AMD SEV-SNP attestation report at boot, binding its verification share to the hardware measurement via `REPORT_DATA[0..32] = SHA256(verification_share_bytes)`. The report is uploaded to S3 alongside the sealed key blob.

The trust chain:
```
AMD attestation report → verification share → DLEQ proof → OPRF evaluation
```

Third-party auditors can verify:
1. Each node's attestation report is signed by AMD and matches the expected binary measurement
2. The verification shares in the attestation reports combine to the published group public key
3. The mobile app verifies DLEQ proofs against the committed group public key

---

## Security Properties

- **No single point of compromise** — key shares split across N nodes, each below the T-of-N threshold
- **Hardware-bound sealing** — sealed blobs encrypted with SEV-SNP `MSG_KEY_REQ`-derived keys; AWS cannot decrypt
- **TEE attestation** — key injection and share recovery verified against hardware attestation reports with AMD certificate chain validation
- **DLEQ proofs** — every partial evaluation includes a DLEQ proof proving the node used its correct key share; coordinator verifies before combining
- **Attestation-bound recovery** — donor nodes independently verify the target's attestation before releasing sub-shares; compromised orchestrator cannot extract shares
- **Network isolation** — nodes only reachable via AWS PrivateLink; traffic never crosses the public internet
- **Device attestation** — Apple App Attest and Google Play Integrity validation (via API Gateway)

## CI

GitHub Actions runs on push/PR to `main`:

1. **Format & Lint** — `cargo fmt --check` + `cargo clippy` (warnings are errors)
2. **Unit Tests** — `cargo test --release`
3. **Build** — `cargo build --release`
4. **Integration Tests** — Full E2E with 3 nodes

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| S3 upload denied during seal | Missing IAM permissions | Add `s3:PutObject` to the instance profile role |
| Container exits on init-seal | Crash during attestation | `ssh <node> "sudo docker logs toprf-init-seal"` |
| Coordinator can't reach peer | PrivateLink endpoint not available | Check `privatelink-state.env` for endpoint IDs; verify endpoint is in `available` state |
| NLB targets unhealthy | Node not running or wrong port | SSH to node, check `docker ps` and `docker logs toprf-node` |

## License

See [LICENSE](LICENSE).
