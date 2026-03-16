# Threshold OPRF

A distributed threshold Oblivious Pseudorandom Function (OPRF) system. The OPRF key is split into shares using T-of-N Shamir secret sharing, with each share running inside an AMD SEV-SNP Trusted Execution Environment on a separate AWS instance. No single node holds enough shares to evaluate the function.

Node count and threshold are configurable — deploy 2-of-3, 3-of-5, 4-of-7, or any T-of-N split.

## Architecture

```
Mobile App → API Gateway (oprf.ruonlabs.com) → Lambda (VPC) → Frontend NLB → Coordinator Node
                                                                                    ↓ AWS PrivateLink
                                                                            (threshold-1) Peer Nodes
```

Each node can act as **coordinator**: it receives the client's blinded point, computes its own partial evaluation, forwards to threshold-1 peer nodes via PrivateLink, verifies each peer's DLEQ proof, combines all partials via Lagrange interpolation, and returns the final OPRF evaluation.

A **frontend NLB** with health checks sits in front of all same-region nodes. If one node goes down, the NLB automatically routes to the surviving node — which coordinates with cross-region peers via PrivateLink to meet the threshold. This provides automatic failover without cross-region Lambda infrastructure, since losing all same-region nodes drops below the threshold regardless.

Node-to-node communication uses **AWS PrivateLink** — each node sits behind its own per-node Network Load Balancer with a VPC Endpoint Service, and peer nodes reach each other via Interface VPC Endpoints over AWS's private backbone. No public internet exposure, no TLS certificate management.

Each node runs in a Docker container on an AMD SEV-SNP Confidential VM. Key shares are sealed to the hardware and stored encrypted in S3 — AWS cannot read them.

The OPRF endpoints (`/challenge`, `/attest`, `/evaluate`) are served from a **dedicated API Gateway** (`oprf.ruonlabs.com`), separate from the developer-facing frontend API (`api.ruonlabs.com`).

## Repository Structure

```
crates/
  core/       Threshold OPRF cryptography (Shamir, partial eval, DLEQ, combine, share recovery)
  node/       TEE node server — coordinator + peer mode, serves /evaluate, /partial-evaluate, /reshare
  keygen/     Offline ceremony tool — generates OPRF key, splits into shares
  seal/       AMD SEV-SNP key sealing/unsealing, ECIES encryption, attestation
lambda/
  handlers/   OPRF Lambda functions (challenge, attest, evaluate)
  rotation/   Automated rotation Lambda (SAM template + handler)
docker/       Dockerfiles, docker-compose, SEV-SNP config
deploy/       Deployment automation (provision.sh, deploy.sh)
scripts/      Dev utilities (integration-test.sh)
```

## Full Deployment Guide (Start to Finish)

### Prerequisites

- AWS CLI authenticated with appropriate IAM permissions
- `jq`, `openssl`, `curl` installed locally
- Rust toolchain installed (for building keygen + init-encrypt)
- Node.js installed (for building Lambda handlers)
- Docker for local development/testing

### Step 1: Build

```bash
cargo build --release
cargo test --release
```

### Step 2: Key Ceremony (air-gapped machine recommended)

#### 2a. Create admin shares (one-time, store in separate secure locations)

```bash
cargo run --release -p toprf-keygen -- init \
    --admin-threshold 3 --admin-shares 5 \
    --output-dir ./ceremony/admin-shares
```

This produces 5 admin shares with a 3-of-5 threshold. Store these in physically separate secure locations (bank vaults, safes, etc). The admin shares are only needed if the entire quorum is lost.

#### 2b. Derive node shares (per deployment)

Bring 3 of the 5 admin shares together to produce T-of-N node shares:

```bash
# 2-of-3 deployment
cargo run --release -p toprf-keygen -- node-shares \
    --admin-share ceremony/admin-shares/admin-1.json \
    --admin-share ceremony/admin-shares/admin-3.json \
    --admin-share ceremony/admin-shares/admin-5.json \
    --node-threshold 2 --node-shares 3 \
    --output-dir ./ceremony/node-shares
```

Output: `node-shares/node-{1..N}-share.json` + `node-shares/public-config.json`.

### Step 3: Configure Deployment

```bash
cd deploy
cp config.env.example config.env
cp nodes.json.example nodes.json
```

Edit `nodes.json`: set `threshold` and configure node regions. Only `id` and `region` are required per node — everything else is auto-populated.

Edit `config.env`: set `NODE_SHARES_DIR=../ceremony/node-shares` and any other values not marked `[auto]`.

### Step 4: Provision TEE Nodes

```bash
./provision.sh all
```

For each node, this:
1. Creates an IAM role (`toprf-node-<id>-role`) scoped to that node's S3 bucket
2. Creates an EC2 key pair (saves `.pem` locally)
3. Finds the latest Amazon Linux 2023 AMI with SEV-SNP support
4. Launches a `c6a.large` instance with SEV-SNP enabled
5. Attaches the IAM instance profile

After provisioning, auto-populate IPs, security groups, and VPC IDs:

```bash
./deploy.sh auto-config
```

### Step 5: Deploy OPRF Nodes

#### Option A: Full deployment (all steps)

```bash
./deploy.sh all
```

This runs pre-seal → init-seal → post-seal in sequence.

#### Option B: Step by step

**Pre-seal** (automated):

```bash
./deploy.sh pre-seal
```

| Step | What it does |
|------|-------------|
| `setup-vms` | Installs Docker on each VM |
| `pull` | Pulls the node image from ghcr.io |
| `storage` | Creates S3 buckets for sealed key blobs |
| `measure` | Fetches the SEV-SNP measurement, saves to `config.env`. Also fetches the AMD ARK fingerprint from KDS. |

**Init-seal** (interactive, S3-mediated ECIES key injection):

```bash
./deploy.sh init-seal
```

For each node:
1. Starts a temporary container in init-seal mode — generates X25519 keypair, gets attestation report, uploads to S3
2. Downloads attestation report and public key from S3
3. Verifies SEV-SNP attestation (measurement + AMD certificate chain + ARK fingerprint)
4. Encrypts key share via ECIES to the attested public key
5. Uploads encrypted share to S3 — node decrypts, seals to hardware, uploads sealed blob

**Post-seal** (automated):

```bash
./deploy.sh post-seal
```

| Step | What it does |
|------|-------------|
| `privatelink` | Creates per-node NLBs, Endpoint Services, and cross-VPC VPC Endpoints |
| `coordinator-config` | Generates per-node coordinator configs with peer PrivateLink endpoints |
| `start` | Starts nodes in coordinator mode (auto-unseal + peer config) |
| `verify` | Health-checks all nodes via SSH |
| `frontend-nlb` | Creates frontend NLB targeting all same-region nodes |

### Step 6: Verify End-to-End

```bash
./deploy.sh e2e
```

Runs an OPRF evaluation through the coordinator to verify the full system works.

### Step 7: Deploy Lambda Functions

Before deploying Lambdas, you need an API Gateway and custom domain set up:

1. Create an HTTP API Gateway in the AWS console or via CLI
2. Request an ACM certificate for `oprf.ruonlabs.com` (DNS validation)
3. Create a custom domain mapping in API Gateway pointing to the cert
4. Add a Route 53 CNAME record: `oprf.ruonlabs.com` → API Gateway domain
5. Create a Lambda execution IAM role with DynamoDB, S3, VPC, and CloudWatch permissions

The three Lambda functions handle the API Gateway layer:

| Function | Route | Description |
|----------|-------|-------------|
| **challenge** | `GET /challenge` | Issues single-use nonces for device attestation |
| **attest** | `POST /attest` | One-time Apple App Attest device key registration |
| **evaluate** | `POST /evaluate` | Attestation-gated OPRF evaluation via frontend NLB |

#### 7a. Generate Lambda config

```bash
# From deploy/ directory
./deploy.sh lambda-config
```

This auto-populates `lambda/config.env` from deployment state (account ID, region, VPC subnets, NLB URL). You'll need to manually set:
- `API_ID` — the OPRF API Gateway ID (for `oprf.ruonlabs.com`)
- `ROLE_ARN` — Lambda execution role ARN
- `APPLE_APP_ID` — Apple App Attest app ID (e.g. `TEAMID.com.yourapp`)
- `APPLE_TEAM_ID` — Apple Developer Team ID

#### 7b. Deploy Lambdas

```bash
cd lambda
./deploy.sh
```

This builds the Lambda handlers, creates/updates the Lambda functions, wires API Gateway routes, and grants invoke permissions.

After deploying, return to the `deploy/` directory for the remaining steps.

### Step 8: Set Up Monitoring

```bash
# From deploy/ directory
./deploy.sh cloudwatch
```

Creates CloudWatch alarms for each node's NLB target health. Unhealthy nodes trigger SNS notifications and automatic rotation.

### Step 9: Sync State for Rotation Lambda

```bash
# From deploy/ directory
./deploy.sh sync-state
```

Pushes node configs, coordinator configs, measurement, and ARK fingerprint to SSM Parameter Store. The rotation Lambda reads these for automated node replacement.

### Step 10: Deploy Rotation Lambda

```bash
cd lambda/rotation
sam build && sam deploy --guided
```

After deploying, return to the `deploy/` directory for the final step.

### Step 11: Lock Nodes (production)

```bash
# From deploy/ directory
./deploy.sh lock
```

Removes SSH access permanently. Nodes become stateless black boxes — only reachable on port 3001 through PrivateLink. **This is irreversible.** If a node fails after locking, terminate and reprovision from scratch.

---

## Common Operations

```bash
./deploy.sh verify                  # Health-check nodes
./deploy.sh e2e                     # End-to-end OPRF evaluation test
./deploy.sh show-ips                # Fetch node IPs from AWS
./deploy.sh auto-config             # Re-populate IPs, SGs, VPCs in nodes.json
./deploy.sh redeploy                # Pull latest image + restart all nodes
./deploy.sh --nodes 2 redeploy     # Single node redeploy
./deploy.sh lambda-config           # Regenerate lambda/config.env
./deploy.sh sync-state              # Push state to SSM (after any config change)
```

---

## Automated Monthly Rotation

Nodes are rotated monthly via an AWS Lambda — no admin ceremony or human intervention required. The rotation uses the **share recovery protocol** so that the existing quorum produces shares for each new node without ever reconstructing the secret.

### How it works

Rotation uses a **staging-based** approach: a new instance is provisioned alongside the existing node, receives its share via reshare, and only after the new node is verified healthy does the swap happen. The old node runs throughout — if anything fails, the rotation is aborted with zero impact.

```
For each node to rotate (1..N):
  1. Provision a staging VM (old node continues serving traffic)
  2. Install Docker, pull the node image on staging VM
  3. Start staging node in init-reshare mode
     → Generates X25519 keypair, gets attestation report, uploads to S3
  4. Download staging node's attestation report + pubkey from S3
  5. Send POST /reshare to each donor node (the other N-1 nodes)
     → Donors verify attestation, compute recovery contribution, ECIES-encrypt
     → Upload encrypted contributions to S3
  6. Staging node collects contributions, decrypts, verifies, combines → new share
  7. Staging node seals share to hardware
  8. Restart staging node in normal mode, health-check
  9. Swap NLB targets: deregister old IP, register new IP
  10. Terminate old instance, retag staging → permanent, clean up
```

If anything fails at any step, the old node is still running. Terminate the staging instance and clean up — back to healthy nodes.

```bash
# Manual rotation
./provision.sh 1 --staging       # Provision staging VM
./deploy.sh rotate 1             # Reshare → verify → swap → cleanup
./deploy.sh --nodes 1 lock       # Lock the new node

# Abort a failed rotation
./provision.sh 1 --terminate-staging
```

### Unhealthy node detection

CloudWatch alarms monitor each node's NLB target health. If a target is unhealthy for 3 consecutive minutes, the alarm fires to SNS. The rotation Lambda is subscribed and automatically triggers single-node recovery.

```bash
./deploy.sh cloudwatch
```

### Success notifications

The rotation Lambda publishes to an SNS topic after each successful rotation. Subscribe via:

```bash
aws sns subscribe \
  --topic-arn <RotationResultsTopicArn from stack outputs> \
  --protocol email \
  --notification-endpoint your@email.com
```

---

## Share Recovery Protocol

When a node needs to be replaced, the remaining quorum produces a new share without reconstructing the secret. The new share lies on the same polynomial — no full reshare or new key generation required.

1. New node boots in init-reshare mode: generates ephemeral X25519 keypair, gets attestation report
2. Orchestrator sends `/reshare` to each donor node with the new node's attestation
3. Each donor independently verifies attestation, then computes `L_i(new_node_id) * k_i` and ECIES-encrypts it
4. New node collects, decrypts, verifies each sub-share against verification shares, combines to obtain new share
5. New node seals and uploads

**Security**: donor is the trust anchor — each independently verifies attestation before releasing sub-shares. Compromised orchestrator cannot extract shares for an unattested target.

---

## Public Verifiability

Each node generates an AMD SEV-SNP attestation report at boot, binding its verification share to the hardware measurement via `REPORT_DATA[0..32] = SHA256(verification_share_bytes)`.

Third-party auditors can verify:
1. Each node's attestation report is signed by AMD and matches the expected binary measurement
2. The verification shares combine to the published group public key
3. The mobile app verifies DLEQ proofs against the committed group public key

---

## Security Properties

- **No single point of compromise** — key shares split across N nodes, each below the T-of-N threshold
- **Hardware-bound sealing** — sealed blobs encrypted with SEV-SNP `MSG_KEY_REQ`-derived keys; AWS cannot decrypt
- **TEE attestation** — key injection and share recovery verified against hardware attestation reports with AMD certificate chain validation, VMPL == 0 enforcement, and guest policy debug-bit rejection
- **ARK fingerprint pinning** — AMD root certificate fingerprint is mandatory
- **DLEQ proofs** — every partial evaluation includes a DLEQ proof proving the node used its correct key share
- **Attestation-bound recovery** — donor nodes independently verify the target's attestation before releasing sub-shares
- **Per-node IAM isolation** — each node's IAM role is scoped to only its own S3 bucket
- **Network isolation** — nodes only reachable via AWS PrivateLink; traffic never crosses the public internet
- **Device attestation** — Apple App Attest and Google Play Integrity validation via API Gateway

## CI

GitHub Actions runs on push/PR to `main`:

1. **Format & Lint** — `cargo fmt --check` + `cargo clippy` (warnings are errors)
2. **Unit Tests** — `cargo test --release`
3. **Build** — `cargo build --release`
4. **Integration Tests** — Full E2E with 3 nodes
5. **Docker Image** — Build and push to ghcr.io (main branch only)

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| S3 upload denied during seal | Missing IAM permissions | Add `s3:PutObject` to the instance profile role |
| Container exits on init-seal | Crash during attestation | `ssh <node> "sudo docker logs toprf-init-seal"` |
| Coordinator can't reach peer | PrivateLink endpoint not available | Check `privatelink-state.env` for endpoint IDs |
| NLB targets unhealthy | Node not running or wrong port | SSH to node, check `docker ps` and `docker logs toprf-node` |
| SEV-SNP measurement mismatch | AMI updated by AWS | Re-run `./deploy.sh measure` and rebuild/re-seal |
| VLEK cert not found | AWS uses VLEK instead of VCEK | System handles both — check AMD KDS fetch in logs |

## License

See [LICENSE](LICENSE).
