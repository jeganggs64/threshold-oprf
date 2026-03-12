# Deployment Guide

Deploy threshold OPRF nodes across AWS regions. Node count and threshold (T-of-N) are configurable via `nodes.json`.

## Architecture

```
Mobile App → API Gateway (TLS) → Lambda (VPC) → NLB
                                                  ↓
                                          Coordinator Node
                                                  ↓ AWS PrivateLink
                                          (threshold-1) Peer Nodes
```

Each node runs in a Docker container on an AMD SEV-SNP Confidential VM. Key shares are sealed to the hardware and stored encrypted in S3 — AWS cannot read them.

The API server (developer registration, billing, admin, webhooks) runs as Lambda functions behind API Gateway — see `ruonid-frontend/` for that infrastructure.

---

## Configuration

Two config files:

- **`config.env`** — Global settings (AWS account, instance type, IAM profile, domain, ceremony path)
- **`nodes.json`** — Per-node config (regions, IPs, keys, S3 buckets, threshold)

Copy the examples and fill in your values:
```bash
cp config.env.example config.env
cp nodes.json.example nodes.json
# Edit both files, then:
./deploy.sh auto-config    # Populates IPs, SGs, VPCs from AWS
```

To change the threshold or node count, edit `nodes.json`: set `threshold` and add/remove entries in the `nodes` array. The keygen ceremony must match:
```bash
toprf-keygen node-shares --node-threshold 3 --node-shares 5  # 3-of-5
```

---

## Step 1: Provision TEE Nodes (`provision.sh`)

Launches AMD SEV-SNP virtual machines across AWS regions.

### Prerequisites

- `nodes.json` with node regions and S3 bucket names filled in (buckets don't need to exist yet — `deploy.sh storage` creates them)
- An IAM instance profile for the nodes, with `IAM_INSTANCE_PROFILE` set in `config.env`. The role needs `s3:PutObject` and `s3:GetObject` on the sealed-key buckets so nodes can upload/download sealed key blobs

### What it does

For each node:
1. Creates an EC2 key pair in the node's region (saves `.pem` locally)
2. Finds the latest Amazon Linux 2023 AMI
3. Launches a `c6a.large` instance with SEV-SNP enabled
4. Sets IMDS hop limit to 2 (for Docker)
5. Attaches the IAM instance profile

### Run

```bash
./provision.sh all        # All nodes
./provision.sh 1          # Just node 1
```

### After it runs

- VMs running, one per node in `nodes.json`
- SSH keys saved to `deploy/<key_name>.pem`
- Run `./deploy.sh auto-config` to populate IPs, SGs, and VPC IDs in `nodes.json`

### Management

```bash
./provision.sh 2 --status      # Check node 2
./provision.sh 3 --terminate   # Terminate node 3 + clear sealed blob
```

---

## Step 2: Deploy OPRF Nodes (`deploy.sh`)

Installs Docker, injects key shares, and starts the OPRF service on each node.

### Prerequisites

- Nodes provisioned and running (step 1)
- `nodes.json` populated (run `./deploy.sh auto-config` after provisioning)
- Key ceremony completed — key shares at `../ceremony/node-shares/`
  - `public-config.json` (group public key, threshold, verification shares)
  - `node-<id>-share.json` for each node in `nodes.json`
- Node image available at `ghcr.io/<owner>/toprf-node:latest` (built by CI)

### What it does

**Phase 1: `pre-seal`** (automated)

| Step | What it does |
|------|-------------|
| `setup-vms` | Installs Docker on each VM |
| `pull` | Pulls the node image from ghcr.io |
| `storage` | Creates S3 buckets for sealed key blobs |

**Phase 2: `init-seal`** (interactive, S3-mediated ECIES)

For each node:
1. Starts a temporary container in init-seal mode — node generates an X25519 keypair, gets an attestation report binding the public key, and uploads both to S3
2. Downloads the attestation report and public key from S3
3. Verifies the SEV-SNP attestation (measurement + AMD certificate chain) and confirms the public key is bound to the report via REPORT_DATA
4. Encrypts the key share using ECIES (X25519 ECDH + HKDF-SHA256 + AES-256-GCM) to the attested public key
5. Uploads the encrypted share to S3 — node picks it up, decrypts with its private key, seals to hardware, verifies the seal round-trips, and uploads the sealed blob

**Phase 3: `post-seal`** (automated)

| Step | What it does |
|------|-------------|
| `privatelink` | Creates NLBs, Endpoint Services, and VPC Endpoints |
| `coordinator-config` | Generates per-node coordinator configs with peer PrivateLink endpoints |
| `start` | Starts nodes in coordinator mode (auto-unseal + peer config) |
| `verify` | Health-checks all nodes via SSH |

### Run

```bash
# Full deployment
./deploy.sh all

# Or step by step
./deploy.sh pre-seal
./deploy.sh init-seal        # Interactive — one node at a time recommended
./deploy.sh post-seal
```

### After it runs

- All nodes are sealed, running, and reachable via PrivateLink
- Each node can act as coordinator (receives client requests, calls threshold-1 peers, returns combined evaluation)

---

## Step 3: Lock Nodes (`deploy.sh lock`)

Removes SSH access permanently. Nodes become stateless black boxes — only reachable on port 3001 through PrivateLink.

### Prerequisites

- Nodes deployed and verified (step 2)
- You're sure everything is working — this is irreversible

### What it does

For each node:
1. Removes `authorized_keys` from the VM
2. Stops and disables `sshd`
3. Deletes the EC2 key pair from AWS
4. Deletes the local `.pem` file

### Run

```bash
./deploy.sh lock
```

### After it runs

- No SSH access to any node
- If a node fails, terminate it (`./provision.sh <N> --terminate`) and reprovision from scratch

---

## Common Operations

### Redeploy nodes (code update)
```bash
./deploy.sh redeploy                # All nodes (requires SSH — before lock)
./deploy.sh --nodes 2 redeploy     # Single node
```

### Check status
```bash
./deploy.sh verify                 # Health-check nodes
./deploy.sh show-ips               # Fetch node IPs from AWS
```

---

## Blue-Green Rotation (recommended)

Zero-downtime node rotation using slots. Each slot is a fully independent set of nodes + NLBs + PrivateLink. Traffic switches by updating the Lambda's NLB_URL env var.

### Prerequisites

- 3-of-5 admin shares (from `toprf-keygen init`)
- Current nodes tagged with a slot (e.g., `blue`)

### Flow

```bash
# 1. Admin ceremony: reconstruct secret, generate fresh node shares
toprf-keygen node-shares \
  -a admin-1.json -a admin-3.json -a admin-5.json \
  -o ./node-shares

# 2. Create config.env + nodes.json from examples, fill in values

# 3. Provision new VMs alongside old ones
SLOT=green ./provision.sh all

# 4. Deploy everything (sealed nodes + PrivateLink + start)
./deploy.sh --slot green auto-config
./deploy.sh --slot green all

# 5. Verify new set is healthy
./deploy.sh --slot green e2e

# 6. Switch traffic (updates Lambda NLB_URL)
./deploy.sh --slot green cutover

# 7. Tear down old set (discovers resources by Slot=blue tag, deletes all)
./deploy.sh --slot blue teardown

# 8. Clean up local files — nothing to keep
rm -f config.env nodes.json *.pem
rm -rf node-shares coordinator-configs-green
```

After teardown, `green` is the active slot. Next rotation deploys to `blue`, cuts over, tears down `green`.

**Nothing persisted locally between rotations.** Admin shares are distributed across 5 admins. All infrastructure state lives in AWS resource tags.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| S3 upload denied during seal | Missing IAM permissions | Add `s3:PutObject` to the instance profile role |
| Container exits on init-seal | Crash during attestation | `ssh <node> "sudo docker logs toprf-init-seal"` |
| Coordinator can't reach peer | PrivateLink endpoint not available | Check `privatelink-state.env` for endpoint IDs; verify endpoint is in `available` state |
| NLB targets unhealthy | Node not running or wrong port | SSH to node, check `docker ps` and `docker logs toprf-node` |
