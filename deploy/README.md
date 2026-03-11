# Deployment Guide

Deploy the RuonID API server and 3 threshold OPRF nodes across AWS.

## Architecture

```
Mobile App → API Gateway (TLS) → VPC Link → NLB (eu-west-1)
                                               ↓
                                    Node 1 or Node 2 (coordinator)
                                               ↓ AWS PrivateLink
                                            Peer Node
```

Each node runs in a Docker container on an AMD SEV-SNP Confidential VM. Key shares are sealed to the hardware and stored encrypted in S3 — AWS cannot read them.

---

## Step 1: ECS Infrastructure (`setup-ecs.sh`)

Sets up the cloud infrastructure for the API server.

### Prerequisites

- AWS CLI authenticated with admin-level access
- `jq` installed
- A domain name (e.g. `api.ruonlabs.com`)
- `config.env` created from `config.env.example` with `AWS_ACCOUNT_ID` and `DOMAIN` set

### What it does

| Step | Creates |
|------|---------|
| `vpc` | VPC, public/private subnets, IGW, NAT Gateway, route tables |
| `security` | Security groups for ALB and ECS tasks |
| `alb` | Application Load Balancer + target group |
| `cert` | ACM certificate request (needs DNS validation after) |
| `roles` | IAM roles for ECS task execution and runtime (DynamoDB, KMS) |
| `ecr` | ECR repository for the API server image |
| `cluster` | ECS Fargate cluster + CloudWatch log group |
| `task` | ECS task definition (api-server) |
| `service` | ECS service wired to the ALB |

### Run

```bash
cd deploy
cp config.env.example config.env   # Fill in AWS_ACCOUNT_ID, DOMAIN
./setup-ecs.sh all
```

### After it runs

- ALB is live (HTTP only initially)
- Add the DNS CNAME record shown in the output
- Validate the ACM certificate, then run `./setup-ecs.sh add-https`
- Note the NAT Gateway EIP
- Resource IDs are saved to `ecs-state.env` (don't delete this file)

---

## Step 2: Provision TEE Nodes (`provision.sh`)

Launches AMD SEV-SNP virtual machines in 3 regions.

### Prerequisites

- `config.env` with node regions filled in and `NODE*_S3_BUCKET` names chosen (buckets don't need to exist yet — `deploy.sh storage` creates them)
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
./provision.sh all        # All 3 nodes
./provision.sh 1          # Just node 1
```

### After it runs

- 3 VMs running, one per region
- SSH keys saved to `deploy/ruonid-node<N>.pem`
- Run `./deploy.sh auto-config` to populate IPs, SGs, and VPC IDs in `config.env`

### Management

```bash
./provision.sh 2 --status      # Check node 2
./provision.sh 3 --terminate   # Terminate node 3 + clear sealed blob
```

---

## Step 3: Deploy OPRF Nodes (`deploy.sh`)

Installs Docker, injects key shares, and starts the OPRF service on each node.

### Prerequisites

- Nodes provisioned and running (step 2)
- `config.env` populated (run `./deploy.sh auto-config` after provisioning)
- Key ceremony completed — key shares at `../ceremony/node-shares/`
  - `public-config.json` (group public key, threshold, verification shares)
  - `node-1-share.json`, `node-2-share.json`, `node-3-share.json`
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
- Each node can act as coordinator (receives client requests, calls a peer, returns combined evaluation)
- Set up API Gateway to expose nodes to clients

---

## Step 4: Lock Nodes (`deploy.sh lock`)

Removes SSH access permanently. Nodes become stateless black boxes — only reachable on port 3001 through PrivateLink.

### Prerequisites

- Nodes deployed and verified (step 3)
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

### Redeploy ECS (API server update)
```bash
./setup-ecs.sh redeploy            # Force new ECS deployment
```

### Check status
```bash
./deploy.sh verify                 # Health-check nodes
./deploy.sh show-ips               # Fetch node IPs from AWS
./setup-ecs.sh status              # ECS service status
```

---

## Node Replacement

If a node fails, replace it with `replace-node.sh`. This provisions a new VM, seals the key share, swaps the NLB target, and starts the node — without touching the other nodes or their PrivateLink endpoints.

```bash
# Full replacement (provision new VM + seal + start)
./replace-node.sh 3 --share-file ../ceremony/node-shares/node-3-share.json

# Skip provisioning (VM already exists, just re-seal and start)
./replace-node.sh 3 --share-file ../ceremony/node-shares/node-3-share.json --skip-provision

# Skip init-seal too (node already sealed, just update NLB and start)
./replace-node.sh 3 --skip-provision --skip-init-seal
```

The NLB target group swap is transparent to peers — the PrivateLink endpoint DNS stays the same, so other nodes' coordinator configs don't need updating.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| S3 upload denied during seal | Missing IAM permissions | Add `s3:PutObject` to the instance profile role |
| Container exits on init-seal | Crash during attestation | `ssh <node> "sudo docker logs toprf-init-seal"` |
| Coordinator can't reach peer | PrivateLink endpoint not available | Check `privatelink-state.env` for endpoint IDs; verify endpoint is in `available` state |
| NLB targets unhealthy | Node not running or wrong port | SSH to node, check `docker ps` and `docker logs toprf-node` |
