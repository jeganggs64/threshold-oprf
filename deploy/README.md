# Deployment Guide

Deploy the RuonID API server, TOPRF proxy, and 3 threshold OPRF nodes across AWS.

## Architecture

```
Internet → ALB (443) → ECS Fargate (eu-west-2):
  ├── api-server  (Node.js, port 3002)
  └── toprf-proxy (Rust, port 3000)
         ↓ VPC Peering (private IPs)
  ├── Node 1 (eu-west-1, :3001, TLS)
  ├── Node 2 (eu-west-1, :3001, TLS)
  └── Node 3 (us-east-2, :3001, TLS)
```

Each node runs in a Docker container on an AMD SEV-SNP Confidential VM. Key shares are sealed to the hardware and stored encrypted in S3 — AWS cannot read them.

---

## Step 1: ECS Infrastructure (`setup-ecs.sh`)

Sets up the cloud infrastructure for the API server and TOPRF proxy.

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
| `roles` | IAM roles for ECS task execution and runtime (DynamoDB, KMS, S3) |
| `config-bucket` | S3 bucket for proxy config and certs |
| `ecr` | ECR repository for the API server image |
| `cluster` | ECS Fargate cluster + CloudWatch log group |
| `task` | ECS task definition (api-server + toprf-proxy + config-init sidecar) |
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
- Note the NAT Gateway EIP — add it to `config.env` as `PROXY_IP`
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
- Proxy config + CA cert uploaded to S3 (`./setup-ecs.sh upload-config`)

### What it does

**Phase 1: `pre-seal`** (automated)

| Step | What it does |
|------|-------------|
| `setup-vms` | Installs Docker on each VM |
| `pull` | Pulls the node image from ghcr.io |
| `storage` | Creates S3 buckets for sealed key blobs |
| `certs` | Generates CA + per-node TLS certs, distributes to VMs |

**Phase 2: `init-seal`** (interactive)

For each node:
1. Starts a temporary container in init-seal mode
2. Waits for the attestation endpoint
3. Pauses so you can verify the SEV-SNP attestation report
4. Sends the key share — node seals it to hardware and uploads to S3

**Phase 3: `post-seal`** (automated)

| Step | What it does |
|------|-------------|
| `start` | Starts nodes in normal mode (auto-unseal from S3) |
| `firewall` | Opens port 3001 from proxy VPC CIDR |
| `peering` | VPC peering between proxy and each node VPC |
| `proxy-config` | Generates `proxy-config.production.json` with private IPs |
| `verify` | Health-checks all nodes via HTTPS |

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

- All nodes are sealed, running, and reachable from the proxy
- Upload the generated proxy config: `./setup-ecs.sh upload-config`
- Redeploy ECS to pick up the new config: `./setup-ecs.sh redeploy`
- Verify end-to-end by hitting the API

---

## Step 4: Lock Nodes (`deploy.sh lock`)

Removes SSH access permanently. Nodes become stateless black boxes — only reachable on port 3001 from the proxy VPC.

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

### Redeploy ECS (API/proxy update)
```bash
./setup-ecs.sh upload-config       # Upload new proxy config
./setup-ecs.sh redeploy            # Force new ECS deployment
```

### Check status
```bash
./deploy.sh verify                 # Health-check nodes
./deploy.sh show-ips               # Fetch node IPs from AWS
./setup-ecs.sh status              # ECS service status
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| S3 upload denied during seal | Missing IAM permissions | Add `s3:PutObject` to the instance profile role |
| Container exits on init-seal | Crash during attestation | `ssh <node> "sudo docker logs toprf-init-seal"` |
| Proxy can't reach nodes | Routes or SG missing | Check VPC peering routes + SG allows TCP 3001 from `10.0.0.0/16` |
| VPC peering "already exists" | Stale peering from previous run | Delete old peering in AWS console |
