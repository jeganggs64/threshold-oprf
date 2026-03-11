# TEE Node Deployment Guide

Deploy threshold OPRF nodes across 3 AWS regions, each running inside an AMD SEV-SNP Trusted Execution Environment. Nodes communicate with the proxy over VPC peering using server-side TLS.

## Overview

Each node runs in a Docker container on a Confidential VM. During init-seal, the node's key share is encrypted with a hardware-bound key and uploaded to S3. On subsequent boots, the node downloads the sealed blob and decrypts it using the same hardware key — AWS cannot read it.

| Node | Region | VM Type | Sealing |
|------|--------|---------|---------|
| 1 | ap-southeast-1 (Singapore) | C6a/M6a (SEV-SNP) | v2 (MSG_KEY_REQ) |
| 2 | us-east-1 (Virginia) | C6a/M6a (SEV-SNP) | v2 (MSG_KEY_REQ) |
| 3 | eu-west-1 (Ireland) | C6a/M6a (SEV-SNP) | v2 (MSG_KEY_REQ) |

## Architecture

```
Internet → ALB (443) → ECS Fargate (eu-west-2):
  ├── toprf-proxy (Rust, port 3000)
  └── api-server (Node.js, port 3002)
         ↓ VPC Peering (private IPs)
  ├── Node 1 (ap-southeast-1, :3001, TLS)
  ├── Node 2 (us-east-1, :3001, TLS)
  └── Node 3 (eu-west-1, :3001, TLS)
```

**Security model:**
- Nodes are only reachable from the proxy VPC via VPC peering
- Security groups restrict port 3001 to the proxy VPC CIDR
- Server-side TLS with CA-signed certificates for encryption in transit
- No mTLS required — network isolation via VPC peering replaces client auth

## Prerequisites

**Local machine:**
- `aws` CLI authenticated
- `jq`, `openssl`, `curl` installed
- SSH access to all 3 VMs
- Key ceremony completed (see main README)

**CI:**
- GitHub Actions builds and pushes `ghcr.io/<owner>/toprf-node:latest` on merge to main

---

## 1. Provision VMs

Provision nodes using the provisioning script:

```bash
./provision.sh 1    # Node 1 in ap-southeast-1
./provision.sh 2    # Node 2 in us-east-1
./provision.sh 3    # Node 3 in eu-west-1
./provision.sh all  # All 3 nodes
```

Each node is a `c6a.large` (or `m6a.large`) instance running Amazon Linux 2023 with AMD SEV-SNP.

The provisioning script handles AMI selection, IMDS hop limit, IAM profile attachment, and tagging automatically. See `provision.sh --help` for details.

To manage individual nodes:

```bash
./provision.sh 2 --status     # Check node 2
./provision.sh 1 --terminate  # Tear down node 1 + clear sealed blob
```

---

## 2. Configure

```bash
cd deploy
cp config.env.example config.env
```

Fill in the `[manual]` fields, then auto-populate IPs, SGs, and VPC IDs:

```bash
./deploy.sh auto-config
```

---

## 3. Deploy

### Full deployment (all nodes)

```bash
./deploy.sh all
```

This runs: `setup-vms` → `pull` → `storage` → `certs` → `init-seal` → `start` → `firewall` → `peering` → `proxy-config` → `verify`

### Per-node deployment

```bash
# Deploy only node 2
./deploy.sh --nodes 2 setup-vms pull storage certs init-seal start

# Init-seal just node 3
./deploy.sh --nodes 3 init-seal

# Restart nodes 1 and 3
./deploy.sh --nodes 1,3 start

# Verify a single node
./deploy.sh --nodes 1 verify
```

### Step by step

```bash
# 1. Install Docker on VMs
./deploy.sh setup-vms

# 2. Pull the node image from ghcr.io
./deploy.sh pull

# 3. Create S3 buckets for sealed key blobs
./deploy.sh storage

# 4. Generate TLS certs and distribute to VMs
./deploy.sh certs

# 5. Interactive key injection (per-node recommended)
./deploy.sh --nodes 1 init-seal
./deploy.sh --nodes 2 init-seal
./deploy.sh --nodes 3 init-seal

# 6. Start nodes in normal mode (auto-unseal from S3)
./deploy.sh start

# 7. Open port 3001 from proxy VPC CIDR
./deploy.sh firewall

# 8. Set up VPC peering between proxy and node VPCs
./deploy.sh peering

# 9. Generate proxy config (uses private IPs)
./deploy.sh proxy-config

# 10. Health check
./deploy.sh verify
```

---

## 4. What each step does

### `setup-vms`
Installs Docker on each VM via `dnf install docker` (Amazon Linux 2023).

### `pull`
Runs `docker pull ghcr.io/<owner>/toprf-node:latest` on each VM.

### `storage`
Creates S3 buckets for sealed key blobs in each node's region.

### `certs`
Generates a CA and per-node TLS server certificates with both public and private IPs as SANs. Distributes certs to each VM at `/etc/toprf/certs/`.

### `init-seal`
For each node:
1. Starts a temporary container in init-seal mode
2. Waits for the attestation endpoint to be ready
3. Pauses for you to verify the attestation report
4. Sends the key share via `/init-key`
5. The node seals the key share and uploads to S3
6. Container exits

### `start`
Starts each node in normal mode with `SEALED_KEY_URL` pointing to its S3 sealed blob. The node auto-unseals on boot and serves HTTPS on port 3001.

### `firewall`
Adds a security group rule allowing TCP 3001 from the proxy VPC CIDR.

### `peering`
Creates VPC peering connections between the proxy VPC (eu-west-2) and each node's VPC, with routes in both directions.

### `proxy-config`
Generates `docker/proxy-config.production.json` using private IPs for node endpoints.

### `verify`
Health-checks each node via HTTPS with CA cert verification.

---

## 5. VPC Peering

The proxy connects to nodes over VPC peering using private IPs. This provides:

- **Network isolation**: Nodes are not publicly accessible on port 3001
- **No mTLS needed**: Security groups + VPC peering replace client certificate auth
- **Lower latency**: Direct AWS backbone instead of public internet
- **Stable addressing**: Private IPs don't change on restart

The `peering` step creates cross-region VPC peering connections and configures route tables automatically.

---

## 6. Common issues

### "error decoding response body" on init-key
**Cause:** No IAM instance profile attached. IMDS returns 404.
**Fix:** `aws ec2 associate-iam-instance-profile --instance-id <ID> --iam-instance-profile Name=<PROFILE>`

### S3 upload denied during seal
**Cause:** IAM role missing S3 write permissions for the sealed blob bucket.
**Fix:** Update the instance profile's IAM role with `s3:PutObject` on `arn:aws:s3:::<BUCKET>/*`.

### "Container exited prematurely" on init-seal
**Cause:** The node container couldn't start or crashed during attestation.
**Fix:** Check logs: `ssh <node> "sudo docker logs toprf-init-seal"`.

### VPC peering "already exists" error
**Cause:** A peering connection was already created (possibly from a previous run).
**Fix:** Check existing peering connections in the AWS console and delete stale ones.

### Proxy can't reach nodes after peering
**Cause:** Route tables not updated, or security group missing.
**Fix:** Verify routes exist in both the proxy private RT and node VPC RT. Check SG allows TCP 3001 from `10.0.0.0/16`.

---

## 7. Redeployment

### Update node binary (code change)
```bash
# After CI builds a new image:
./deploy.sh redeploy              # All nodes
./deploy.sh --nodes 2 redeploy    # Single node
```

### Key rotation
See "Zero-Downtime Key Rotation" in the main README.
