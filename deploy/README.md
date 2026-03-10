# TEE Node Deployment Guide

Deploy threshold OPRF nodes across 3 cloud providers, each running inside an AMD SEV-SNP Trusted Execution Environment.

## Overview

Each node runs in a Docker container on a Confidential VM. During init-seal, the node's key share is encrypted with a hardware-bound key and uploaded to cloud storage. On subsequent boots, the node downloads the sealed blob and decrypts it using the same hardware key — the cloud provider cannot read it.

| Node | Cloud | VM Type | Attestation | Sealing |
|------|-------|---------|-------------|---------|
| 1 | GCP | C2D (SEV-SNP) | TSM configfs | v2 (MSG_KEY_REQ) |
| 2 | Azure | DCasv5 (SEV-SNP) | vTPM (HCL report) | v1 (HKDF from measurement) |
| 3 | AWS | C6a/M6a (SEV-SNP) | TSM configfs | v2 (MSG_KEY_REQ) |

Azure doesn't expose `/dev/sev-guest`, so it uses the vTPM for attestation and HKDF-based sealing instead of hardware-derived keys. GCP and AWS use the standard kernel interfaces.

## Prerequisites

**Local machine:**
- `gcloud`, `az`, `aws` CLIs authenticated
- `jq`, `openssl`, `curl` installed
- SSH access to all 3 VMs
- Key ceremony completed (see main README)

**CI:**
- GitHub Actions builds and pushes `ghcr.io/<owner>/toprf-node:latest` on merge to main

---

## 1. Provision VMs

### Node 1: GCP Confidential VM

```bash
gcloud compute instances create toprf-node-1 \
    --project=<PROJECT> \
    --zone=<ZONE> \
    --machine-type=n2d-standard-2 \
    --confidential-compute-type=SEV_SNP \
    --min-cpu-platform="AMD Milan" \
    --maintenance-policy=TERMINATE \
    --image-family=ubuntu-2404-lts-amd64 \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=30GB \
    --scopes=default,storage-read-write \
    --service-account=<SA_EMAIL>
```

**Critical:** Include `storage-read-write` in `--scopes`. If you forget, you must stop the VM and run:
```bash
gcloud compute instances set-service-account toprf-node-1 \
    --zone=<ZONE> --project=<PROJECT> \
    --scopes=default,storage-read-write
gcloud compute instances start toprf-node-1 --zone=<ZONE> --project=<PROJECT>
```
The VM IP will change after restart — update `config.env`.

### Node 2: Azure Confidential VM

```bash
az vm create \
    --resource-group <RG> \
    --name toprf-node-2 \
    --size Standard_DC2as_v5 \
    --image Canonical:ubuntu-24_04-lts:cvm:latest \
    --security-type ConfidentialVM \
    --os-disk-security-encryption-type VMGuestStateOnly \
    --admin-username azureuser \
    --generate-ssh-keys \
    --public-ip-sku Standard
```

Assign a managed identity for blob storage access:
```bash
az vm identity assign --resource-group <RG> --name toprf-node-2
```

### Node 3: AWS SEV-SNP Instance

Launch a `c6a.large` (or `m6a.large`) instance with an AMD SEV-SNP AMI (Ubuntu 24.04).

**Critical:** Attach an IAM instance profile at launch. If you forget:
```bash
aws ec2 associate-iam-instance-profile \
    --instance-id <INSTANCE_ID> \
    --iam-instance-profile Name=<PROFILE_NAME> \
    --region <REGION>
```

The IAM role needs:
```json
{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::<BUCKET>/node-3-sealed.bin"
}
```

Set the IMDS hop limit to 2 (required for Docker containers to reach IMDS):
```bash
aws ec2 modify-instance-metadata-options \
    --instance-id <INSTANCE_ID> \
    --http-put-response-hop-limit 2 \
    --region <REGION>
```

---

## 2. Configure

```bash
cd deploy
cp config.env.example config.env
```

Fill in the `[manual]` fields in `config.env`, then auto-populate IPs and other derived fields:

```bash
./deploy.sh auto-config
```

---

## 3. Deploy

### Full deployment (all nodes)

```bash
./deploy.sh all
```

This runs: `setup-vms` → `pull` → `storage` → `certs` → `init-seal` → `start` → `firewall` → `proxy-config` → `verify`

### Per-node deployment

Use `--nodes` to target specific nodes. This is useful when one node fails and you need to retry without rerunning everything:

```bash
# Deploy only node 2
./deploy.sh --nodes 2 setup-vms pull storage certs init-seal start firewall

# Init-seal just node 3 (e.g. after fixing IAM)
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

# 3. Create storage buckets and bind IAM identities
./deploy.sh storage

# 4. Generate mTLS certs and distribute to VMs
./deploy.sh certs

# 5. Interactive key injection (per-node recommended)
./deploy.sh --nodes 1 init-seal
./deploy.sh --nodes 2 init-seal
./deploy.sh --nodes 3 init-seal

# 6. Start nodes in normal mode (auto-unseal from cloud storage)
./deploy.sh start

# 7. Open port 3001 from proxy IP to each node
./deploy.sh firewall

# 8. Generate proxy config for ECS
./deploy.sh proxy-config

# 9. Health check
./deploy.sh verify
```

---

## 4. What each step does

### `setup-vms`
Installs Docker on each VM via `curl -fsSL https://get.docker.com | sudo sh`.

### `pull`
Runs `docker pull ghcr.io/<owner>/toprf-node:latest` on each VM.

### `storage`
Creates sealed blob storage (GCS bucket, Azure blob container, S3 bucket) and grants the VM's identity read/write access.

### `certs`
Generates a CA + per-node TLS certificates with the node's public IP as a SAN. Also generates a proxy client certificate for mTLS. Distributes certs to each VM at `/etc/toprf/certs/`.

### `init-seal`
For each node:
1. Starts a temporary container in init-seal mode (ephemeral TLS, `/attest` and `/init-key` endpoints)
2. Waits for the attestation endpoint to be ready
3. Pauses for you to verify the attestation report
4. Sends the key share via `/init-key`
5. The node seals the key share and uploads the sealed blob to cloud storage
6. Container exits

The deploy script automatically detects available hardware interfaces per VM:
- `/dev/sev-guest` → passed as `--device` for MSG_KEY_REQ (GCP, AWS)
- `/sys/kernel/config/tsm/report` → bind-mounted for TSM configfs attestation (GCP, AWS)
- `/dev/tpmrm0` or `/dev/tpm0` → passed as `--device` for vTPM attestation (Azure)

If the container exits prematurely (e.g. Azure without the code changes), the script detects it and offers to skip.

### `start`
Starts each node in normal mode with `SEALED_KEY_URL` pointing to its sealed blob. The node auto-unseals on boot.

### `firewall`
Opens port 3001 on each node's firewall, restricted to the proxy IP only.

### `verify`
Runs an mTLS health check against each node.

---

## 5. Sealing modes

### v2: Hardware-derived key (GCP, AWS)
Uses AMD SEV-SNP `MSG_KEY_REQ` to request a key from the CPU's secure processor. The key is unique to the physical chip + software measurement. Even with access to the sealed blob and cloud storage, the data cannot be decrypted without the same physical CPU running the same code.

### v1: HKDF from measurement (Azure)
Azure doesn't expose `/dev/sev-guest`, so `MSG_KEY_REQ` is unavailable. Instead, the sealing key is derived via HKDF from the SNP measurement (firmware + kernel + initrd hash) plus a random salt. The measurement binds the sealed blob to the specific VM image. The sealed blob is protected by Azure managed identity + blob storage IAM.

The auto-unseal code detects the blob version automatically and uses the correct unseal path.

---

## 6. Adding a new node

1. **Provision the VM** following the instructions in section 1 for the relevant cloud provider
2. **Key requirement:** The VM must have:
   - SSH access from your deploy machine
   - IAM permissions to read/write its sealed blob storage
   - AMD SEV-SNP enabled
3. **Add to `config.env`:** Set the node's IP, bucket, and provider fields
4. **Run auto-config** to fill in derived fields: `./deploy.sh auto-config`
5. **Deploy the single node:**
   ```bash
   ./deploy.sh --nodes <N> setup-vms pull storage certs init-seal start firewall
   ```
6. **Verify:** `./deploy.sh --nodes <N> verify`
7. **Update proxy config** if the proxy needs to know about the new node:
   ```bash
   ./deploy.sh proxy-config
   ```

---

## 7. Common issues

### "error decoding response body" on init-key (AWS)
**Cause:** No IAM instance profile attached. The IMDS returns 404 for credentials, and the code fails parsing HTML as JSON.
**Fix:** `aws ec2 associate-iam-instance-profile --instance-id <ID> --iam-instance-profile Name=<PROFILE>`

### GCS upload 403 Forbidden (GCP)
**Cause:** VM has `devstorage.read_only` scope instead of `devstorage.read_write`.
**Fix:** Stop the VM, change scopes with `gcloud compute instances set-service-account`, restart. Update the IP in `config.env` (it changes on restart).

### "Container exited prematurely" on init-seal
**Cause:** The node container couldn't start (missing device) or crashed during attestation.
**Fix:** Check container logs: `ssh <node> "sudo docker logs toprf-init-seal"`. Common causes:
- Missing `/dev/sev-guest` on Azure → expected, code falls back to vTPM
- TSM configfs mkdir ENXIO → expected on Azure, code falls back
- If all providers fail, check that the VM is actually SEV-SNP enabled

### "Waiting for attestation endpoint" timeout
**Cause:** The container is running but not serving HTTPS yet, or it crashed.
**Fix:** SSH to the node and check `sudo docker logs toprf-init-seal`. The script checks for container exit during the wait, so if it's truly stuck, there may be a network issue.

### Sealed blob version mismatch on auto-unseal
**Cause:** The node was sealed with v1 but is now trying to unseal with v2 (or vice versa).
**Fix:** The auto-unseal code detects the version automatically. If you see this error, the sealed blob may be corrupted. Re-run init-seal: `./deploy.sh --nodes <N> init-seal`

---

## 8. Redeployment

### Update node binary (code change)
```bash
# After CI builds a new image:
./deploy.sh redeploy              # All nodes
./deploy.sh --nodes 2 redeploy    # Single node
```

### Key rotation
See "Zero-Downtime Key Rotation" in the main README. Summary:
1. Derive new node shares from admin shares
2. Provision 3 new VMs
3. Deploy to new VMs with `./deploy.sh all`
4. Switch proxy to new nodes
5. Decommission old VMs
