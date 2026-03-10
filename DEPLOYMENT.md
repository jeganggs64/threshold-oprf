# Threshold OPRF Deployment Guide

Production deployment of the threshold OPRF system: Express API server + Rust threshold proxy + 3 TEE nodes across GCP, Azure, and AWS.

## Architecture

```
Mobile App
    |  HTTPS (<your-domain>)
    v
  Cloud Load Balancer (any provider)
    |
    v
  Express API (port 3002)        <-- attestation, rate limiting, billing
    |  HTTP (internal)
    v
  Rust TOPRF Proxy (port 3000)   <-- fans out to TEE nodes, DLEQ verification
    |  mTLS
    +--- Node 1 (GCP Singapore,     N2D Confidential VM,  SEV-SNP)
    +--- Node 2 (Azure US East,     DCasv5 Confidential VM, SEV-SNP)
    +--- Node 3 (AWS EU Ireland,    C6a SEV-SNP instance)
```

Express and the Rust proxy run together on the same host. Only Express is exposed externally. The Rust proxy communicates with TEE nodes over mTLS.

Nodes are spread across three cloud providers in different geographic jurisdictions to minimize the impact of a single provider compromise or legal order — each provider only has 1-of-3 shares (below the threshold of 2).

### Cost estimate

| Provider | Instance | vCPUs | RAM | Region | ~Monthly |
|----------|----------|-------|-----|--------|----------|
| GCP | n2d-standard-2 (Confidential VM) | 2 | 8 GB | asia-southeast1 (Singapore) | ~$85 |
| Azure | Standard_DC2as_v5 | 2 | 8 GB | East US | ~$63 |
| AWS | c6a.large + SEV-SNP | 2 | 4 GB | eu-west-1 (Ireland) | ~$64 |
| **Total nodes** | | | | | **~$212/mo** |

These are the smallest SEV-SNP capable instances on each provider. Scaling to larger instances (e.g., 4 vCPUs) changes the SEV-SNP measurement (vCPU count affects the VMSA blob in the launch digest), so resealing is required after any instance size change.

### Sealed blob storage

Each node's sealed blob is stored on the **same provider** where the VM runs. The blob is encrypted with a key derived from the specific physical AMD chip via MSG_KEY_REQ — even the cloud provider cannot decrypt it (this is the SEV-SNP guarantee). Each VM uses its native IAM role / service account / instance profile to access its own storage, so no cross-provider credentials are needed.

| Node | VM + Storage |
|------|-------------|
| Node 1 | GCP Singapore (Cloud Storage) |
| Node 2 | Azure US East (Blob Storage) |
| Node 3 | AWS EU Ireland (S3) |

---

## Step 1: Generate keys

Run on an air-gapped machine. This generates the threshold key shares and admin recovery shares.

```bash
cd threshold-oprf
cargo build --release -p toprf-keygen

./target/release/toprf-keygen init \
  --admin-threshold 3 --admin-shares 5 \
  --node-threshold 2 --node-shares 3 \
  --output-dir ./ceremony
```

Outputs:

```
ceremony/
  public-config.json                  # group public key + verification shares (safe to share)
  node-shares/
    node-1-share.json                 # SECRET - node 1 key share
    node-2-share.json                 # SECRET - node 2 key share
    node-3-share.json                 # SECRET - node 3 key share
  admin-shares/
    admin-share-{1..5}.json           # SECRET - admin recovery shares
```

Keep `public-config.json` — you'll need the `group_public_key` and `verification_shares` later.

---

## Step 2: Provision 3 TEE servers

All three providers offer managed AMD SEV-SNP confidential VMs — no bare metal setup or BIOS configuration required.

### Node 1: GCP Singapore

```bash
# SEV-SNP VMs can't live migrate, so maintenance-policy must be TERMINATE
gcloud compute instances create toprf-node-1 \
  --zone=asia-southeast1-b \
  --machine-type=n2d-standard-2 \
  --confidential-compute-type=SEV_SNP \
  --maintenance-policy=TERMINATE \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud
```

Attestation: GCP metadata API (`SNP_PROVIDER=gcp`) or `/dev/sev-guest` (`SNP_PROVIDER=raw`).

### Node 2: Azure US East

```bash
# Create resource group first: az group create --name <azure-rg> --location eastus
# Confidential VMs require vTPM enabled
az vm create \
  --resource-group <azure-rg> \
  --name toprf-node-2 \
  --location eastus \
  --size Standard_DC2as_v5 \
  --image Canonical:ubuntu-24_04-lts:cvm:latest \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --enable-vtpm true \
  --admin-username azureuser \
  --generate-ssh-keys
```

Attestation: `/dev/sev-guest` (`SNP_PROVIDER=raw`). Azure also provides Microsoft Azure Attestation (MAA) service for remote verification.

### Node 3: AWS EU Ireland

```bash
# Find the latest Ubuntu 24.04 AMI
AMI_ID=$(aws ec2 describe-images --region eu-west-1 --owners 099720109477 --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' --output text)

# Create SSH key pair (if needed)
aws ec2 create-key-pair --key-name <aws-key-name> --region eu-west-1 --query 'KeyMaterial' --output text > <aws-key-name>.pem
chmod 400 <aws-key-name>.pem

# Create security group (allow SSH only for now; port 3001 is opened in Step 8)
SG_ID=$(aws ec2 create-security-group --group-name toprf-node3 --description "TOPRF Node 3" --region eu-west-1 --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr "$(curl -s4 ifconfig.me)/32" --region eu-west-1

# Launch the instance
aws ec2 run-instances --region eu-west-1 --instance-type c6a.large --image-id "$AMI_ID" --cpu-options AmdSevSnp=enabled --key-name <aws-key-name> --security-group-ids "$SG_ID"
```

Attestation: `/dev/sev-guest` (`SNP_PROVIDER=raw`). AWS signs reports with VLEK (Versioned Loaded Endorsement Key) rather than VCEK.

**Note:** AWS SEV-SNP is currently available in only 2 regions: `us-east-2` (Ohio) and `eu-west-1` (Ireland). Only M6a, C6a, and R6a instance families support it.

---

## Step 3: Build and push Docker images

All images must be built for `linux/amd64` since the TEE VMs are x86_64. If building on Apple Silicon, always pass `--platform linux/amd64`.

### Build from the threshold-oprf repo

```bash
cd threshold-oprf

# Node image
docker buildx build --platform linux/amd64 -f deploy/sev/Dockerfile.sev -t toprf-node:latest --load .

# Proxy image
docker buildx build --platform linux/amd64 -f deploy/Dockerfile.proxy -t toprf-proxy:latest --load .
```

### Push to ECR

```bash
aws ecr get-login-password --region eu-west-2 | docker login --username AWS --password-stdin <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com

docker tag toprf-node:latest <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com/<ecr-repo-prefix>/toprf-node:latest
docker push <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com/<ecr-repo-prefix>/toprf-node:latest

docker tag toprf-proxy:latest <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com/<ecr-repo-prefix>/toprf-proxy:latest
docker push <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com/<ecr-repo-prefix>/toprf-proxy:latest
```

### Install Docker + pull image on each VM

SSH into each VM and run:

```bash
# GCP:   gcloud compute ssh toprf-node-1 --zone=asia-southeast1-b
# Azure: ssh azureuser@<azure-node-ip>
# AWS:   ssh -i <aws-key-name>.pem ubuntu@<aws-node-ip>

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Install AWS CLI (needed for ECR login)
sudo apt update && sudo apt install -y unzip curl
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
rm -rf awscliv2.zip aws/

# Configure AWS credentials
aws configure
# Access Key ID: <your-key>
# Secret Access Key: <your-secret>
# Region: eu-west-2
# Output format: (press Enter for default)

# Login to ECR and pull the node image
aws ecr get-login-password --region eu-west-2 | docker login --username AWS --password-stdin <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com
docker pull <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com/<ecr-repo-prefix>/toprf-node:latest
```

### What changes the measurement

The measurement is the SHA-384 hash of the guest's initial memory state (OVMF firmware + kernel + initrd + VMSAs), computed by the AMD Secure Processor during VM launch.

| Change | Measurement changes? | Action required |
|--------|---------------------|-----------------|
| Application code update | No | Just redeploy the binary |
| Kernel update | Yes | Re-run init-seal |
| Firmware/UEFI update (provider-pushed) | Yes | Re-run init-seal |
| vCPU count change (instance resize) | Yes | Re-run init-seal |
| Disk/data changes | No | Nothing |
| Different physical host (same provider) | Yes (different chip key) | Re-run init-seal |

**Note:** With MSG_KEY_REQ sealing (v2), the sealed blob is bound to the **specific physical CPU chip**, not just the measurement. Moving to a different physical host (e.g., VM stop/start on cloud) requires re-running the init-seal flow.

---

## Step 4: Initial key injection (init-seal)

This is the critical step. Each node seals its key share using the AMD Secure Processor's MSG_KEY_REQ, which derives a key unique to this specific CPU chip + measurement + TCB version. The sealed blob can only be decrypted on the same physical chip running the same software.

### How it works

The `--init-seal` mode uses attested TLS to securely inject the key share:

1. **Node boots** inside the SEV-SNP VM and generates an ephemeral TLS keypair
2. **Node binds the TLS key to the attestation report** — puts the SHA-256 of the TLS public key into the `REPORT_DATA` field of the SNP attestation report
3. **Node serves two endpoints** over HTTPS:
   - `GET /attest` — returns the raw AMD attestation report
   - `POST /init-key` — accepts the key share, seals it, uploads, then exits
4. **Operator verifies the attestation** — checks AMD signature chain (ARK → ASK → VCEK), confirms the MEASUREMENT matches the expected binary, confirms REPORT_DATA contains the TLS pubkey hash
5. **Operator sends the key share** via the attested TLS channel
6. **Node seals** using `MSG_KEY_REQ(MEASUREMENT | TCB_VERSION)` and uploads to object storage

### Field selector bitmask

The AMD firmware ABI allows the guest to choose which fields are mixed into the MSG_KEY_REQ derived key via a bitmask. The implementation explicitly uses **only safe fields**:

- **MEASUREMENT** (bit 3) — SHA-384 of firmware + kernel + initrd + VMSAs. Stable across reboots on the same image.
- **TCB_VERSION** (bit 5) — Firmware and microcode security versions. Stable until a microcode update.

Fields explicitly **NOT** included:

- GUEST_POLICY (bit 0) — could change if VM policy is reconfigured
- IMAGE_ID (bit 1) — operator-set, may vary between deployments
- FAMILY_ID (bit 2) — operator-set, may vary between deployments
- GUEST_SVN (bit 4) — changes with guest software version updates

### Set up blob storage

Create a storage bucket on each provider for that node's sealed blob. Grant the VM's identity read/write access.

#### GCP Cloud Storage (Node 1)

```bash
gcloud storage buckets create gs://<gcp-sealed-bucket> --location=asia-southeast1

gcloud storage buckets add-iam-policy-binding gs://<gcp-sealed-bucket> \
  --member="serviceAccount:$(gcloud compute instances describe toprf-node-1 \
    --zone=asia-southeast1-b --format='get(serviceAccounts[0].email)')" \
  --role="roles/storage.objectAdmin"
```

#### Azure Blob Storage (Node 2)

```bash
# Enable managed identity on the VM
az vm identity assign --resource-group <azure-rg> --name toprf-node-2

# Create storage account + container (do this in the Azure portal if CLI auth fails)
az storage account create --name <azure-storage-account> --resource-group <azure-rg> --location eastus --sku Standard_LRS
az storage container create --name sealed-blobs --account-name <azure-storage-account> --public-access off

# Grant the VM's managed identity access
VM_IDENTITY=$(az vm show --resource-group <azure-rg> --name toprf-node-2 --query identity.principalId -o tsv)
az role assignment create --assignee "$VM_IDENTITY" --role "Storage Blob Data Contributor" --scope "/subscriptions/<azure-subscription-id>/resourceGroups/<azure-rg>/providers/Microsoft.Storage/storageAccounts/<azure-storage-account>"
```

#### AWS S3 (Node 3)

```bash
aws s3 mb s3://<aws-sealed-bucket> --region eu-west-1

aws iam create-policy --policy-name toprf-node3-sealed-blob --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::<aws-sealed-bucket>/node-3-sealed.bin"}]}'

aws iam create-role --role-name toprf-node3-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

aws iam attach-role-policy --role-name toprf-node3-role --policy-arn arn:aws:iam::<aws-account-id>:policy/toprf-node3-sealed-blob

aws iam create-instance-profile --instance-profile-name toprf-node3-profile
aws iam add-role-to-instance-profile --instance-profile-name toprf-node3-profile --role-name toprf-node3-role

# Find the instance ID
aws ec2 describe-instances --region eu-west-1 --filters "Name=instance-state-name,Values=running,pending" --query 'Reservations[*].Instances[*].[InstanceId,InstanceType]' --output text

# Associate the profile (replace with your instance ID)
aws ec2 associate-iam-instance-profile --instance-id <node3-instance-id> --iam-instance-profile Name=toprf-node3-profile --region eu-west-1
```

### Run init-seal on each node

SSH into each TEE VM and run the Docker container in init-seal mode. The `--device` flag passes through the SEV-SNP attestation device so the container can access the AMD Secure Processor.

#### Node 1 (GCP Singapore)

```bash
docker run --rm -it \
  -e SNP_PROVIDER=gcp \
  -e EXPECTED_VERIFICATION_SHARE=<node-1-verification-share> \
  --device /dev/sev-guest:/dev/sev-guest \
  -p 3001:3001 \
  <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com/<ecr-repo-prefix>/toprf-node:latest \
  --init-seal \
  --upload-url "gs://<gcp-sealed-bucket>/node-1-sealed.bin" \
  --port 3001
```

The node starts an HTTPS server with an ephemeral self-signed certificate. From your local machine:

```bash
# 1. Fetch the attestation report
curl -k https://<gcp-node-ip>:3001/attest -o report.bin

# 2. Verify the attestation report:
#    - AMD signature chain valid (ARK → ASK → VCEK)?
#    - MEASUREMENT matches expected binary?
#    - REPORT_DATA[0..32] == SHA-256 of the TLS certificate's public key?
#    (Use snpguest or a custom verifier)

# 3. Once verified, send the key share
curl -k https://<gcp-node-ip>:3001/init-key \
  -X POST \
  -H "Content-Type: application/json" \
  -d @ceremony/node-shares/node-1-share.json
```

The node will:
- Call MSG_KEY_REQ to derive a chip-specific key K
- Encrypt the key share with K using AES-256-GCM (v2 sealed blob format)
- Upload the sealed blob to the `--upload-url`
- Zeroize the plaintext key share from memory
- Exit

#### Node 2 (Azure US East)

```bash
docker run --rm -it \
  -e SNP_PROVIDER=raw \
  -e EXPECTED_VERIFICATION_SHARE=<node-2-verification-share> \
  --device /dev/sev-guest:/dev/sev-guest \
  -p 3001:3001 \
  <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com/<ecr-repo-prefix>/toprf-node:latest \
  --init-seal \
  --upload-url "https://<azure-storage-account>.blob.core.windows.net/sealed-blobs/node-2-sealed.bin" \
  --port 3001
```

Then from your local machine, verify attestation and send `node-2-share.json` as above.

#### Node 3 (AWS EU Ireland)

```bash
docker run --rm -it \
  -e SNP_PROVIDER=raw \
  -e EXPECTED_VERIFICATION_SHARE=<node-3-verification-share> \
  --device /dev/sev-guest:/dev/sev-guest \
  -p 3001:3001 \
  <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com/<ecr-repo-prefix>/toprf-node:latest \
  --init-seal \
  --upload-url "s3://<aws-sealed-bucket>/node-3-sealed.bin" \
  --port 3001
```

Then from your local machine, verify attestation and send `node-3-share.json` as above.

### Security properties of init-seal

- **Attested TLS** — the TLS public key hash is embedded in the AMD-signed attestation report. The operator verifies this before sending the key share, ensuring they're talking to the genuine TEE (not an impersonator).
- **MSG_KEY_REQ** — the sealing key is derived by the AMD Secure Processor from the chip's unique root key (VCEK). It never exists outside the CPU. A different chip produces a completely different key.
- **Field selector** — explicitly set to `MEASUREMENT | TCB_VERSION` only. No per-boot-random fields are included.
- **MSG_KEY_REQ sealing** — even though the blob is stored on the same provider as the VM, the blob is AES-256-GCM encrypted with a key derived from the specific physical AMD chip. The provider cannot decrypt it — this is the core SEV-SNP guarantee.
- **One-time endpoint** — `/init-key` accepts exactly one call, then the node exits. There is no persistent key injection endpoint.

---

## Step 5: Generate mTLS certificates

Generate a private CA and certificates for mutual TLS between the proxy and nodes. Do this **before** starting nodes in normal mode.

```bash
cd threshold-oprf
bash scripts/gen-certs.sh
```

This creates:

```
certs/
  ca/ca.pem, ca.key                      # Private CA
  nodes/node1.pem, node1.key             # Node 1 server cert
  nodes/node2.pem, node2.key             # Node 2 server cert
  nodes/node3.pem, node3.key             # Node 3 server cert
  proxy/proxy-client.pem, proxy-client.key  # Proxy client cert (mTLS)
```

Copy certs to each VM (create `/etc/toprf/certs/` first):

```bash
# On each VM:
sudo mkdir -p /etc/toprf/certs

# From your local machine — copy the relevant certs to each node:
# Node 1 (GCP):
gcloud compute scp certs/ca/ca.pem certs/nodes/node1.pem certs/nodes/node1.key toprf-node-1:/tmp/ --zone=asia-southeast1-b
# Then on the VM: sudo mv /tmp/{ca.pem,node1.pem,node1.key} /etc/toprf/certs/

# Node 2 (Azure):
scp certs/ca/ca.pem certs/nodes/node2.pem certs/nodes/node2.key azureuser@<azure-ip>:/tmp/
# Then on the VM: sudo mv /tmp/{ca.pem,node2.pem,node2.key} /etc/toprf/certs/

# Node 3 (AWS):
scp -i <aws-key-name>.pem certs/ca/ca.pem certs/nodes/node3.pem certs/nodes/node3.key ubuntu@<aws-ip>:/tmp/
# Then on the VM: sudo mv /tmp/{ca.pem,node3.pem,node3.key} /etc/toprf/certs/
```

---

## Step 6: Start nodes in normal mode

After init-seal completes, restart each node in normal mode. The node fetches its sealed blob, calls MSG_KEY_REQ to derive the same chip-specific key, and unseals.

### Node 1 (GCP Singapore)

```bash
docker run -d --name toprf-node --restart=unless-stopped \
  -e SEALED_KEY_URL="gs://<gcp-sealed-bucket>/node-1-sealed.bin" \
  -e EXPECTED_VERIFICATION_SHARE=<node-1-verification-share> \
  -e SNP_PROVIDER=gcp \
  --device /dev/sev-guest:/dev/sev-guest \
  -v /etc/toprf/certs:/etc/toprf/certs:ro \
  -p 3001:3001 \
  <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com/<ecr-repo-prefix>/toprf-node:latest \
  --port 3001 \
  --tls-cert /etc/toprf/certs/node1.pem \
  --tls-key /etc/toprf/certs/node1.key \
  --client-ca /etc/toprf/certs/ca.pem
```

On boot, the node:
1. Fetches the sealed blob from the cloud storage URL
2. Calls `MSG_KEY_REQ(MEASUREMENT | TCB_VERSION)` — same chip + same software → same key K
3. Decrypts the key share with K
4. Verifies `k_i * G == expected_verification_share`
5. Starts serving `/health`, `/info`, `/partial-evaluate`

### Node 2 (Azure US East)

```bash
docker run -d --name toprf-node --restart=unless-stopped \
  -e SEALED_KEY_URL="https://<azure-storage-account>.blob.core.windows.net/sealed-blobs/node-2-sealed.bin" \
  -e EXPECTED_VERIFICATION_SHARE=<node-2-verification-share> \
  -e SNP_PROVIDER=raw \
  --device /dev/sev-guest:/dev/sev-guest \
  -v /etc/toprf/certs:/etc/toprf/certs:ro \
  -p 3001:3001 \
  <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com/<ecr-repo-prefix>/toprf-node:latest \
  --port 3001 \
  --tls-cert /etc/toprf/certs/node2.pem \
  --tls-key /etc/toprf/certs/node2.key \
  --client-ca /etc/toprf/certs/ca.pem
```

### Node 3 (AWS EU Ireland)

```bash
docker run -d --name toprf-node --restart=unless-stopped \
  -e SEALED_KEY_URL="s3://<aws-sealed-bucket>/node-3-sealed.bin" \
  -e EXPECTED_VERIFICATION_SHARE=<node-3-verification-share> \
  -e SNP_PROVIDER=raw \
  --device /dev/sev-guest:/dev/sev-guest \
  -v /etc/toprf/certs:/etc/toprf/certs:ro \
  -p 3001:3001 \
  <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com/<ecr-repo-prefix>/toprf-node:latest \
  --port 3001 \
  --tls-cert /etc/toprf/certs/node3.pem \
  --tls-key /etc/toprf/certs/node3.key \
  --client-ca /etc/toprf/certs/ca.pem
```

### Backwards compatibility

The node auto-detects the sealed blob format:
- **v2 blobs** (from `--init-seal`): Uses `MSG_KEY_REQ` — chip-specific, strongest security
- **v1 blobs** (from `toprf-seal` CLI): Uses HKDF from measurement — not chip-specific, but works across hardware

---

## Step 7: Configure the proxy

Edit `deploy/proxy-config.json` using values from `ceremony/public-config.json`:

```json
{
  "group_public_key": "<group_public_key from public-config.json>",
  "threshold": 2,
  "require_attestation": false,
  "rate_limit": { "per_hour": 1000, "per_day": 10000 },
  "node_ca_cert": "/etc/toprf/certs/ca.pem",
  "proxy_client_cert": "/etc/toprf/certs/proxy-client.pem",
  "proxy_client_key": "/etc/toprf/certs/proxy-client.key",
  "nodes": [
    {
      "node_id": 1,
      "endpoint": "https://<gcp-node-ip-or-dns>:3001",
      "verification_share": "<node 1 verification_share from public-config.json>"
    },
    {
      "node_id": 2,
      "endpoint": "https://<azure-node-ip-or-dns>:3001",
      "verification_share": "<node 2 verification_share>"
    },
    {
      "node_id": 3,
      "endpoint": "https://<aws-node-ip-or-dns>:3001",
      "verification_share": "<node 3 verification_share>"
    }
  ]
}
```

`require_attestation` is `false` because the Express server handles device attestation before proxying to the Rust proxy. The proxy only handles node fan-out and DLEQ proof verification.

---

## Step 8: Deploy the API + proxy

The Express API and Rust proxy run together on the same host.

### Open port 3001 on each node's firewall

Now that you know the proxy host's public IP, allow it to reach the nodes:

```bash
# GCP Node 1
gcloud compute firewall-rules create allow-toprf-proxy \
  --allow=tcp:3001 \
  --source-ranges=<proxy-ip>/32 \
  --target-tags=toprf-node

# Azure Node 2
az network nsg rule create --resource-group <azure-rg> --nsg-name toprf-node-2NSG \
  --name allow-toprf-proxy --priority 100 --access Allow \
  --protocol Tcp --destination-port-ranges 3001 --source-address-prefixes <proxy-ip>/32

# AWS Node 3
aws ec2 authorize-security-group-ingress --group-id <node3-sg-id> --protocol tcp --port 3001 --cidr <proxy-ip>/32 --region eu-west-1
```

### Copy proxy certs to the API host

```bash
sudo mkdir -p /etc/toprf/certs
# Copy ca.pem, proxy-client.pem, proxy-client.key to /etc/toprf/certs/
```

### Build and deploy

```bash
cd threshold-oprf

# Set environment variables
cp deploy/.env deploy/.env.local  # edit with real values

# Start both services
docker compose -f deploy/docker-compose.yml up -d
```

This starts:
- **Express API** on port 3002 (exposed to load balancer)
- **Rust TOPRF Proxy** on port 3000 (internal only, not exposed)

---

## Step 9: Verify

```bash
# Express health
curl https://<your-domain>/health

# OPRF challenge (nonce issuance)
curl https://<your-domain>/oprf/challenge

# Rust proxy health (from the API host only, not externally)
curl http://localhost:3000/health

# Individual node health (from the API host, via mTLS)
curl --cacert /etc/toprf/certs/ca.pem \
     --cert /etc/toprf/certs/proxy-client.pem \
     --key /etc/toprf/certs/proxy-client.key \
     https://<node-ip>:3001/health
```

---

## Post-deployment checklist

- [ ] All 3 nodes report `"status": "ready"` on `/health`
- [ ] Rust proxy `/health` shows all nodes reachable
- [ ] `POST /oprf/evaluate` returns `{ partials: [...], threshold: 2 }`
- [ ] Mobile app can complete full OPRF flow (hash, blind, evaluate, combine, unblind, derive ruonId)
- [ ] Delete plaintext key share files from the ceremony machine
- [ ] Store admin recovery shares in separate secure locations (different physical locations)
- [ ] Set up monitoring for all 3 nodes
- [ ] Verify mTLS: nodes reject connections without the proxy client cert
- [ ] Verify sealed blob storage is private (no public access, VM identity only)
- [ ] Set `AMD_ARK_FINGERPRINT` env var on the proxy for AMD root cert pinning

---

## Firmware update / resealing procedure

With MSG_KEY_REQ sealing (v2), the sealed blob is bound to the specific physical CPU chip AND the measurement. Resealing is needed when:
- The cloud provider pushes a firmware update (measurement changes)
- You change instance size / vCPU count (measurement changes)
- The VM moves to a different physical host (different chip key)

**Procedure:**

1. **Boot the updated VM** with the new firmware/instance size.

2. **Re-run init-seal** — the node will generate a new sealed blob bound to the new chip + measurement:
   ```bash
   docker run --rm -it \
     -e SNP_PROVIDER=raw \
     -e EXPECTED_VERIFICATION_SHARE=<node-N-verification-share> \
     --device /dev/sev-guest:/dev/sev-guest \
     -p 3001:3001 \
     <aws-account-id>.dkr.ecr.eu-west-2.amazonaws.com/<ecr-repo-prefix>/toprf-node:latest \
     --init-seal \
     --upload-url "<same storage URL as initial deployment>" \
     --port 3001
   ```
   Then send the key share to `/init-key` as in the initial deployment. The new blob overwrites the old one at the same URL.

3. **Restart in normal mode** — `SEALED_KEY_URL` stays the same since the blob path hasn't changed.

**If you no longer have the plaintext key shares** (deleted after initial sealing), use the admin recovery shares to reconstruct and re-split:

```bash
./target/release/toprf-keygen recover \
  --shares admin-share-1.json admin-share-2.json admin-share-3.json \
  --output-dir ./recovered
```

---

## Key rotation (reshare)

If you need to rotate the threshold secret (adding/removing nodes, suspected compromise):

1. Use `toprf-keygen reshare` to generate new shares from existing ones (any 2-of-3 nodes can participate)
2. Seal new shares with current TEE measurements
3. Upload new sealed blobs to cross-provider storage
4. Restart nodes — they auto-unseal with new shares
5. Update `proxy-config.json` with new verification shares and group public key
6. Restart the Rust proxy

The reshare protocol never reconstructs the full secret — old and new nodes collaborate to produce new shares without any party learning the combined key.
