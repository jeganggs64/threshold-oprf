# Threshold OPRF Deployment Guide

Production deployment of the threshold OPRF system: Express API server + Rust threshold proxy + 3 TEE nodes across GCP, Azure, and AWS.

## Architecture

```
Mobile App
    |  HTTPS (api.ruonlabs.com)
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

### Cross-provider sealed blob storage

To prevent a single cloud provider from having both the VM and the sealed blob (which together could allow unsealing), store each node's sealed blob on a **different** provider:

| Node | VM runs on | Sealed blob stored on |
|------|-----------|----------------------|
| Node 1 | GCP Singapore | Azure Blob Storage |
| Node 2 | Azure US | AWS S3 |
| Node 3 | AWS EU | GCP Cloud Storage |

This way, compromising a single provider only gives access to either the VM or the blob, never both.

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
gcloud compute instances create toprf-node-1 \
  --zone=asia-southeast1-b \
  --machine-type=n2d-standard-2 \
  --confidential-compute-type=SEV_SNP \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud
```

Attestation: GCP metadata API (`SNP_PROVIDER=gcp`) or `/dev/sev-guest` (`SNP_PROVIDER=raw`).

### Node 2: Azure US East

```bash
az vm create \
  --resource-group ruonid-rg \
  --name toprf-node-2 \
  --location eastus \
  --size Standard_DC2as_v5 \
  --image Canonical:ubuntu-24_04-lts:cvm:latest \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --admin-username azureuser \
  --generate-ssh-keys
```

Attestation: `/dev/sev-guest` (`SNP_PROVIDER=raw`). Azure also provides Microsoft Azure Attestation (MAA) service for remote verification.

### Node 3: AWS EU Ireland

```bash
aws ec2 run-instances \
  --region eu-west-1 \
  --instance-type c6a.large \
  --image-id ami-xxxxxxxxx \
  --cpu-options AmdSevSnp=enabled \
  --key-name ruonid-node3 \
  --security-group-ids sg-xxxxxxxxx
```

Attestation: `/dev/sev-guest` (`SNP_PROVIDER=raw`). AWS signs reports with VLEK (Versioned Loaded Endorsement Key) rather than VCEK.

**Note:** AWS SEV-SNP is currently available in only 2 regions: `us-east-2` (Ohio) and `eu-west-1` (Ireland). Only M6a, C6a, and R6a instance families support it.

---

## Step 3: Build node images and get measurements

```bash
cargo build --release -p toprf-node
# Or build a Docker image:
docker build -f deploy/sev/Dockerfile.sev -t toprf-node:latest .
```

### Getting the measurement (launch digest)

The measurement is the SHA-384 hash of the guest's initial memory state (OVMF firmware + kernel + initrd + VMSAs), computed by the AMD Secure Processor during VM launch.

**Option A: Pre-compute with `sev-snp-measure` (recommended for known firmware)**

The [`sev-snp-measure`](https://github.com/virtee/sev-snp-measure) tool computes the expected launch digest from the VM inputs without booting:

```bash
pip install sev-snp-measure

sev-snp-measure --mode snp \
  --vcpus=2 \
  --vcpu-type=EPYC-v4 \
  --ovmf=OVMF.fd \
  --kernel=vmlinuz \
  --initrd=initrd.img \
  --append="console=ttyS0"
```

This requires access to the exact firmware image the cloud provider uses, which may not always be available.

**Option B: Boot once and read from attestation report (recommended for cloud VMs)**

Boot the guest VM without a key (it will start but can't serve evaluations), then capture the measurement:

```bash
# Using the built-in toprf-measure tool
toprf-measure --provider gcp --json   # GCP
toprf-measure --provider raw --json   # Azure, AWS

# Or using snpguest
cargo install snpguest
snpguest report --request /dev/sev-guest
```

The MEASUREMENT field (48 bytes / 96 hex chars) is the launch digest. Save it — you'll need it for sealing.

**Important:** The measurement is deterministic for a given software stack + vCPU count. Two VMs with the same firmware, kernel, initrd, command line, and vCPU count will produce the same measurement, regardless of which physical machine or provider they run on. However, different cloud providers use different firmware images, so each node will likely have a different measurement.

### What changes the measurement

| Change | Measurement changes? | Action required |
|--------|---------------------|-----------------|
| Application code update | No | Just redeploy the binary |
| Kernel update | Yes | Reseal key share |
| Firmware/UEFI update (provider-pushed) | Yes | Reseal key share |
| vCPU count change (instance resize) | Yes | Reseal key share |
| Disk/data changes | No | Nothing |
| Different physical host (same provider) | No | Nothing |

---

## Step 4: Seal key shares

Seal each node's key share on your air-gapped machine using its TEE measurement.

```bash
cargo build --release -p toprf-seal

# Seal each node's share with its measurement
./target/release/toprf-seal seal \
  --input ceremony/node-shares/node-1-share.json \
  --measurement <node-1-measurement-hex> \
  --policy <policy-value> \
  --output node-1-sealed.bin

./target/release/toprf-seal seal \
  --input ceremony/node-shares/node-2-share.json \
  --measurement <node-2-measurement-hex> \
  --policy <policy-value> \
  --output node-2-sealed.bin

./target/release/toprf-seal seal \
  --input ceremony/node-shares/node-3-share.json \
  --measurement <node-3-measurement-hex> \
  --policy <policy-value> \
  --output node-3-sealed.bin
```

The sealed blob is AES-256-GCM encrypted with a key derived from `HKDF(measurement || policy)`. Only a TEE with the matching measurement can derive the same key and unseal.

---

## Step 5: Upload sealed blobs (cross-provider)

Each sealed blob is stored on a **different** provider than where its node runs. This ensures no single provider has access to both the VM and the blob.

### Node 1 blob → Azure Blob Storage

Node 1 runs on GCP, so store its blob on Azure:

```bash
# Create storage account + container (one-time)
az storage account create \
  --name ruonidsealedkeys \
  --resource-group ruonid-rg \
  --location eastus \
  --sku Standard_LRS

az storage container create \
  --name sealed-blobs \
  --account-name ruonidsealedkeys \
  --public-access off

# Upload
az storage blob upload \
  --account-name ruonidsealedkeys \
  --container-name sealed-blobs \
  --name node-1-sealed.bin \
  --file node-1-sealed.bin

# Generate a SAS URL for the node to fetch at boot (valid 1 year, read-only)
az storage blob generate-sas \
  --account-name ruonidsealedkeys \
  --container-name sealed-blobs \
  --name node-1-sealed.bin \
  --permissions r \
  --expiry $(date -u -v+1y '+%Y-%m-%dT%H:%MZ') \
  --full-uri

# Node SEALED_KEY_URL will be:
# https://ruonidsealedkeys.blob.core.windows.net/sealed-blobs/node-1-sealed.bin?sv=...&sig=...
```

### Node 2 blob → AWS S3

Node 2 runs on Azure, so store its blob on AWS:

```bash
# Create bucket (one-time)
aws s3 mb s3://ruonid-sealed-keys-eu --region eu-west-1

# Upload
aws s3 cp node-2-sealed.bin s3://ruonid-sealed-keys-eu/node-2-sealed.bin

# Create IAM user with read-only access to just this object
aws iam create-user --user-name toprf-node2-reader
aws iam put-user-policy --user-name toprf-node2-reader \
  --policy-name sealed-blob-read \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::ruonid-sealed-keys-eu/node-2-sealed.bin"
    }]
  }'

# Generate access key for the node
aws iam create-access-key --user-name toprf-node2-reader

# Or generate a pre-signed URL (valid 7 days, renew periodically)
aws s3 presign s3://ruonid-sealed-keys-eu/node-2-sealed.bin --expires-in 604800

# Node SEALED_KEY_URL will be the pre-signed URL or direct S3 URL with credentials
```

### Node 3 blob → GCP Cloud Storage

Node 3 runs on AWS, so store its blob on GCP:

```bash
# Create bucket (one-time)
gcloud storage buckets create gs://ruonid-sealed-keys --location=asia-southeast1

# Upload
gcloud storage cp node-3-sealed.bin gs://ruonid-sealed-keys/node-3-sealed.bin

# Create a service account with read-only access
gcloud iam service-accounts create toprf-node3-reader
gcloud storage buckets add-iam-policy-binding gs://ruonid-sealed-keys \
  --member=serviceAccount:toprf-node3-reader@PROJECT.iam.gserviceaccount.com \
  --role=roles/storage.objectViewer

# Generate a signed URL (valid 7 days)
gcloud storage sign-url gs://ruonid-sealed-keys/node-3-sealed.bin \
  --duration=7d \
  --private-key-file=service-account-key.json

# Node SEALED_KEY_URL will be the signed URL
```

### Security notes

- **Cross-provider storage is critical.** A rogue employee at provider X can access the VM on X but not the blob on provider Y. They would need to compromise two independent providers simultaneously.
- **The sealed blob is encrypted** (AES-256-GCM bound to the TEE measurement), so even with blob access, decryption requires a VM with the matching measurement. Cross-provider storage is defense-in-depth.
- **Use time-limited signed URLs** rather than static credentials where possible. Rotate them periodically.
- **Delete plaintext key share files** (`node-*-share.json`) after sealing. The admin recovery shares are the only backup.
- **The threshold protects you even if cross-provider storage fails.** An attacker needs 2-of-3 shares. Even if they compromise one provider entirely (VM + blob on a different provider), they only get 1 share.

---

## Step 6: Generate mTLS certificates

Generate a private CA and certificates for mutual TLS between the proxy and nodes.

```bash
cd threshold-oprf
bash scripts/gen-certs.sh
```

This creates:

```
certs/
  ca/ca.pem, ca.key           # Private CA
  nodes/node{1,2,3}.pem/key   # Node server certs (TLS)
  proxy/proxy-client.pem/key   # Proxy client cert (mTLS)
```

Distribute:
- `ca.pem` + `proxy-client.pem` + `proxy-client.key` → proxy host
- `ca.pem` + `node1.pem` + `node1.key` → GCP node
- `ca.pem` + `node2.pem` + `node2.key` → Azure node
- `ca.pem` + `node3.pem` + `node3.key` → AWS node

---

## Step 7: Deploy TEE nodes

On each TEE VM, run the node binary with auto-unseal. The node fetches its sealed blob, gets a hardware attestation report, derives the sealing key, and decrypts the share — all at boot with no manual intervention.

### Node 1 (GCP Singapore)

```bash
SEALED_KEY_URL="https://ruonidsealedkeys.blob.core.windows.net/sealed-blobs/node-1-sealed.bin?sv=...&sig=..." \
EXPECTED_VERIFICATION_SHARE=<node-1-verification-share-from-public-config.json> \
SNP_PROVIDER=gcp \
toprf-node \
  --port 3001 \
  --tls-cert /etc/toprf/certs/node1.pem \
  --tls-key /etc/toprf/certs/node1.key \
  --client-ca /etc/toprf/certs/ca.pem
```

`SNP_PROVIDER=gcp` uses the GCP metadata API for attestation reports.

### Node 2 (Azure US East)

```bash
SEALED_KEY_URL="https://ruonid-sealed-keys-eu.s3.eu-west-1.amazonaws.com/node-2-sealed.bin?X-Amz-..." \
EXPECTED_VERIFICATION_SHARE=<node-2-verification-share> \
SNP_PROVIDER=raw \
toprf-node \
  --port 3001 \
  --tls-cert /etc/toprf/certs/node2.pem \
  --tls-key /etc/toprf/certs/node2.key \
  --client-ca /etc/toprf/certs/ca.pem
```

`SNP_PROVIDER=raw` reads attestation reports from `/dev/sev-guest`.

### Node 3 (AWS EU Ireland)

```bash
SEALED_KEY_URL="https://storage.googleapis.com/ruonid-sealed-keys/node-3-sealed.bin?X-Goog-..." \
EXPECTED_VERIFICATION_SHARE=<node-3-verification-share> \
SNP_PROVIDER=raw \
toprf-node \
  --port 3001 \
  --tls-cert /etc/toprf/certs/node3.pem \
  --tls-key /etc/toprf/certs/node3.key \
  --client-ca /etc/toprf/certs/ca.pem
```

---

## Step 8: Configure the proxy

Edit `ruonid/deploy/proxy-config.json` using values from `ceremony/public-config.json`:

```json
{
  "group_public_key": "<group_public_key from public-config.json>",
  "threshold": 2,
  "require_attestation": false,
  "rate_limit": { "per_hour": 1000, "per_day": 10000 },
  "node_ca_cert": "/etc/toprf/certs/ca/ca.pem",
  "proxy_client_cert": "/etc/toprf/certs/proxy/proxy-client.pem",
  "proxy_client_key": "/etc/toprf/certs/proxy/proxy-client.key",
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

## Step 9: Deploy the API + proxy

The Express API and Rust proxy run together. Build and deploy:

```bash
# Build proxy image (from threshold-oprf repo)
cd threshold-oprf
docker build -f deploy/Dockerfile.proxy -t toprf-proxy:latest .

# Deploy both services
cd ruonid
docker compose -f deploy/docker-compose.yml up -d
```

This starts:
- **Express API** on port 3002 (exposed to load balancer)
- **Rust TOPRF Proxy** on port 3000 (internal only, not exposed)

---

## Step 10: Verify

```bash
# Express health
curl https://api.ruonlabs.com/health

# OPRF challenge (nonce issuance)
curl https://api.ruonlabs.com/oprf/challenge

# Rust proxy health (from the API host only, not externally)
curl http://localhost:3000/health

# Individual node health (from the API host, via mTLS)
curl --cacert certs/ca/ca.pem \
     --cert certs/proxy/proxy-client.pem \
     --key certs/proxy/proxy-client.key \
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
- [ ] Verify sealed blob storage is private (no public access)
- [ ] Set `AMD_ARK_FINGERPRINT` env var on the proxy for AMD root cert pinning

---

## Firmware update / resealing procedure

When a cloud provider pushes a firmware update (or you change instance size), the SEV-SNP measurement changes and the node will fail to unseal on next boot.

**Procedure:**

1. **Before the update takes effect**, the running node still has the key in memory and is serving traffic normally.

2. **Get the new measurement.** Boot a test VM with the updated firmware/instance size and run `toprf-measure` to capture the new measurement.

3. **Reseal on your air-gapped machine:**
   ```bash
   ./target/release/toprf-seal seal \
     --input ceremony/node-shares/node-N-share.json \
     --measurement <new-measurement> \
     --policy <policy-value> \
     --output node-N-sealed-v2.bin
   ```

4. **Upload the new blob** to the cross-provider storage, replacing the old one.

5. **Apply the update and restart the node.** It will fetch the new blob and unseal with the new measurement.

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
