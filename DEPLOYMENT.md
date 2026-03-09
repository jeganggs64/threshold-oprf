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

## Step 3: Build and deploy the node binary

```bash
cargo build --release -p toprf-node
# Or build a Docker image:
docker build -f deploy/sev/Dockerfile.sev -t toprf-node:latest .
```

Deploy the `toprf-node` binary to each VM.

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
# Create bucket
gcloud storage buckets create gs://ruonid-sealed-node1 --location=asia-southeast1

# Grant the VM's service account access
gcloud storage buckets add-iam-policy-binding gs://ruonid-sealed-node1 \
  --member="serviceAccount:$(gcloud compute instances describe toprf-node-1 \
    --zone=asia-southeast1-b --format='get(serviceAccounts[0].email)')" \
  --role="roles/storage.objectAdmin"
```

#### Azure Blob Storage (Node 2)

```bash
# Create storage account + container
az storage account create \
  --name ruonidsealednode2 \
  --resource-group ruonid-rg \
  --location eastus \
  --sku Standard_LRS

az storage container create \
  --name sealed-blobs \
  --account-name ruonidsealednode2 \
  --public-access off

# Assign the VM's managed identity read/write access
VM_IDENTITY=$(az vm show --resource-group ruonid-rg --name toprf-node-2 \
  --query identity.principalId -o tsv)

az role assignment create \
  --assignee "$VM_IDENTITY" \
  --role "Storage Blob Data Contributor" \
  --scope "/subscriptions/<sub-id>/resourceGroups/ruonid-rg/providers/Microsoft.Storage/storageAccounts/ruonidsealednode2"
```

**Note:** Enable a system-assigned managed identity on the VM if not already enabled:
```bash
az vm identity assign --resource-group ruonid-rg --name toprf-node-2
```

#### AWS S3 (Node 3)

```bash
# Create bucket
aws s3 mb s3://ruonid-sealed-node3 --region eu-west-1

# Create an IAM policy for the bucket
aws iam create-policy --policy-name toprf-node3-sealed-blob --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::ruonid-sealed-node3/node-3-sealed.bin"
  }]
}'

# Attach to the instance's IAM role
aws iam attach-role-policy \
  --role-name toprf-node3-role \
  --policy-arn arn:aws:iam::<account-id>:policy/toprf-node3-sealed-blob
```

**Note:** Create an IAM role and attach it to the EC2 instance as an instance profile if not already done.

### Run init-seal on each node

SSH into each TEE VM and run:

#### Node 1 (GCP Singapore)

```bash
SNP_PROVIDER=gcp \
EXPECTED_VERIFICATION_SHARE=<node-1-verification-share> \
toprf-node \
  --init-seal \
  --upload-url "gs://ruonid-sealed-node1/node-1-sealed.bin" \
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

Repeat for nodes 2 and 3 with their respective share files and upload URLs.

#### Node 2 (Azure US East)

```bash
SNP_PROVIDER=raw \
EXPECTED_VERIFICATION_SHARE=<node-2-verification-share> \
toprf-node \
  --init-seal \
  --upload-url "https://ruonidsealednode2.blob.core.windows.net/sealed-blobs/node-2-sealed.bin" \
  --port 3001
```

The node uses the VM's managed identity to authenticate the upload — no credentials needed.

#### Node 3 (AWS EU Ireland)

```bash
SNP_PROVIDER=raw \
EXPECTED_VERIFICATION_SHARE=<node-3-verification-share> \
toprf-node \
  --init-seal \
  --upload-url "s3://ruonid-sealed-node3/node-3-sealed.bin" \
  --port 3001
```

The node uses the instance profile's IAM role to authenticate — no credentials needed.

### Security properties of init-seal

- **Attested TLS** — the TLS public key hash is embedded in the AMD-signed attestation report. The operator verifies this before sending the key share, ensuring they're talking to the genuine TEE (not an impersonator).
- **MSG_KEY_REQ** — the sealing key is derived by the AMD Secure Processor from the chip's unique root key (VCEK). It never exists outside the CPU. A different chip produces a completely different key.
- **Field selector** — explicitly set to `MEASUREMENT | TCB_VERSION` only. No per-boot-random fields are included.
- **MSG_KEY_REQ sealing** — even though the blob is stored on the same provider as the VM, the blob is AES-256-GCM encrypted with a key derived from the specific physical AMD chip. The provider cannot decrypt it — this is the core SEV-SNP guarantee.
- **One-time endpoint** — `/init-key` accepts exactly one call, then the node exits. There is no persistent key injection endpoint.

---

## Step 5: Start nodes in normal mode

After init-seal completes, restart each node in normal mode. The node fetches its sealed blob, calls MSG_KEY_REQ to derive the same chip-specific key, and unseals.

Each node uses its native cloud identity to fetch the sealed blob — no expiring URLs or credentials to manage.

### Node 1 (GCP Singapore)

```bash
SEALED_KEY_URL="gs://ruonid-sealed-node1/node-1-sealed.bin" \
EXPECTED_VERIFICATION_SHARE=<node-1-verification-share> \
SNP_PROVIDER=gcp \
toprf-node \
  --port 3001 \
  --tls-cert /etc/toprf/certs/node1.pem \
  --tls-key /etc/toprf/certs/node1.key \
  --client-ca /etc/toprf/certs/ca.pem
```

On boot, the node:
1. Fetches the sealed blob from the cross-provider URL
2. Calls `MSG_KEY_REQ(MEASUREMENT | TCB_VERSION)` — same chip + same software → same key K
3. Decrypts the key share with K
4. Verifies `k_i * G == expected_verification_share`
5. Starts serving `/health`, `/info`, `/partial-evaluate`

### Node 2 (Azure US East)

```bash
SEALED_KEY_URL="https://ruonidsealednode2.blob.core.windows.net/sealed-blobs/node-2-sealed.bin" \
EXPECTED_VERIFICATION_SHARE=<node-2-verification-share> \
SNP_PROVIDER=raw \
toprf-node \
  --port 3001 \
  --tls-cert /etc/toprf/certs/node2.pem \
  --tls-key /etc/toprf/certs/node2.key \
  --client-ca /etc/toprf/certs/ca.pem
```

The node uses the VM's managed identity to authenticate the download.

### Node 3 (AWS EU Ireland)

```bash
SEALED_KEY_URL="s3://ruonid-sealed-node3/node-3-sealed.bin" \
EXPECTED_VERIFICATION_SHARE=<node-3-verification-share> \
SNP_PROVIDER=raw \
toprf-node \
  --port 3001 \
  --tls-cert /etc/toprf/certs/node3.pem \
  --tls-key /etc/toprf/certs/node3.key \
  --client-ca /etc/toprf/certs/ca.pem
```

The node uses the instance profile's IAM role to authenticate the download.

### Backwards compatibility

The node auto-detects the sealed blob format:
- **v2 blobs** (from `--init-seal`): Uses `MSG_KEY_REQ` — chip-specific, strongest security
- **v1 blobs** (from `toprf-seal` CLI): Uses HKDF from measurement — not chip-specific, but works across hardware

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

## Step 7: Configure the proxy

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

## Step 8: Deploy the API + proxy

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

## Step 9: Verify

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
   SNP_PROVIDER=raw \
   EXPECTED_VERIFICATION_SHARE=<node-N-verification-share> \
   toprf-node \
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
