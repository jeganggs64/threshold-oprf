# Threshold OPRF Deployment Guide

Production deployment of the threshold OPRF system: Express API server (AWS) + Rust threshold proxy + 3 TEE nodes across GCP, OVHCloud, and Hetzner.

## Architecture

```
Mobile App
    |  HTTPS (api.ruonlabs.com)
    v
  AWS ALB
    |
    v
  Express API (port 3002)        <-- attestation, rate limiting, billing
    |  HTTP (internal)
    v
  Rust TOPRF Proxy (port 3000)   <-- fans out to TEE nodes, DLEQ verification
    |  mTLS
    +--- Node 1 (GCP Confidential VM,  SEV-SNP)
    +--- Node 2 (OVHCloud bare metal,  SEV-SNP)
    +--- Node 3 (Hetzner bare metal,   SEV-SNP)
```

Express and the Rust proxy run together on the same AWS host. Only Express is exposed externally. The Rust proxy communicates with TEE nodes over mTLS.

Nodes are spread across three providers in different jurisdictions to minimize the impact of a single provider compromise or legal order — each provider only has 1-of-3 shares (below the threshold of 2).

---

## Step 1: Generate keys

Run on an air-gapped machine if possible. This generates the threshold key shares and admin recovery shares.

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

| Node | Provider | Server type | TEE | Attestation |
|------|----------|-------------|-----|-------------|
| 1 | GCP | N2D Confidential VM (AMD EPYC) | AMD SEV-SNP | GCP metadata API |
| 2 | OVHCloud | Bare metal Scale (AMD EPYC 9005) | AMD SEV-SNP | `/dev/sev-guest` |
| 3 | Hetzner | AX162 dedicated (AMD EPYC 9454P) | AMD SEV-SNP | `/dev/sev-guest` |

### GCP (Node 1) — Managed Confidential VM

GCP handles the hypervisor and SEV-SNP setup. Create a Confidential VM:

```bash
gcloud compute instances create toprf-node-1 \
  --zone=europe-west1-b \
  --machine-type=n2d-standard-2 \
  --confidential-compute-type=SEV_SNP \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud
```

Attestation reports are available via the GCP metadata service or `/dev/sev-guest`. The `toprf-node` binary supports both (`SNP_PROVIDER=gcp` uses the metadata API, `SNP_PROVIDER=raw` uses `/dev/sev-guest` directly).

### OVHCloud (Node 2) — Bare metal

OVHCloud provides bare metal servers with AMD EPYC processors. You must configure SEV-SNP yourself:

1. Order a Scale series server with AMD EPYC 9005 (or 9004) processor
2. Access BIOS via IPMI/KVM console and enable:
   - SMEE (Secure Memory Encryption)
   - SEV Control
   - SEV-ES ASID Space Limit > 1
   - SNP / RMP Table
3. Set up a host OS with KVM and QEMU (with SEV-SNP support — upstream Linux kernel 6.x+)
4. Launch a confidential guest VM with SNP enabled
5. Inside the guest, `/dev/sev-guest` becomes available via the `sev-guest` kernel module

### Hetzner (Node 3) — Bare metal

Same setup as OVHCloud — Hetzner provides dedicated root servers with AMD EPYC:

1. Order an AX162 (EPYC 9454P, 48 cores) or similar AMD EPYC server
2. Access BIOS via KVM console (Hetzner provides 3 free hours, then ~EUR 8.40/3h) and enable SEV-SNP settings
3. Set up host KVM + QEMU with SEV-SNP
4. Launch a confidential guest VM
5. `/dev/sev-guest` available inside the guest

For a detailed walkthrough of bare-metal SEV-SNP setup, see: https://blog.lyc8503.net/en/post/amd-sev-snp/

---

## Step 3: Build node images and get measurements

```bash
docker build -f deploy/sev/Dockerfile.sev -t toprf-node:latest .
```

### Getting the measurement (launch digest)

The measurement is the SHA-384 hash of the guest's initial memory state (OVMF firmware + kernel + initrd), computed by the AMD Secure Processor during VM launch.

**Option A: Pre-compute with `sev-snp-measure` (recommended)**

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

This gives you the measurement deterministically from the build artifacts.

**Option B: Boot once and read from attestation report**

Boot the guest VM, then read the measurement from inside:

```bash
# Install snpguest (Rust CLI for /dev/sev-guest)
cargo install snpguest

# Get attestation report
snpguest report --request /dev/sev-guest

# The MEASUREMENT field (48 bytes) is the launch digest
```

On GCP, you can also read it from the metadata API.

Use the same measurement for all nodes running the same guest image. If the images differ per provider (different kernels/firmware), each node will have a different measurement.

---

## Step 4: Seal key shares

Seal each node's key share using its TEE measurement. The sealed blob can only be decrypted by a TEE instance with the matching measurement.

```bash
cargo build --release -p toprf-seal

# Seal each node's share with its measurement
./target/release/toprf-seal seal \
  --input ceremony/node-shares/node-1-share.json \
  --measurement <node-1-measurement> \
  --policy <policy-value> \
  --output node-1-sealed.bin

./target/release/toprf-seal seal \
  --input ceremony/node-shares/node-2-share.json \
  --measurement <node-2-measurement> \
  --policy <policy-value> \
  --output node-2-sealed.bin

./target/release/toprf-seal seal \
  --input ceremony/node-shares/node-3-share.json \
  --measurement <node-3-measurement> \
  --policy <policy-value> \
  --output node-3-sealed.bin
```

---

## Step 5: Upload sealed blobs to object storage

Each sealed blob must be accessible by its corresponding TEE node at boot time via HTTPS. Upload each blob to the S3-compatible object storage of the provider where that node runs.

### GCP (Node 1) — Google Cloud Storage

```bash
# Create bucket (one-time)
gcloud storage buckets create gs://ruonid-sealed-keys --location=europe-west1

# Upload
gcloud storage cp node-1-sealed.bin gs://ruonid-sealed-keys/node-1-sealed.bin

# Restrict access: only the node VM's service account can read
gcloud storage buckets add-iam-policy-binding gs://ruonid-sealed-keys \
  --member=serviceAccount:node1-sa@project.iam.gserviceaccount.com \
  --role=roles/storage.objectViewer

# Node URL:
# https://storage.googleapis.com/ruonid-sealed-keys/node-1-sealed.bin
```

### OVHCloud (Node 2) — S3-compatible Object Storage

OVHCloud offers S3-compatible object storage with zero egress fees. Create credentials in the OVH control panel under Public Cloud > Object Storage > S3 Users.

```bash
# Configure aws-cli with OVH S3 credentials
aws configure --profile ovh
# Set endpoint: https://s3.<region>.cloud.ovh.net (e.g., s3.gra.cloud.ovh.net)

# Create bucket
aws --profile ovh --endpoint-url https://s3.gra.cloud.ovh.net \
  s3 mb s3://ruonid-sealed-keys

# Upload
aws --profile ovh --endpoint-url https://s3.gra.cloud.ovh.net \
  s3 cp node-2-sealed.bin s3://ruonid-sealed-keys/node-2-sealed.bin

# Restrict access: set bucket policy to allow only the node's S3 user
aws --profile ovh --endpoint-url https://s3.gra.cloud.ovh.net \
  s3api put-bucket-policy --bucket ruonid-sealed-keys --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": { "AWS": ["arn:aws:iam:::user/node2-s3-user"] },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::ruonid-sealed-keys/node-2-sealed.bin"
    }]
  }'

# Node URL:
# https://s3.gra.cloud.ovh.net/ruonid-sealed-keys/node-2-sealed.bin
# (or https://ruonid-sealed-keys.s3.gra.cloud.ovh.net/node-2-sealed.bin)
```

### Hetzner (Node 3) — S3-compatible Object Storage

Hetzner offers Ceph-backed S3-compatible storage. Create credentials in the Hetzner Cloud Console under Object Storage.

```bash
# Configure aws-cli with Hetzner S3 credentials
aws configure --profile hetzner
# Set endpoint: https://fsn1.your-objectstorage.com (Falkenstein)
# or https://nbg1.your-objectstorage.com (Nuremberg)
# or https://hel1.your-objectstorage.com (Helsinki)

# Create bucket
aws --profile hetzner --endpoint-url https://fsn1.your-objectstorage.com \
  s3 mb s3://ruonid-sealed-keys

# Upload
aws --profile hetzner --endpoint-url https://fsn1.your-objectstorage.com \
  s3 cp node-3-sealed.bin s3://ruonid-sealed-keys/node-3-sealed.bin

# Set bucket policy to restrict access
aws --profile hetzner --endpoint-url https://fsn1.your-objectstorage.com \
  s3api put-bucket-policy --bucket ruonid-sealed-keys --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::ruonid-sealed-keys", "arn:aws:s3:::ruonid-sealed-keys/*"],
      "Condition": {
        "StringNotEquals": { "aws:username": "node3-s3-user" }
      }
    }]
  }'

# Node URL:
# https://fsn1.your-objectstorage.com/ruonid-sealed-keys/node-3-sealed.bin
```

### Security notes

- **Never make sealed blob buckets public.** Use per-user credentials or IAM policies so only the specific node can read its blob.
- **The sealed blob is encrypted** (AES-256-GCM bound to the TEE measurement), so even if someone obtains it, they cannot decrypt it without matching hardware. Access restrictions are defense-in-depth.
- **Delete the plaintext key share files** (`node-*-share.json`) after sealing. The admin recovery shares are the only way to reconstruct the secret if all sealed blobs are lost.
- **Pre-signed URLs** are another option for OVH/Hetzner — generate a time-limited URL for the node to fetch at boot, avoiding stored credentials on the node.

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
- `ca.pem` + `proxy-client.pem` + `proxy-client.key` → AWS (proxy)
- `ca.pem` + `node1.pem` + `node1.key` → GCP node
- `ca.pem` + `node2.pem` + `node2.key` → OVHCloud node
- `ca.pem` + `node3.pem` + `node3.key` → Hetzner node

---

## Step 7: Deploy TEE nodes

On each TEE VM, run the node binary with auto-unseal. The node fetches its sealed blob, gets a hardware attestation report, derives the sealing key, and decrypts the share — all at boot with no manual intervention.

### Node 1 (GCP)

```bash
SEALED_KEY_URL=https://storage.googleapis.com/ruonid-sealed-keys/node-1-sealed.bin \
EXPECTED_VERIFICATION_SHARE=<node-1-verification-share-from-public-config.json> \
SNP_PROVIDER=gcp \
toprf-node \
  --port 3001 \
  --tls-cert /etc/toprf/certs/node1.pem \
  --tls-key /etc/toprf/certs/node1.key \
  --client-ca /etc/toprf/certs/ca.pem
```

`SNP_PROVIDER=gcp` uses the GCP metadata API to retrieve the attestation report.

### Node 2 (OVHCloud)

```bash
SEALED_KEY_URL=https://s3.gra.cloud.ovh.net/ruonid-sealed-keys/node-2-sealed.bin \
EXPECTED_VERIFICATION_SHARE=<node-2-verification-share> \
SNP_PROVIDER=raw \
toprf-node \
  --port 3001 \
  --tls-cert /etc/toprf/certs/node2.pem \
  --tls-key /etc/toprf/certs/node2.key \
  --client-ca /etc/toprf/certs/ca.pem
```

`SNP_PROVIDER=raw` reads the attestation report directly from `/dev/sev-guest` via the kernel's `sev-guest` module. The guest VM must have SEV-SNP enabled and the module loaded.

### Node 3 (Hetzner)

```bash
SEALED_KEY_URL=https://fsn1.your-objectstorage.com/ruonid-sealed-keys/node-3-sealed.bin \
EXPECTED_VERIFICATION_SHARE=<node-3-verification-share> \
SNP_PROVIDER=raw \
toprf-node \
  --port 3001 \
  --tls-cert /etc/toprf/certs/node3.pem \
  --tls-key /etc/toprf/certs/node3.key \
  --client-ca /etc/toprf/certs/ca.pem
```

Same as OVHCloud — `SNP_PROVIDER=raw` talks to `/dev/sev-guest` directly.

---

## Step 8: Configure the proxy

Copy `certs/` to `ruonid/deploy/certs/` on the AWS host.

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
      "endpoint": "https://<ovhcloud-node-ip-or-dns>:3001",
      "verification_share": "<node 2 verification_share>"
    },
    {
      "node_id": 3,
      "endpoint": "https://<hetzner-node-ip-or-dns>:3001",
      "verification_share": "<node 3 verification_share>"
    }
  ]
}
```

`require_attestation` is `false` because the Express server handles device attestation before proxying to the Rust proxy. The proxy only handles node fan-out and DLEQ proof verification.

---

## Step 9: Deploy on AWS

Build the Rust proxy image (from the threshold-oprf repo):

```bash
cd threshold-oprf
docker build -f deploy/Dockerfile.proxy -t toprf-proxy:latest .
```

Deploy both services:

```bash
cd ruonid
docker compose -f deploy/docker-compose.yml up -d
```

This starts:
- **Express API** on port 3002 (exposed to ALB)
- **Rust TOPRF Proxy** on port 3000 (internal only, not exposed)

Your existing ALB routes `api.ruonlabs.com` to port 3002 — no DNS or ALB changes needed.

---

## Step 10: Verify

```bash
# Express health
curl https://api.ruonlabs.com/health

# OPRF challenge (nonce issuance)
curl https://api.ruonlabs.com/oprf/challenge

# Rust proxy health (from the AWS host only, not externally)
curl http://localhost:3000/health

# Individual node health (from the AWS host, via mTLS)
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
- [ ] Store admin recovery shares in separate secure locations
- [ ] Set up monitoring webhook for GCP node (`toprf-monitor --webhook-url ...`)
- [ ] Verify mTLS: nodes reject connections without the proxy client cert
- [ ] Verify sealed blob buckets are not publicly accessible
- [ ] Verify OVH/Hetzner node BIOS has SEV-SNP enabled and `/dev/sev-guest` is accessible in guest

---

## Bare metal SEV-SNP setup notes (OVHCloud + Hetzner)

Unlike GCP which provides managed confidential VMs, OVHCloud and Hetzner give you bare metal. You are responsible for:

1. **BIOS configuration** — Enable SMEE, SEV Control, SEV-ES ASID Space Limit > 1, SNP, and RMP Table via IPMI/KVM console.

2. **Host hypervisor** — Install a Linux host (kernel 6.x+ with SEV-SNP support) with KVM and QEMU. The upstream kernel and QEMU both support SEV-SNP.

3. **Guest VM launch** — Launch the node's guest VM with SNP enabled. QEMU flags include `-object sev-snp-guest,...` and the appropriate OVMF firmware.

4. **Guest kernel module** — The guest kernel needs the `sev-guest` module loaded (`modprobe sev-guest`) to expose `/dev/sev-guest`.

5. **Attestation verification** — The node verifies its own attestation report against AMD's Key Distribution Service (KDS) certificate chain: ARK (self-signed) → ASK → VCEK → report signature.

For a detailed walkthrough: https://blog.lyc8503.net/en/post/amd-sev-snp/

Useful tools:
- [`sev-snp-measure`](https://github.com/virtee/sev-snp-measure) — Pre-compute expected launch digest from VM artifacts
- [`snpguest`](https://github.com/virtee/snpguest) — Rust CLI for interacting with `/dev/sev-guest`

---

## Key rotation (reshare)

If you need to rotate the threshold secret (adding/removing nodes, suspected compromise):

1. Use `toprf-keygen reshare` to generate new shares from existing ones (any 2-of-3 nodes can participate)
2. Seal new shares with current TEE measurements
3. Upload new sealed blobs to object storage
4. Restart nodes — they auto-unseal with new shares
5. Update `proxy-config.json` with new verification shares and group public key
6. Restart the Rust proxy

The reshare protocol never reconstructs the full secret — old and new nodes collaborate to produce new shares without any party learning the combined key.
