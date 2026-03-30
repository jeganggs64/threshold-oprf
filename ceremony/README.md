# Key Ceremony

Generates a new OPRF master key, splits it into 2-of-3 node shares, deploys sealed shares to AMD SEV-SNP TEE nodes, verifies with a live OPRF evaluation + mobile app, and encrypts the master key with `age`.

**This key is permanent.** Once deployed with real users, it cannot be changed without forcing all users to re-onboard. Node shares can be rotated (reshare) without changing the master key.

## Overview

The ceremony runs **headlessly** on a Raspberry Pi Zero 2W via `cloud-init`. The Pi boots from a flashed SD card, connects to a WiFi hotspot, runs the full ceremony script, and outputs an age-encrypted master key. No keyboard, monitor, or manual interaction is needed during execution.

### Why a Raspberry Pi?

- Air-gapped key generation (offline steps 1-3)
- No persistent storage after SD card wipe
- Single-purpose device with no other software
- Physical possession required

### Architecture

```
Pi (offline)         Pi (online via WiFi)           AWS
─────────────        ──────────────────────         ────────────────
1. keygen init    →  4. WiFi → hotspot           →  EC2 Instance Connect
2. node-shares       5. init-seal on each node   →  S3 (attestation + encrypted shares)
3. cross-verify      6. verify health + e2e      →  NLB → nodes
                     7. shred node shares
Pi (offline)
────────────────
8. disconnect
9. OPRF simulation + mobile verify
10. age encrypt → key.age
```

## Prerequisites

### Binaries

Build ceremony binaries for aarch64 (Pi's architecture). Use the GitHub Actions workflow or build locally:

```bash
# Via GitHub Actions (recommended — native aarch64 runner)
# Trigger: .github/workflows/build-ceremony.yml
# Downloads: toprf-keygen + toprf-init-encrypt from artifacts

# Or cross-compile (requires Docker + QEMU):
cross build --release --target aarch64-unknown-linux-gnu -p toprf-keygen
cross build --release --target aarch64-unknown-linux-gnu -p toprf-seal --bin toprf-init-encrypt
```

### AWS

1. Create a temporary IAM user (e.g., `raspberry-pi`) with permissions for:
   - S3: read/write to `toprf-sealed-*` buckets
   - EC2 Instance Connect: `ec2-instance-connect:SendSSHPublicKey`
   - EC2: `ec2:DescribeInstances`
   - STS: `sts:GetCallerIdentity`
2. Disable CloudWatch alarms before the ceremony (prevents auto-rotation during deployment):
   ```bash
   aws cloudwatch disable-alarm-actions --alarm-names \
     toprf-node-1-unhealthy toprf-node-2-unhealthy toprf-node-3-unhealthy \
     --region eu-west-1
   ```

### Node access

Nodes are provisioned without SSH keys (rotation Lambda uses user-data only). The ceremony uses **EC2 Instance Connect** to push a temporary SSH key (valid 60 seconds) before each SSH/SCP call. The `nodes.json` file must include `instance_id` and `az` fields for each node.

## Prepare the SD card

1. Flash a fresh Raspberry Pi OS (Debian Trixie / Bookworm) image to the SD card.

2. Mount the boot partition and write `firstboot.sh` with all ceremony files embedded. The script is written to the FAT32 boot partition and triggered via cloud-init `runcmd`.

### Files on the boot partition

```
/Volumes/bootfs/
├── firstboot.sh           # all-in-one ceremony script (cloud-init entry point)
├── ceremony.env           # AWS creds + identity info
├── config.env             # EXPECTED_MEASUREMENT, NODE_IMAGE, etc.
├── nodes.json             # node IPs, instance IDs, AZs, S3 buckets
├── toprf-keygen           # aarch64 binary
├── toprf-init-encrypt     # aarch64 binary
├── wordlist.txt           # diceware wordlist (7776 words)
└── coordinator-configs/
    ├── coordinator-node-1.json
    ├── coordinator-node-2.json
    └── coordinator-node-3.json
```

### Key design decisions for headless operation

**WiFi via wpa_supplicant** — cloud-init `network-config` uses netplan, but Debian Trixie uses NetworkManager. The script connects WiFi directly via `wpa_supplicant`:
```bash
wpa_passphrase "HOTSPOT_NAME" "PASSWORD" > /tmp/wpa.conf
wpa_supplicant -B -i wlan0 -c /tmp/wpa.conf
dhclient wlan0
```

**SSH keys embedded as heredocs** — FAT32 corrupts files on unclean shutdown. Node SSH keys are embedded directly in the script as heredocs rather than stored as separate `.pem` files.

**EC2 Instance Connect** — Every SSH/SCP call is preceded by `aws ec2-instance-connect send-ssh-public-key` to push a temporary key. This is needed because rotation Lambda provisions instances without permanent SSH keys.

**age keypair encryption (not passphrase)** — `age -p` requires `/dev/tty` for passphrase input, which isn't available in cloud-init. Instead, the script generates an ephemeral age keypair, encrypts with `age -r <pubkey>`, displays the private key in the log for a 120-second window, then destroys it.

**AWS CLI via apt** — The Pi installs `awscli` via apt-get (not pip/snap) with a clock fix (`date -s` from HTTP headers) since the Pi has no RTC battery.

## ceremony.env

```bash
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=eu-west-1
NATIONALITY=<your nationality>
NATIONAL_ID=<your national ID number>
WIFI_SSID=<hotspot name>
WIFI_PASS=<hotspot password>
```

## Steps

| Step | What happens | Network |
|------|-------------|---------|
| 1 | Generate master key + 2-of-4 admin shares | Offline |
| 2 | Generate 2-of-3 node shares from admin shares | Offline |
| 3 | Cross-verify: both share sets reconstruct the same key | Offline |
| 4 | Connect WiFi to phone hotspot | Online |
| 5 | Deploy key shares to TEE nodes (init-seal via S3 + ECIES) | Online |
| 6 | Verify all nodes healthy + correct group public key + e2e /evaluate | Online |
| 7 | Shred node shares from disk | Online |
| 8 | Reconstruct master key from admin shares, re-split into fresh admin shares | Online |
| 9 | OPRF simulation with national ID + 240s window for mobile app verification | Online |
| 10 | Encrypt master key with age keypair, display private key for 120s, shred all plaintext | Online |

### Step 5 detail: init-seal

For each node:
1. Start `toprf-init-seal` container (with `--device /dev/sev-guest`)
2. Container generates an ephemeral keypair, produces an SNP attestation report, uploads `attestation.bin`, `pubkey.bin`, `certs.bin` to S3
3. Pi downloads attestation artifacts, runs `toprf-init-encrypt` to verify the attestation measurement and encrypt the key share with ECIES
4. Pi uploads `encrypted-share.bin` to S3
5. Container picks up the encrypted share, decrypts with its private key, seals to hardware via `MSG_KEY_REQ`, uploads `node-N-sealed.bin`
6. Pi uploads coordinator config, starts the node in normal mode

## After the ceremony

### 1. Copy the encrypted key

After the Pi finishes, the `key.age` file is on the SD card (or displayed in cloud-init logs depending on the approach). Copy it to a secure location (e.g., iCloud Drive, hardware-encrypted USB).

### 2. Wipe the SD card

```bash
# On your Mac after removing the SD card:
sudo dd if=/dev/zero of=/dev/diskN bs=4M status=progress
```

### 3. Delete the ceremony IAM user

```bash
aws iam delete-access-key --user-name raspberry-pi --access-key-id AKIA...
aws iam detach-user-policy --user-name raspberry-pi --policy-arn arn:aws:iam::aws:policy/...
aws iam delete-user --user-name raspberry-pi
```

### 4. Update SSM Parameter Store

The ceremony does NOT automatically update SSM. You must sync the new keys manually. This is required for the rotation Lambda to function correctly.

**Main config** (`/toprf/config`, SecureString):

Update the `group_public_key` and each node's `verification_share` to match the ceremony output:

```bash
# Get the group public key from any node's attestation metadata:
aws s3 cp s3://toprf-sealed-<account>-node-1/attestation/metadata.json - | jq -r '.group_public_key'

# Get each node's verification share:
aws s3 cp s3://toprf-sealed-<account>-node-N/attestation/metadata.json - | jq -r '.verification_share'
```

Push the updated config:
```bash
aws ssm put-parameter --name "/toprf/config" --type SecureString --overwrite --value '<json>'
```

The config JSON must include for each node: `id`, `region`, `ip`, `private_ip`, `instance_id`, `sg_id`, `vpc_id`, `subnet_id`, `s3_bucket`, `ami_id`, `tg_arn`, `nlb_endpoint`, `verification_share`, `key_name`.

Top-level fields: `threshold`, `group_public_key`, `node_image`, `instance_type`, `frontend_tg_arn`, `coordinator_vpc_id`.

**Coordinator configs** (`/toprf/coordinator-config/{node_id}`, String):

Each node's coordinator config lists its peers with their NLB endpoints and verification shares. Update all 3:

```bash
aws ssm put-parameter --name "/toprf/coordinator-config/1" --type String --overwrite --value '{
  "peers": [
    {"node_id": 2, "endpoint": "http://toprf-node-2-nlb-....elb...amazonaws.com:3001", "verification_share": "<node2_vs>"},
    {"node_id": 3, "endpoint": "http://toprf-node-3-nlb-....elb...amazonaws.com:3001", "verification_share": "<node3_vs>"}
  ]
}'
# Repeat for nodes 2 and 3
```

Or use `deploy.sh sync-state` if you have local files up to date:
```bash
NODE_SHARES_DIR=../ceremony/node-shares ./deploy.sh sync-state
```

**Important:** If you skip this step, the rotation Lambda will fail with `group_public_key does not match this node's key` because it reads the reshare group key from SSM.

### 5. Update local files

Update `deploy/nodes.json` and `deploy/coordinator-configs/coordinator-node-*.json` with the new verification shares so that `deploy.sh` commands work correctly.

### 6. Re-enable CloudWatch alarms

```bash
aws cloudwatch enable-alarm-actions --alarm-names \
  toprf-node-1-unhealthy toprf-node-2-unhealthy toprf-node-3-unhealthy \
  --region eu-west-1
```

### 7. Fix any unhealthy nodes

If a node was unhealthy during the ceremony or its rotation was triggered, you may need to manually fix it or invoke a rotation after SSM is updated:

```bash
aws lambda invoke --function-name toprf-rotation --payload '{"node_id": N}' --invocation-type Event --cli-binary-format raw-in-base64-out out.json
```

Use `--invocation-type Event` (async) to avoid the CLI retrying on timeout, which would trigger a duplicate invocation. The rotation lock prevents double execution, but async invoke avoids the noisy "skipping" notification.

The rotation Lambda will reshare the key from the 2 healthy donor nodes — the new node gets a mathematically equivalent share sealed to its own hardware.

## Decrypting the master key

If using passphrase-based age encryption:
```bash
age -d key.age > admin-shares.json
```

If using keypair-based age encryption (headless ceremony):
```bash
age -d -i private-key.txt key.age > admin-shares.json
```

The private key was displayed during step 10 of the ceremony. If you did not copy it, the master key is unrecoverable — but the OPRF system continues to function via the sealed node shares and reshare protocol.

## Troubleshooting

**Node SSH fails after rotation:** Rotation provisions instances without SSH keys. Use EC2 Instance Connect:
```bash
aws ec2-instance-connect send-ssh-public-key \
  --instance-id <id> --instance-os-user ec2-user \
  --ssh-public-key file://key.pub --availability-zone <az> --region eu-west-1
ssh -i key.pem ec2-user@<ip> ...
```

**Rotation Lambda fails with "group_public_key does not match":** SSM config has the old group key. Update `/toprf/config` with the new `group_public_key` from the ceremony.

**Node crashes with "key verification FAILED":** The `EXPECTED_VERIFICATION_SHARE` env var doesn't match the sealed blob. After a reshare, the verification share changes. Check `attestation/metadata.json` in the node's S3 bucket for the correct share.

**DynamoDB rotation lock stuck:** The Lambda uses a DynamoDB lock (`toprf-rotation-lock` table) with 15-minute TTL. DynamoDB TTL doesn't delete instantly. Force-clear:
```bash
aws dynamodb delete-item --table-name toprf-rotation-lock --key '{"lockId": {"S": "rotation-node-N"}}'
```
