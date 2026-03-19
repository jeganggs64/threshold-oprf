# Threshold OPRF

A distributed threshold Oblivious Pseudorandom Function (OPRF) system using T-of-N Shamir secret sharing. Each share runs inside an AMD SEV-SNP Trusted Execution Environment on a separate AWS instance. Node count and threshold are configurable (2-of-3, 3-of-5, etc).

## Architecture

```
Client → API Gateway (oprf.ruonlabs.com) → Lambda → Frontend NLB → Coordinator Node
                                                                          ↓ PrivateLink
                                                                  (threshold-1) Peer Nodes
```

- **Coordinator**: receives blinded point, computes own partial evaluation, forwards to peers via PrivateLink, verifies DLEQ proofs, combines via Lagrange interpolation
- **Frontend NLB**: health-checked load balancer across same-region nodes — automatic failover
- **PrivateLink**: node-to-node traffic stays on AWS's private backbone, no public exposure
- **SEV-SNP**: key shares sealed to hardware, stored encrypted in S3 — AWS cannot read them
- **No SSM Run Command**: nodes have no remote execution interface. VM bootstrapping uses EC2 user data only. Even with full AWS account access, no code can be executed inside the SEV-SNP guest.

## Repository Structure

```
crates/
  core/       Threshold OPRF cryptography (Shamir, partial eval, DLEQ, combine, recovery)
  node/       TEE node server (coordinator + peer mode)
  keygen/     Offline ceremony tool (generate key, split into shares, verify, simulate)
  seal/       AMD SEV-SNP sealing, ECIES, attestation verification
ceremony/     Raspberry Pi key ceremony script + config template
lambda/
  handlers/   API Lambda functions (challenge, attest, evaluate)
  rotation/   Automated rotation Lambda (SAM template)
deploy/       Deployment scripts (provision.sh, deploy.sh)
scripts/      Dev utilities (integration-test.sh, gen-certs.sh)
```

## Prerequisites

**Local tools:**
- AWS CLI v2 (authenticated)
- `jq`, `openssl`, `curl`
- Rust toolchain
- Node.js
- AWS SAM CLI

**AWS resources (create before deployment):**
- HTTP API Gateway with custom domain (`oprf.ruonlabs.com`)
- ACM certificate for the domain
- Route 53 hosted zone with CNAME to API Gateway
- Lambda execution IAM role (`toprf-lambda-exec`) with DynamoDB, S3, VPC, CloudWatch permissions
- DynamoDB tables: `ruonid-nonces`, `ruonid-device-keys`
- KMS signing key (secp256k1, `alias/ruonid-signing`)

**AWS resources (created by deployment scripts):**
- EC2 instances (SEV-SNP VMs, `c6a.large`)
- Per-node IAM roles, instance profiles, ED25519 key pairs
- S3 buckets for sealed key blobs (`toprf-sealed-<account>-node-<id>`)
- NLBs (per-node + frontend)
- PrivateLink (endpoint services, VPC endpoints, security groups)
- CloudWatch alarms + SNS topics
- SSM Parameter Store entries (config, coordinator configs)

**VPC endpoints required:**
| Endpoint | Type | Purpose | Required by |
|----------|------|---------|-------------|
| `s3` | Gateway | Sealed blobs, reshare artifacts | Nodes, Lambda |
| `ssm` | Interface | Parameter Store (config reads) | Rotation Lambda |
| `ec2` | Interface | Instance operations | Rotation Lambda |
| `sts` | Interface | IAM credential resolution | Rotation Lambda |
| `elasticloadbalancing` | Interface | NLB target management | Rotation Lambda |
| `sns` | Interface | Rotation notifications | Rotation Lambda |
| `dynamodb` | Gateway | Nonces, device keys | API Lambdas |

**Important:** The `ssm` endpoint is for Parameter Store API only (key-value config reads). The `ssmmessages` and `ec2messages` endpoints are NOT needed — SSM Run Command is not used. The endpoint security group must allow **port 443** inbound from the VPC CIDR.

## Deployment

### 1. Build

```bash
cargo build --release
cargo test --release
```

### 2. Configure

```bash
cd deploy
cp config.env.example config.env    # Set manual values
cp nodes.json.example nodes.json    # Set threshold, node regions, S3 buckets
```

### 3. Provision + Deploy (test key)

```bash
# Provision nodes
./provision.sh 1
./provision.sh 2
./provision.sh 3
./deploy.sh auto-config             # Populate IPs, SGs, VPCs

# Generate test key shares
cd ..
./target/release/toprf-keygen init \
    --admin-threshold 2 --admin-shares 4 \
    --output-dir ./test-admin-shares
./target/release/toprf-keygen node-shares \
    -a ./test-admin-shares/admin-1.json \
    -a ./test-admin-shares/admin-2.json \
    --node-threshold 2 --node-shares 3 \
    --output-dir ./ceremony/node-shares

# Deploy
cd deploy
./deploy.sh pre-seal                # Docker setup, image pull, S3 buckets, measure
NODE_SHARES_DIR=../ceremony/node-shares ./deploy.sh init-seal
./deploy.sh post-seal               # PrivateLink, coordinator configs, start, verify
./deploy.sh e2e                     # End-to-end test
```

### 4. Deploy Lambdas

```bash
./deploy.sh lambda-config           # Auto-generate lambda/config.env
# Manually verify: API_ID, ROLE_ARN, APPLE_APP_ID, APPLE_TEAM_ID

cd ../lambda && ./deploy.sh         # Deploy API Lambdas + wire API Gateway routes
```

### 5. Deploy Rotation Lambda

```bash
cd rotation
sam build && sam deploy --guided
```

Parameters:
- **Stack name**: `toprf-rotation`
- **Region**: `eu-west-1`
- **SSMPrefix**: `/toprf` (default)
- **VpcSubnetIds**: from `lambda/config.env` (`VPC_SUBNETS`)
- **VpcSecurityGroupIds**: from `lambda/config.env` (`VPC_SG`)

After first deploy, `samconfig.toml` saves the config. Future deploys: `sam build && sam deploy`.

### 6. Push State to SSM

```bash
cd ../../deploy
./deploy.sh sync-state              # Push nodes.json + coordinator configs to SSM Parameter Store
./deploy.sh cloudwatch              # Create health alarms → SNS
```

### 7. Production Key Ceremony (Raspberry Pi)

See [ceremony/ceremony.sh](ceremony/ceremony.sh) for the full 13-step ceremony script. Replaces the test key with a production key, prints admin shares as QR codes, and verifies with a local OPRF simulation.

### 8. Lock Nodes (optional, irreversible)

```bash
./deploy.sh lock                    # Removes SSH, deletes key pairs
```

## Rotation

Automated monthly via Lambda. Uses staging-based share recovery — no admin ceremony needed. No SSH or SSM Run Command — all VM setup uses EC2 user data.

**How it works:**
1. Lambda launches staging instance with user data (installs Docker, pulls image, starts init-reshare)
2. Init-reshare generates attestation + ephemeral keypair → uploads to S3
3. Lambda downloads attestation, sends `/reshare` to donor nodes via NLB
4. Donors verify attestation (AMD cert chain + compiled-in measurement), compute + encrypt contributions
5. Lambda uploads contributions to S3 → staging node combines, seals
6. User data starts normal mode container
7. Lambda health-checks via direct HTTP to staging IP
8. Lambda swaps NLB targets (per-node + frontend)
9. Lambda terminates old instance, updates SSM config

If anything fails, the staging instance is terminated. Old node is unaffected. Zero downtime.

### Manual Rotation

```bash
aws lambda invoke --function-name toprf-rotation \
  --payload '{"node_id": 1}' \
  --cli-binary-format raw-in-base64-out \
  --region eu-west-1 \
  --cli-read-timeout 900 \
  /dev/stdout
```

Replace `"node_id": 1` with the node to rotate (1, 2, or 3).

### Rotation Triggers

| Trigger | How |
|---------|-----|
| Manual | `aws lambda invoke` as above |
| Unhealthy node | CloudWatch alarm → SNS → Lambda (automatic) |
| Monthly schedule | EventBridge cron → Lambda (first of month, 06:00 UTC) |

### Rotation Prerequisites

For rotation to work, these must all be in place:

1. **SSM Parameter Store** — `/toprf/config` must contain the full node config JSON (pushed by `deploy.sh sync-state`). Coordinator configs at `/toprf/coordinator-config/<node_id>`.

2. **VPC endpoints** — The rotation Lambda runs in the VPC. It needs the `ssm` interface endpoint (port 443) to read config from Parameter Store, plus `ec2`, `sts`, `elasticloadbalancing`, `sns` endpoints, and the `s3` gateway endpoint.

3. **Security group** — The VPC endpoint security group must allow **TCP 443 inbound** from the VPC CIDR (e.g., `172.31.0.0/16`) for Parameter Store/API access, and **TCP 3001** for node-to-node PrivateLink traffic.

4. **IAM** — The rotation Lambda role needs: `ssm:GetParameter`, `ssm:PutParameter`, `ec2:RunInstances`, `ec2:TerminateInstances`, `ec2:DescribeInstances`, `ec2:CreateTags`, `iam:PassRole`, `s3:*Object`, `elasticloadbalancing:*Targets`, `sns:Publish`.

5. **Per-node IAM profiles** — Each node instance profile (`toprf-node-<id>-profile`) must have S3 access to its own bucket.

6. **NLBs + target groups** — Per-node NLBs with target groups must exist. The rotation Lambda swaps targets during rotation.

7. **Donor nodes healthy** — At least `threshold` donor nodes must be healthy (responding on `/health`).

## AMI Updates

The peer measurement (SHA-384 of VM firmware) is **compiled into the Docker image** at `crates/node/src/reshare_handler.rs`. This prevents a compromised AWS account from substituting a rogue measurement — the measurement is baked into the image on ghcr.io, outside AWS.

To update the AMI:

1. Provision a test node with the new AMI
2. Run `./deploy.sh measure` to capture the new measurement
3. Update `EXPECTED_PEER_MEASUREMENT` in `crates/node/src/reshare_handler.rs`
4. Rebuild and push the Docker image to ghcr.io
5. **First 3 rotations** — rotate all nodes with the **old AMI** (picks up new image with updated measurement)
6. Update `ami_id` in SSM config (`/toprf/config`)
7. **Next 3 rotations** — rotate all nodes with the **new AMI** (donors now accept the new measurement)

Total: 6 automated rotations. The staggering is required because donors check the measurement from their compiled-in binary, so they must have the new image before any node uses the new AMI.

## Key Ceremony Tool

```bash
# Generate admin shares (2-of-4 Shamir)
toprf-keygen init --admin-threshold 2 --admin-shares 4 --output-dir ./admin-shares

# Generate node shares from admin shares
toprf-keygen node-shares \
    -a admin-shares/admin-1.json -a admin-shares/admin-2.json \
    --node-threshold 2 --node-shares 3 --output-dir ./node-shares

# Cross-verify both share sets reconstruct the same key
toprf-keygen verify \
    -a admin-shares/admin-1.json -a admin-shares/admin-2.json \
    -n node-shares/node-1-share.json -n node-shares/node-2-share.json

# Evaluate a raw blinded point
toprf-keygen evaluate \
    -a admin-shares/admin-1.json -a admin-shares/admin-2.json \
    --blinded-point <hex> --expected <hex>

# Simulate full mobile app OPRF flow (hash → blind → eval → unblind → ruonId)
toprf-keygen simulate \
    -a admin-shares/admin-1.json -a admin-shares/admin-2.json \
    --nationality "Singapore" --national-id "S1234567A"
```

## Full Key Replacement

If the OPRF secret is compromised and needs to be replaced entirely (not routine — node rotation preserves the existing key):

1. Run new key ceremony (admin shares → node shares)
2. Clear sealed blobs from S3 buckets
3. `./deploy.sh init-seal` (inject new shares)
4. `./deploy.sh start` (restart nodes)
5. `./deploy.sh e2e` (verify)
6. `./deploy.sh sync-state` (update SSM)

**Warning:** all existing `ruonId` values become invalid.

## Security

- **T-of-N threshold** — no single node holds enough shares to reconstruct the key
- **Hardware sealing** — SEV-SNP `MSG_KEY_REQ` derived keys; AWS cannot decrypt
- **No remote execution** — no SSH (after lock), no SSM Run Command, no SSM agent. The only interface is port 3001 (authenticated TOPRF API). Even a fully compromised AWS account cannot execute code inside the guest.
- **Compiled-in measurement** — peer measurement is baked into the Docker image, not stored in any AWS-writable config. Prevents measurement substitution attacks.
- **Attestation** — AMD certificate chain verification, VMPL=0 enforcement, debug-bit rejection, REPORT_DATA pubkey binding
- **DLEQ proofs** — every partial evaluation proves correct key share usage
- **Attestation-bound recovery** — donors independently verify target attestation before releasing sub-shares
- **Per-node IAM** — each node scoped to its own S3 bucket
- **Network isolation** — PrivateLink only, no public key exposure
- **Device attestation** — Apple App Attest / Google Play Integrity
- **Replay protection** — reshare requests tracked by attestation report digest with TTL-based eviction

## Common Operations

```bash
./deploy.sh verify              # Health-check all nodes via SSH
./deploy.sh e2e                 # End-to-end OPRF evaluation test
./deploy.sh show-ips            # Fetch current node IPs
./deploy.sh redeploy            # Pull latest image + restart (requires SSH)
./deploy.sh sync-state          # Push config to SSM Parameter Store
./deploy.sh lambda-config       # Regenerate lambda/config.env from deployment state
./deploy.sh auto-config         # Auto-populate nodes.json from AWS
```

## CI

GitHub Actions on push/PR to `main`: format (rustfmt), lint (clippy), security audit, unit tests, build, integration tests, Docker image push to ghcr.io (main only).

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Rotation Lambda timeout | Ensure `ssm` VPC endpoint exists with port 443 allowed in SG |
| SSM ConnectTimeoutError | VPC endpoint SG must allow TCP 443 from VPC CIDR |
| S3 denied during seal | Add `s3:PutObject` to node IAM role |
| Container exits on init-seal | Check `docker logs toprf-init-seal` |
| Peer unreachable | Check PrivateLink endpoint state, coordinator configs |
| NLB unhealthy | Check `docker ps` and `docker logs toprf-node` |
| Measurement mismatch | Update `EXPECTED_PEER_MEASUREMENT` in `reshare_handler.rs`, rebuild image |
| Rotation donor rejection | Ensure donors have the latest Docker image (rotate with old AMI first) |
| `ecs-agent` container on nodes | Remove with `docker rm -f ecs-agent && systemctl disable ecs` |

## License

See [LICENSE](LICENSE).
