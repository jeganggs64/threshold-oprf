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

## Repository Structure

```
crates/
  core/       Threshold OPRF cryptography (Shamir, partial eval, DLEQ, combine, recovery)
  node/       TEE node server (coordinator + peer mode)
  keygen/     Offline ceremony tool (generate key, split into shares)
  seal/       AMD SEV-SNP sealing, ECIES, attestation verification
lambda/
  handlers/   API Lambda functions (challenge, attest, evaluate)
  rotation/   Automated rotation Lambda (SAM template)
deploy/       Deployment scripts (provision.sh, deploy.sh)
scripts/      Dev utilities (integration-test.sh, gen-certs.sh)
```

## Prerequisites

**Local tools:**
- AWS CLI (authenticated)
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
- EC2 instances (SEV-SNP VMs)
- Per-node IAM roles, instance profiles, key pairs
- S3 buckets for sealed key blobs
- NLBs (per-node + frontend)
- PrivateLink (endpoint services, VPC endpoints, security groups)
- CloudWatch alarms + SNS topics
- SSM Parameter Store entries
- VPC endpoints (S3, SSM, EC2, STS, SSM Messages, EC2 Messages)

## Deployment

### 1. Build

```bash
cargo build --release
cargo test --release
```

### 2. Key Ceremony

Run on an air-gapped machine.

```bash
# Create admin shares (one-time, store in separate secure locations)
cargo run --release -p toprf-keygen -- init \
    --admin-threshold 3 --admin-shares 5 \
    --output-dir ./ceremony/admin-shares

# Derive node shares (bring 3 admin shares together)
cargo run --release -p toprf-keygen -- node-shares \
    --admin-share ceremony/admin-shares/admin-1.json \
    --admin-share ceremony/admin-shares/admin-3.json \
    --admin-share ceremony/admin-shares/admin-5.json \
    --node-threshold 2 --node-shares 3 \
    --output-dir ./ceremony/node-shares
```

### 3. Configure

```bash
cd deploy
cp config.env.example config.env    # Set NODE_SHARES_DIR, manual values
cp nodes.json.example nodes.json    # Set threshold, node regions
```

### 4. Provision + Deploy

```bash
./provision.sh all          # Launch SEV-SNP VMs
./deploy.sh auto-config     # Populate IPs, SGs, VPCs
./deploy.sh all             # pre-seal → init-seal → post-seal
./deploy.sh e2e             # Verify end-to-end
```

### 5. Deploy Lambdas

```bash
./deploy.sh lambda-config   # Auto-generate lambda/config.env
# Manually set: API_ID, ROLE_ARN, APPLE_APP_ID, APPLE_TEAM_ID

cd lambda && ./deploy.sh    # Deploy + wire API Gateway routes
```

### 6. Monitoring + Rotation

```bash
# From deploy/ directory
./deploy.sh cloudwatch      # Health alarms → SNS
./deploy.sh sync-state      # Push config to SSM for rotation Lambda

# Deploy rotation Lambda
cd lambda/rotation
sam build && sam deploy --guided
```

Create VPC endpoints in the coordinator VPC so the rotation Lambda can reach AWS services:

```bash
# S3 gateway (free)
aws ec2 create-vpc-endpoint --vpc-id <VPC_ID> \
  --service-name com.amazonaws.<REGION>.s3 \
  --vpc-endpoint-type Gateway --route-table-ids <RT_ID>

# Interface endpoints (~$7/month each)
for svc in ssm ec2 sts ssmmessages ec2messages; do
  aws ec2 create-vpc-endpoint --vpc-id <VPC_ID> \
    --service-name com.amazonaws.<REGION>.$svc \
    --vpc-endpoint-type Interface \
    --subnet-ids <SUB1> <SUB2> --security-group-ids <SG> \
    --private-dns-enabled
done
```

Subscribe the Lambda to CloudWatch alarm SNS topics:

```bash
aws sns subscribe --topic-arn <ALERT_TOPIC> --protocol lambda \
  --notification-endpoint <ROTATION_LAMBDA_ARN>
aws lambda add-permission --function-name toprf-rotation \
  --statement-id sns-invoke --action lambda:InvokeFunction \
  --principal sns.amazonaws.com --source-arn <ALERT_TOPIC>
```

### 7. Lock Nodes

```bash
./deploy.sh lock    # Irreversible — removes SSH, deletes keys
```

## Common Operations

```bash
./deploy.sh e2e                 # End-to-end test
./deploy.sh verify              # Health-check nodes
./deploy.sh show-ips            # Fetch node IPs
./deploy.sh redeploy            # Pull latest image + restart
./deploy.sh sync-state          # Push config to SSM
```

## Rotation

Automated monthly via Lambda. Uses staging-based share recovery — no admin ceremony needed.

1. Provision staging VM alongside existing node
2. Start init-reshare → attestation report + ephemeral keypair to S3
3. Send `/reshare` to donor nodes → donors verify attestation, compute + encrypt contributions
4. Staging node collects, decrypts, verifies, combines → new share
5. Seal to hardware, health-check, swap NLB targets
6. Terminate old instance

If anything fails, the old node is still running. Zero-downtime.

```bash
# Manual rotation
./provision.sh 1 --staging && ./deploy.sh rotate 1 && ./deploy.sh --nodes 1 lock

# Abort
./provision.sh 1 --terminate-staging
```

**Triggers:**
- CloudWatch alarm (unhealthy node) → SNS → Lambda
- EventBridge schedule (monthly)
- Manual invocation

## Full Key Replacement

If the OPRF secret is compromised and needs to be replaced entirely (not routine — node rotation preserves the existing key):

1. Run new key ceremony (admin shares → node shares)
2. Clear sealed blobs from S3 buckets
3. `./deploy.sh init-seal` (inject new shares)
4. `./deploy.sh start` (restart nodes)
5. `./deploy.sh e2e` (verify)
6. `./deploy.sh sync-state` (update SSM)

**Warning:** all existing `appSpecificId` values become invalid.

## Security

- **T-of-N threshold** — no single node holds enough shares
- **Hardware sealing** — SEV-SNP `MSG_KEY_REQ` derived keys; AWS cannot decrypt
- **Attestation** — AMD certificate chain, VMPL=0 enforcement, debug-bit rejection, ARK fingerprint pinning
- **DLEQ proofs** — every partial evaluation proves correct key share usage
- **Attestation-bound recovery** — donors verify target attestation before releasing sub-shares
- **Per-node IAM** — each node scoped to its own S3 bucket
- **Network isolation** — PrivateLink only, no public exposure
- **Device attestation** — Apple App Attest / Google Play Integrity

## CI

GitHub Actions on push/PR to `main`: format, lint, test, build, integration tests, Docker image push (main only).

## Troubleshooting

| Problem | Fix |
|---------|-----|
| S3 denied during seal | Add `s3:PutObject` to node IAM role |
| Container exits on init-seal | Check `docker logs toprf-init-seal` |
| Peer unreachable | Check PrivateLink endpoint state |
| NLB unhealthy | Check `docker ps` and `docker logs toprf-node` |
| Measurement mismatch | Re-run `./deploy.sh measure`, rebuild |

## License

See [LICENSE](LICENSE).
