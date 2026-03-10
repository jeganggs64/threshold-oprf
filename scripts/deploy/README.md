# Deployment Scripts

Automated deployment for the threshold OPRF system: 3 TEE nodes across GCP, Azure, and AWS, plus an ECS Fargate service for the API proxy.

## Prerequisites

- 3 TEE VMs provisioned with AMD SEV-SNP (GCP, Azure, AWS)
- IAM roles / managed identities / instance profiles attached to each VM
- SSH access to all 3 VMs
- `gcloud`, `az`, `aws` CLIs authenticated locally
- `jq`, `openssl`, `curl` installed locally
- Key ceremony completed (`toprf-keygen init`)

## Setup

```bash
cp config.env.example config.env
# Fill in your values (VM IPs, bucket names, etc.)
```

## deploy.sh — TEE Node Deployment

Manages the 3 TEE nodes: builds Docker images on each VM (native amd64), creates storage buckets, generates mTLS certs, handles init-seal key injection, and starts nodes.

```bash
./deploy.sh --help

# Full deployment
./deploy.sh all

# Or step by step
./deploy.sh setup-vms      # Install Docker + Git on VMs
./deploy.sh build           # Clone repo + docker build on each VM
./deploy.sh storage         # Create sealed blob storage buckets
./deploy.sh certs           # Generate mTLS certs + distribute to VMs
./deploy.sh init-seal       # Interactive: inject key shares via attested TLS
./deploy.sh start           # Start nodes in normal mode
./deploy.sh firewall        # Open port 3001 from proxy to nodes
./deploy.sh proxy-config    # Generate proxy-config.production.json
./deploy.sh verify          # Health check all nodes via mTLS

# Code updates (no reseal needed)
./deploy.sh redeploy

# Utilities
./deploy.sh show-ips        # Fetch VM IPs from all 3 providers
```

## setup-ecs.sh — ECS Fargate + ALB

Provisions the API server infrastructure: VPC with NAT Gateway (stable outbound IP), ALB, ECS Fargate cluster running the Express API + Rust proxy.

```bash
./setup-ecs.sh --help

# Full infrastructure setup
./setup-ecs.sh all

# Or step by step
./setup-ecs.sh vpc          # VPC, subnets, IGW, NAT Gateway
./setup-ecs.sh security     # Security groups
./setup-ecs.sh alb          # Application Load Balancer
./setup-ecs.sh cert         # ACM certificate request
./setup-ecs.sh roles        # IAM roles
./setup-ecs.sh config-bucket # S3 bucket for proxy config
./setup-ecs.sh ecr          # ECR repo for API server
./setup-ecs.sh cluster      # ECS cluster
./setup-ecs.sh task         # Task definition
./setup-ecs.sh service      # ECS service
./setup-ecs.sh redis-peering # VPC peering for ElastiCache

# After ACM cert validation
./setup-ecs.sh add-https

# Operations
./setup-ecs.sh upload-config # Upload proxy config + certs to S3
./setup-ecs.sh status        # Show NAT EIP, ALB DNS, service health
./setup-ecs.sh redeploy      # Update task + force new deployment
```

## Files

| File | Tracked | Description |
|------|---------|-------------|
| `config.env.example` | Yes | Template — copy to `config.env` |
| `config.env` | No | Your actual values (gitignored) |
| `ecs-state.env` | No | Created resource IDs (gitignored) |
| `deploy.sh` | Yes | TEE node deployment |
| `setup-ecs.sh` | Yes | ECS + ALB infrastructure |
