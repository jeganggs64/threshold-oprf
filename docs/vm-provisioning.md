# VM Provisioning

Create (or recreate) TEE VMs with Amazon Linux 2023 and AMD SEV-SNP across 3 AWS regions.

## Automated provisioning

The `provision.sh` script handles AMI selection, instance launch, IMDS configuration, IAM profile attachment, and tagging.

### Prerequisites

1. Fill in `deploy/config.env`:
   - `NODE1_KEY_NAME`, `NODE2_KEY_NAME`, `NODE3_KEY_NAME` — AWS key pair names
   - `IAM_INSTANCE_PROFILE` — IAM instance profile with S3 read/write
   - `INSTANCE_TYPE` — defaults to `c6a.large`

2. Ensure your AWS CLI is authenticated with permissions to launch EC2 instances.

### Provision individual nodes

```bash
cd deploy

# Provision one node at a time
./provision.sh 1    # Node 1 in ap-southeast-1 (Singapore)
./provision.sh 2    # Node 2 in us-east-1 (Virginia)
./provision.sh 3    # Node 3 in eu-west-1 (Ireland)

# Or all at once
./provision.sh all
```

### Check status

```bash
./provision.sh 1 --status    # Show node 1 instance details
./provision.sh all --status  # Show all nodes
```

### Terminate

```bash
./provision.sh 3 --terminate    # Terminate node 3 + clear sealed blob
./provision.sh all --terminate  # Terminate all nodes
```

## What provision.sh does

For each node:

1. Finds the latest Amazon Linux 2023 x86_64 AMI in the target region
2. Launches a `c6a.large` instance with `AmdSevSnp=enabled` and a 50GB gp3 volume
3. Waits for the instance to reach `running` state
4. Sets the IMDS hop limit to 2 (required for Docker containers to reach instance metadata)
5. Attaches the IAM instance profile (if `IAM_INSTANCE_PROFILE` is set)
6. Tags the instance `Name=toprf-node-<N>` for auto-config discovery
7. Prints the instance ID, IPs, security group, and VPC

## After provisioning

```bash
cd deploy
./deploy.sh auto-config    # Fetches IPs, SG IDs, VPC IDs into config.env
./deploy.sh all            # Full deploy (Docker, certs, init-seal, start, peering)
```

## Manual provisioning

If you need to provision manually (e.g. custom VPC, subnet, or security group):

```bash
# Find latest AL2023 AMI
AMI=$(aws ec2 describe-images --region <REGION> \
    --owners amazon \
    --filters "Name=name,Values=al2023-ami-*-x86_64" \
              "Name=state,Values=available" \
    --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)

# Launch with SEV-SNP
aws ec2 run-instances --region <REGION> \
    --instance-type c6a.large \
    --image-id $AMI \
    --key-name <KEY_NAME> \
    --cpu-options AmdSevSnp=enabled \
    --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=50,VolumeType=gp3}' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=toprf-node-<N>}]'

# Set IMDS hop limit (required for Docker)
aws ec2 modify-instance-metadata-options \
    --instance-id <INSTANCE_ID> \
    --http-put-response-hop-limit 2 \
    --region <REGION>

# Attach IAM instance profile
aws ec2 associate-iam-instance-profile \
    --instance-id <INSTANCE_ID> \
    --iam-instance-profile Name=<PROFILE_NAME> \
    --region <REGION>
```

## Clear old sealed blobs

When reprovisioning, clear the previous node's sealed blob so init-seal can write a new one:

```bash
aws s3 rm s3://ruonid-sealed-node1/node-1-sealed.bin --region ap-southeast-1
aws s3 rm s3://ruonid-sealed-node2/node-2-sealed.bin --region us-east-1
aws s3 rm s3://ruonid-sealed-node3/node-3-sealed.bin --region eu-west-1
```

The `./provision.sh <N> --terminate` command does this automatically.
