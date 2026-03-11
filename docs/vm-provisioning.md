# VM Provisioning

Create (or recreate) the 3 TEE VMs with Ubuntu 24.04 and AMD SEV-SNP across 3 AWS regions.

## Node 1: AWS ap-southeast-1 (Singapore)

```bash
# Find latest Ubuntu 24.04 AMI
AMI=$(aws ec2 describe-images --region ap-southeast-1 \
    --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
    --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)

# Create instance with SEV-SNP
aws ec2 run-instances --region ap-southeast-1 \
    --instance-type c6a.large \
    --image-id $AMI \
    --key-name ruonid-node1 \
    --cpu-options AmdSevSnp=enabled \
    --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=50,VolumeType=gp3}' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=toprf-node-1}]'
```

## Node 2: AWS us-east-1 (Virginia)

```bash
AMI=$(aws ec2 describe-images --region us-east-1 \
    --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
    --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)

aws ec2 run-instances --region us-east-1 \
    --instance-type c6a.large \
    --image-id $AMI \
    --key-name ruonid-node2 \
    --cpu-options AmdSevSnp=enabled \
    --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=50,VolumeType=gp3}' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=toprf-node-2}]'
```

## Node 3: AWS eu-west-1 (Ireland)

```bash
AMI=$(aws ec2 describe-images --region eu-west-1 \
    --owners 099720109477 \
    --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" \
    --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)

aws ec2 run-instances --region eu-west-1 \
    --instance-type c6a.large \
    --image-id $AMI \
    --key-name ruonid-node3 \
    --cpu-options AmdSevSnp=enabled \
    --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=50,VolumeType=gp3}' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=toprf-node-3}]'
```

## Post-provisioning (all nodes)

For each node, set the IMDS hop limit to 2 (required for Docker to reach IMDS):

```bash
aws ec2 modify-instance-metadata-options \
    --instance-id <INSTANCE_ID> \
    --http-put-response-hop-limit 2 \
    --region <REGION>
```

Attach an IAM instance profile with S3 read/write for the sealed blob bucket:

```bash
aws ec2 associate-iam-instance-profile \
    --instance-id <INSTANCE_ID> \
    --iam-instance-profile Name=<PROFILE_NAME> \
    --region <REGION>
```

## Clear old sealed blobs

```bash
aws s3 rm s3://ruonid-sealed-node1/node-1-sealed.bin --region ap-southeast-1
aws s3 rm s3://ruonid-sealed-node2/node-2-sealed.bin --region us-east-1
aws s3 rm s3://ruonid-sealed-node3/node-3-sealed.bin --region eu-west-1
```

## After provisioning

```bash
cd deploy
./deploy.sh auto-config    # Fetches new IPs, SG IDs, VPC IDs
./deploy.sh all            # Full deploy to the VMs
```
