#!/usr/bin/env bash
# =============================================================================
# setup-ecs.sh — Provision ECS Fargate + ALB for the API + TOPRF proxy.
#
# Creates:
#   - VPC with public/private subnets + NAT Gateway (stable outbound IP)
#   - ALB with HTTP listener (HTTPS added after ACM cert validation)
#   - ECS Fargate cluster, task definition, service
#   - S3 bucket for proxy config + certs (pulled by init container at startup)
#   - IAM roles for task execution and runtime
#   - ACM certificate request for ${DOMAIN}
#
# Architecture:
#   Internet → ALB (port 443) → ECS Task:
#     - api-server (Express, port 3002) → TOPRF proxy (Rust, port 3000)
#     - config-init container pulls proxy-config.json + certs from S3
#   ECS Task → NAT Gateway (stable EIP) → TEE nodes on port 3001
#
# Usage:
#   ./setup-ecs.sh              # Run all steps
#   ./setup-ecs.sh vpc          # Run specific step
#   ./setup-ecs.sh upload-config # Upload proxy config + certs to S3
#
# Prerequisites:
#   - AWS CLI authenticated with admin-level access
#   - ECR repos created (see ecr step)
#   - jq installed
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load shared config if available
CONFIG_FILE="${SCRIPT_DIR}/config.env"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

# ─── Configuration ───────────────────────────────────────────────────────────

# Load these from config.env or set here
REGION="${ECR_REGION:-eu-west-2}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:?Set AWS_ACCOUNT_ID in config.env}"
PROJECT="${PROJECT_NAME:-ruonid}"
CLUSTER_NAME="${ECS_CLUSTER_NAME:-${PROJECT}}"
SERVICE_NAME="${ECS_SERVICE_NAME:-${PROJECT}-api}"
DOMAIN="${DOMAIN:?Set DOMAIN in config.env (e.g. api.example.com)}"

VPC_CIDR="10.0.0.0/16"
PUBLIC_SUBNET_1_CIDR="10.0.1.0/24"
PUBLIC_SUBNET_2_CIDR="10.0.2.0/24"
PRIVATE_SUBNET_1_CIDR="10.0.10.0/24"
PRIVATE_SUBNET_2_CIDR="10.0.11.0/24"
AZ_1="${REGION}a"
AZ_2="${REGION}b"

ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
API_IMAGE="${ECR_URI}/${API_ECR_REPO:-toprf/api-server}:latest"
PROXY_IMAGE="${ECR_URI}/${PROXY_ECR_REPO:-toprf/toprf-proxy}:latest"
CONFIG_BUCKET="${ECS_CONFIG_BUCKET:-${CLUSTER_NAME}-ecs-config}"

# State file — tracks created resource IDs for idempotency
STATE_FILE="${SCRIPT_DIR}/ecs-state.env"

# ─── Helpers ─────────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
warn()  { echo "  WARN: $*"; }
die()   { echo "  ERROR: $*" >&2; exit 1; }

save_state() { echo "$1=$2" >> "$STATE_FILE"; }

load_state() {
    if [[ -f "$STATE_FILE" ]]; then
        source "$STATE_FILE"
    fi
}

# Get a value from state, or empty string
state_val() {
    load_state
    echo "${!1:-}"
}

tag_resource() {
    aws ec2 create-tags --region "$REGION" --resources "$1" \
        --tags "Key=Name,Value=$2" "Key=Project,Value=${PROJECT}" 2>/dev/null || true
}

# =============================================================================
# Steps
# =============================================================================

# ─── 1. VPC + Networking ────────────────────────────────────────────────────

step_vpc() {
    echo ""
    info "Creating VPC and networking"
    load_state

    # VPC
    if [[ -z "${VPC_ID:-}" ]]; then
        VPC_ID=$(aws ec2 create-vpc --region "$REGION" \
            --cidr-block "$VPC_CIDR" \
            --query 'Vpc.VpcId' --output text)
        save_state "VPC_ID" "$VPC_ID"
        tag_resource "$VPC_ID" "${PROJECT}-vpc"
        aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC_ID" --enable-dns-hostnames
        aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC_ID" --enable-dns-support
        echo "  VPC: $VPC_ID"
    else
        echo "  VPC: $VPC_ID (exists)"
    fi

    # Internet Gateway
    if [[ -z "${IGW_ID:-}" ]]; then
        IGW_ID=$(aws ec2 create-internet-gateway --region "$REGION" \
            --query 'InternetGateway.InternetGatewayId' --output text)
        save_state "IGW_ID" "$IGW_ID"
        tag_resource "$IGW_ID" "${PROJECT}-igw"
        aws ec2 attach-internet-gateway --region "$REGION" \
            --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID"
        echo "  IGW: $IGW_ID"
    else
        echo "  IGW: $IGW_ID (exists)"
    fi

    # Public subnets
    if [[ -z "${PUB_SUBNET_1:-}" ]]; then
        PUB_SUBNET_1=$(aws ec2 create-subnet --region "$REGION" \
            --vpc-id "$VPC_ID" --cidr-block "$PUBLIC_SUBNET_1_CIDR" \
            --availability-zone "$AZ_1" \
            --query 'Subnet.SubnetId' --output text)
        save_state "PUB_SUBNET_1" "$PUB_SUBNET_1"
        tag_resource "$PUB_SUBNET_1" "${PROJECT}-public-1"
        aws ec2 modify-subnet-attribute --region "$REGION" \
            --subnet-id "$PUB_SUBNET_1" --map-public-ip-on-launch
        echo "  Public subnet 1: $PUB_SUBNET_1 ($AZ_1)"
    else
        echo "  Public subnet 1: $PUB_SUBNET_1 (exists)"
    fi

    if [[ -z "${PUB_SUBNET_2:-}" ]]; then
        PUB_SUBNET_2=$(aws ec2 create-subnet --region "$REGION" \
            --vpc-id "$VPC_ID" --cidr-block "$PUBLIC_SUBNET_2_CIDR" \
            --availability-zone "$AZ_2" \
            --query 'Subnet.SubnetId' --output text)
        save_state "PUB_SUBNET_2" "$PUB_SUBNET_2"
        tag_resource "$PUB_SUBNET_2" "${PROJECT}-public-2"
        aws ec2 modify-subnet-attribute --region "$REGION" \
            --subnet-id "$PUB_SUBNET_2" --map-public-ip-on-launch
        echo "  Public subnet 2: $PUB_SUBNET_2 ($AZ_2)"
    else
        echo "  Public subnet 2: $PUB_SUBNET_2 (exists)"
    fi

    # Private subnets
    if [[ -z "${PRIV_SUBNET_1:-}" ]]; then
        PRIV_SUBNET_1=$(aws ec2 create-subnet --region "$REGION" \
            --vpc-id "$VPC_ID" --cidr-block "$PRIVATE_SUBNET_1_CIDR" \
            --availability-zone "$AZ_1" \
            --query 'Subnet.SubnetId' --output text)
        save_state "PRIV_SUBNET_1" "$PRIV_SUBNET_1"
        tag_resource "$PRIV_SUBNET_1" "${PROJECT}-private-1"
        echo "  Private subnet 1: $PRIV_SUBNET_1 ($AZ_1)"
    else
        echo "  Private subnet 1: $PRIV_SUBNET_1 (exists)"
    fi

    if [[ -z "${PRIV_SUBNET_2:-}" ]]; then
        PRIV_SUBNET_2=$(aws ec2 create-subnet --region "$REGION" \
            --vpc-id "$VPC_ID" --cidr-block "$PRIVATE_SUBNET_2_CIDR" \
            --availability-zone "$AZ_2" \
            --query 'Subnet.SubnetId' --output text)
        save_state "PRIV_SUBNET_2" "$PRIV_SUBNET_2"
        tag_resource "$PRIV_SUBNET_2" "${PROJECT}-private-2"
        echo "  Private subnet 2: $PRIV_SUBNET_2 ($AZ_2)"
    else
        echo "  Private subnet 2: $PRIV_SUBNET_2 (exists)"
    fi

    # NAT Gateway (Elastic IP + NAT in public subnet 1)
    if [[ -z "${NAT_EIP_ALLOC:-}" ]]; then
        NAT_EIP_ALLOC=$(aws ec2 allocate-address --region "$REGION" \
            --domain vpc --query 'AllocationId' --output text)
        save_state "NAT_EIP_ALLOC" "$NAT_EIP_ALLOC"

        NAT_EIP=$(aws ec2 describe-addresses --region "$REGION" \
            --allocation-ids "$NAT_EIP_ALLOC" \
            --query 'Addresses[0].PublicIp' --output text)
        save_state "NAT_EIP" "$NAT_EIP"
        echo "  NAT Elastic IP: $NAT_EIP"
    else
        echo "  NAT Elastic IP: ${NAT_EIP:-$NAT_EIP_ALLOC} (exists)"
    fi

    if [[ -z "${NAT_GW_ID:-}" ]]; then
        NAT_GW_ID=$(aws ec2 create-nat-gateway --region "$REGION" \
            --subnet-id "$PUB_SUBNET_1" \
            --allocation-id "$NAT_EIP_ALLOC" \
            --query 'NatGateway.NatGatewayId' --output text)
        save_state "NAT_GW_ID" "$NAT_GW_ID"
        tag_resource "$NAT_GW_ID" "${PROJECT}-nat"
        echo "  NAT Gateway: $NAT_GW_ID (creating...)"

        echo "  Waiting for NAT Gateway to become available..."
        aws ec2 wait nat-gateway-available --region "$REGION" \
            --nat-gateway-ids "$NAT_GW_ID"
        echo "  NAT Gateway ready."
    else
        echo "  NAT Gateway: $NAT_GW_ID (exists)"
    fi

    # Route tables
    if [[ -z "${PUB_RT:-}" ]]; then
        PUB_RT=$(aws ec2 create-route-table --region "$REGION" \
            --vpc-id "$VPC_ID" --query 'RouteTable.RouteTableId' --output text)
        save_state "PUB_RT" "$PUB_RT"
        tag_resource "$PUB_RT" "${PROJECT}-public-rt"
        aws ec2 create-route --region "$REGION" --route-table-id "$PUB_RT" \
            --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_ID" > /dev/null
        aws ec2 associate-route-table --region "$REGION" \
            --route-table-id "$PUB_RT" --subnet-id "$PUB_SUBNET_1" > /dev/null
        aws ec2 associate-route-table --region "$REGION" \
            --route-table-id "$PUB_RT" --subnet-id "$PUB_SUBNET_2" > /dev/null
        echo "  Public route table: $PUB_RT"
    else
        echo "  Public route table: $PUB_RT (exists)"
    fi

    if [[ -z "${PRIV_RT:-}" ]]; then
        PRIV_RT=$(aws ec2 create-route-table --region "$REGION" \
            --vpc-id "$VPC_ID" --query 'RouteTable.RouteTableId' --output text)
        save_state "PRIV_RT" "$PRIV_RT"
        tag_resource "$PRIV_RT" "${PROJECT}-private-rt"
        aws ec2 create-route --region "$REGION" --route-table-id "$PRIV_RT" \
            --destination-cidr-block 0.0.0.0/0 --nat-gateway-id "$NAT_GW_ID" > /dev/null
        aws ec2 associate-route-table --region "$REGION" \
            --route-table-id "$PRIV_RT" --subnet-id "$PRIV_SUBNET_1" > /dev/null
        aws ec2 associate-route-table --region "$REGION" \
            --route-table-id "$PRIV_RT" --subnet-id "$PRIV_SUBNET_2" > /dev/null
        echo "  Private route table: $PRIV_RT"
    else
        echo "  Private route table: $PRIV_RT (exists)"
    fi

    echo "  Done."
}

# ─── 2. Security Groups ─────────────────────────────────────────────────────

step_security() {
    echo ""
    info "Creating security groups"
    load_state

    [[ -n "${VPC_ID:-}" ]] || die "Run 'vpc' step first"

    # ALB security group
    if [[ -z "${ALB_SG:-}" ]]; then
        ALB_SG=$(aws ec2 create-security-group --region "$REGION" \
            --group-name ${PROJECT}-alb-sg --description "${PROJECT} ALB" \
            --vpc-id "$VPC_ID" --query 'GroupId' --output text)
        save_state "ALB_SG" "$ALB_SG"
        tag_resource "$ALB_SG" "${PROJECT}-alb-sg"
        aws ec2 authorize-security-group-ingress --region "$REGION" \
            --group-id "$ALB_SG" --protocol tcp --port 80 --cidr 0.0.0.0/0
        aws ec2 authorize-security-group-ingress --region "$REGION" \
            --group-id "$ALB_SG" --protocol tcp --port 443 --cidr 0.0.0.0/0
        echo "  ALB SG: $ALB_SG (inbound 80, 443)"
    else
        echo "  ALB SG: $ALB_SG (exists)"
    fi

    # ECS tasks security group
    if [[ -z "${ECS_SG:-}" ]]; then
        ECS_SG=$(aws ec2 create-security-group --region "$REGION" \
            --group-name ${PROJECT}-ecs-sg --description "${PROJECT} ECS tasks" \
            --vpc-id "$VPC_ID" --query 'GroupId' --output text)
        save_state "ECS_SG" "$ECS_SG"
        tag_resource "$ECS_SG" "${PROJECT}-ecs-sg"
        aws ec2 authorize-security-group-ingress --region "$REGION" \
            --group-id "$ECS_SG" --protocol tcp --port 3002 \
            --source-group "$ALB_SG"
        echo "  ECS SG: $ECS_SG (inbound 3002 from ALB)"
    else
        echo "  ECS SG: $ECS_SG (exists)"
    fi

    echo "  Done."
}

# ─── 3. ALB ─────────────────────────────────────────────────────────────────

step_alb() {
    echo ""
    info "Creating Application Load Balancer"
    load_state

    [[ -n "${PUB_SUBNET_1:-}" && -n "${ALB_SG:-}" ]] || die "Run 'vpc' and 'security' steps first"

    if [[ -z "${ALB_ARN:-}" ]]; then
        ALB_ARN=$(aws elbv2 create-load-balancer --region "$REGION" \
            --name ${PROJECT}-alb --type application \
            --subnets "$PUB_SUBNET_1" "$PUB_SUBNET_2" \
            --security-groups "$ALB_SG" \
            --query 'LoadBalancers[0].LoadBalancerArn' --output text)
        save_state "ALB_ARN" "$ALB_ARN"

        ALB_DNS=$(aws elbv2 describe-load-balancers --region "$REGION" \
            --load-balancer-arns "$ALB_ARN" \
            --query 'LoadBalancers[0].DNSName' --output text)
        save_state "ALB_DNS" "$ALB_DNS"
        echo "  ALB: $ALB_DNS"
    else
        echo "  ALB: ${ALB_DNS:-$ALB_ARN} (exists)"
    fi

    # Target group
    if [[ -z "${TG_ARN:-}" ]]; then
        TG_ARN=$(aws elbv2 create-target-group --region "$REGION" \
            --name ${PROJECT}-api-tg --protocol HTTP --port 3002 \
            --vpc-id "$VPC_ID" --target-type ip \
            --health-check-path /health \
            --health-check-interval-seconds 30 \
            --healthy-threshold-count 2 \
            --unhealthy-threshold-count 3 \
            --query 'TargetGroups[0].TargetGroupArn' --output text)
        save_state "TG_ARN" "$TG_ARN"
        echo "  Target group: $TG_ARN"
    else
        echo "  Target group: $TG_ARN (exists)"
    fi

    # HTTP listener (HTTPS added later after ACM cert validation)
    if [[ -z "${HTTP_LISTENER_ARN:-}" ]]; then
        HTTP_LISTENER_ARN=$(aws elbv2 create-listener --region "$REGION" \
            --load-balancer-arn "$ALB_ARN" \
            --protocol HTTP --port 80 \
            --default-actions "Type=forward,TargetGroupArn=$TG_ARN" \
            --query 'Listeners[0].ListenerArn' --output text)
        save_state "HTTP_LISTENER_ARN" "$HTTP_LISTENER_ARN"
        echo "  HTTP listener: port 80 → target group"
    else
        echo "  HTTP listener: exists"
    fi

    echo "  Done."
}

# ─── 4. ACM Certificate ─────────────────────────────────────────────────────

step_cert() {
    echo ""
    info "Requesting ACM certificate for $DOMAIN"
    load_state

    if [[ -z "${CERT_ARN:-}" ]]; then
        CERT_ARN=$(aws acm request-certificate --region "$REGION" \
            --domain-name "$DOMAIN" \
            --validation-method DNS \
            --query 'CertificateArn' --output text)
        save_state "CERT_ARN" "$CERT_ARN"
        echo "  Certificate ARN: $CERT_ARN"
    else
        echo "  Certificate ARN: $CERT_ARN (exists)"
    fi

    # Show DNS validation record
    sleep 2
    echo ""
    echo "  Add this DNS record to validate:"
    aws acm describe-certificate --region "$REGION" \
        --certificate-arn "$CERT_ARN" \
        --query 'Certificate.DomainValidationOptions[0].ResourceRecord' \
        --output table 2>/dev/null || echo "  (record not yet available — re-run this step in a minute)"

    echo ""
    echo "  After DNS propagates, run: ./setup-ecs.sh add-https"
    echo "  Done."
}

# ─── 5. Add HTTPS listener (after cert validation) ──────────────────────────

step_add_https() {
    echo ""
    info "Adding HTTPS listener to ALB"
    load_state

    [[ -n "${ALB_ARN:-}" && -n "${CERT_ARN:-}" && -n "${TG_ARN:-}" ]] \
        || die "Run 'alb' and 'cert' steps first"

    # Check cert status
    local status
    status=$(aws acm describe-certificate --region "$REGION" \
        --certificate-arn "$CERT_ARN" \
        --query 'Certificate.Status' --output text)

    if [[ "$status" != "ISSUED" ]]; then
        die "Certificate not yet validated (status: $status). Add the DNS record and wait."
    fi

    if [[ -z "${HTTPS_LISTENER_ARN:-}" ]]; then
        HTTPS_LISTENER_ARN=$(aws elbv2 create-listener --region "$REGION" \
            --load-balancer-arn "$ALB_ARN" \
            --protocol HTTPS --port 443 \
            --certificates "CertificateArn=$CERT_ARN" \
            --default-actions "Type=forward,TargetGroupArn=$TG_ARN" \
            --query 'Listeners[0].ListenerArn' --output text)
        save_state "HTTPS_LISTENER_ARN" "$HTTPS_LISTENER_ARN"
        echo "  HTTPS listener: port 443 → target group"

        # Redirect HTTP → HTTPS
        aws elbv2 modify-listener --region "$REGION" \
            --listener-arn "$HTTP_LISTENER_ARN" \
            --default-actions 'Type=redirect,RedirectConfig={Protocol=HTTPS,Port=443,StatusCode=HTTP_301}' \
            > /dev/null
        echo "  HTTP listener: port 80 → redirect to HTTPS"
    else
        echo "  HTTPS listener: exists"
    fi

    echo "  Done."
}

# ─── 6. IAM Roles ───────────────────────────────────────────────────────────

step_roles() {
    echo ""
    info "Creating IAM roles"
    load_state

    # Task execution role (ECR pull, CloudWatch logs, S3 config)
    if [[ -z "${EXEC_ROLE_ARN:-}" ]]; then
        EXEC_ROLE_ARN=$(aws iam create-role --role-name ${PROJECT}-ecs-exec \
            --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
            --query 'Role.Arn' --output text 2>/dev/null) \
            || EXEC_ROLE_ARN=$(aws iam get-role --role-name ${PROJECT}-ecs-exec \
                --query 'Role.Arn' --output text)
        save_state "EXEC_ROLE_ARN" "$EXEC_ROLE_ARN"

        aws iam attach-role-policy --role-name ${PROJECT}-ecs-exec \
            --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy 2>/dev/null || true

        # S3 access for init container to pull config
        aws iam put-role-policy --role-name ${PROJECT}-ecs-exec \
            --policy-name s3-config-access \
            --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":\"arn:aws:s3:::${CONFIG_BUCKET}/*\"}]}"

        echo "  Execution role: $EXEC_ROLE_ARN"
    else
        echo "  Execution role: $EXEC_ROLE_ARN (exists)"
    fi

    # Task role (DynamoDB, KMS, S3 — used by app at runtime)
    if [[ -z "${TASK_ROLE_ARN:-}" ]]; then
        TASK_ROLE_ARN=$(aws iam create-role --role-name ${PROJECT}-ecs-task \
            --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
            --query 'Role.Arn' --output text 2>/dev/null) \
            || TASK_ROLE_ARN=$(aws iam get-role --role-name ${PROJECT}-ecs-task \
                --query 'Role.Arn' --output text)
        save_state "TASK_ROLE_ARN" "$TASK_ROLE_ARN"

        aws iam put-role-policy --role-name ${PROJECT}-ecs-task \
            --policy-name ${PROJECT}-runtime \
            --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:GetItem\",\"dynamodb:PutItem\",\"dynamodb:UpdateItem\",\"dynamodb:Query\",\"dynamodb:DeleteItem\"],\"Resource\":\"arn:aws:dynamodb:${REGION}:${AWS_ACCOUNT_ID}:table/${PROJECT}-*\"},{\"Effect\":\"Allow\",\"Action\":[\"kms:Sign\",\"kms:Verify\",\"kms:GetPublicKey\"],\"Resource\":\"arn:aws:kms:${REGION}:${AWS_ACCOUNT_ID}:key/*\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":\"arn:aws:s3:::${CONFIG_BUCKET}/*\"}]}"

        echo "  Task role: $TASK_ROLE_ARN"
    else
        echo "  Task role: $TASK_ROLE_ARN (exists)"
    fi

    echo "  Done."
}

# ─── 7. S3 Config Bucket ────────────────────────────────────────────────────

step_config_bucket() {
    echo ""
    info "Creating S3 config bucket"
    load_state

    aws s3 mb "s3://${CONFIG_BUCKET}" --region "$REGION" 2>/dev/null \
        || warn "bucket may already exist"
    aws s3api put-public-access-block --region "$REGION" \
        --bucket "$CONFIG_BUCKET" \
        --public-access-block-configuration \
        'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'

    echo "  Bucket: s3://${CONFIG_BUCKET}"
    echo "  Run './setup-ecs.sh upload-config' to upload proxy config + certs."
    echo "  Done."
}

# ─── 8. Upload proxy config + certs to S3 ───────────────────────────────────

step_upload_config() {
    echo ""
    info "Uploading proxy config + certs to S3"

    local proxy_config="$REPO_ROOT/docker/proxy-config.production.json"
    local certs_dir="$REPO_ROOT/certs"

    if [[ ! -f "$proxy_config" ]]; then
        die "proxy-config.production.json not found. Run './deploy.sh proxy-config' first."
    fi
    if [[ ! -d "$certs_dir/ca" ]]; then
        die "certs/ not found. Run './deploy.sh certs' first."
    fi

    aws s3 cp "$proxy_config" "s3://${CONFIG_BUCKET}/proxy-config.json" --region "$REGION"
    aws s3 cp "$certs_dir/ca/ca.pem" "s3://${CONFIG_BUCKET}/certs/ca/ca.pem" --region "$REGION"
    aws s3 cp "$certs_dir/proxy/proxy-client.pem" "s3://${CONFIG_BUCKET}/certs/proxy/proxy-client.pem" --region "$REGION"
    aws s3 cp "$certs_dir/proxy/proxy-client.key" "s3://${CONFIG_BUCKET}/certs/proxy/proxy-client.key" --region "$REGION"

    echo "  Uploaded:"
    echo "    s3://${CONFIG_BUCKET}/proxy-config.json"
    echo "    s3://${CONFIG_BUCKET}/certs/ca/ca.pem"
    echo "    s3://${CONFIG_BUCKET}/certs/proxy/proxy-client.pem"
    echo "    s3://${CONFIG_BUCKET}/certs/proxy/proxy-client.key"
    echo "  Done."
}

# ─── 9. ECR Repo for API Server ─────────────────────────────────────────────

step_ecr() {
    echo ""
    info "Creating ECR repo for api-server"

    local ecr_repo="${API_ECR_REPO:-toprf/api-server}"
    aws ecr create-repository --region "$REGION" \
        --repository-name "$ecr_repo" 2>/dev/null \
        || warn "repo may already exist"

    echo "  Repo: ${ECR_URI}/${ecr_repo}"
    echo "  Build and push:"
    echo "    cd server"
    echo "    docker buildx build --platform linux/amd64 -t ${PROJECT}-api:latest --load ."
    echo "    docker tag ${PROJECT}-api:latest ${API_IMAGE}"
    echo "    docker push ${API_IMAGE}"
    echo "  Done."
}

# ─── 10. ECS Cluster ────────────────────────────────────────────────────────

step_cluster() {
    echo ""
    info "Creating ECS cluster"
    load_state

    if [[ -z "${CLUSTER_ARN:-}" ]]; then
        CLUSTER_ARN=$(aws ecs create-cluster --region "$REGION" \
            --cluster-name "$CLUSTER_NAME" \
            --query 'cluster.clusterArn' --output text 2>/dev/null) \
            || CLUSTER_ARN=$(aws ecs describe-clusters --region "$REGION" \
                --clusters "$CLUSTER_NAME" \
                --query 'clusters[0].clusterArn' --output text)
        save_state "CLUSTER_ARN" "$CLUSTER_ARN"
        echo "  Cluster: $CLUSTER_ARN"
    else
        echo "  Cluster: $CLUSTER_ARN (exists)"
    fi

    # CloudWatch log group
    aws logs create-log-group --region "$REGION" \
        --log-group-name "/ecs/$CLUSTER_NAME" 2>/dev/null \
        || warn "log group may already exist"

    echo "  Done."
}

# ─── 11. Task Definition ────────────────────────────────────────────────────

step_task() {
    echo ""
    info "Registering ECS task definition"
    load_state

    [[ -n "${EXEC_ROLE_ARN:-}" && -n "${TASK_ROLE_ARN:-}" ]] \
        || die "Run 'roles' step first"

    # Write task definition JSON to temp file (heredoc + pipe to stdin
    # doesn't work reliably with aws cli)
    local task_file
    task_file=$(mktemp /tmp/task-def-XXXXXX.json)
    trap "rm -f '$task_file'" RETURN

    cat > "$task_file" <<TASKEOF
{
  "family": "${SERVICE_NAME}",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "${EXEC_ROLE_ARN}",
  "taskRoleArn": "${TASK_ROLE_ARN}",
  "containerDefinitions": [
    {
      "name": "config-init",
      "image": "amazon/aws-cli:latest",
      "essential": false,
      "command": ["sh", "-c", "aws s3 cp s3://${CONFIG_BUCKET}/proxy-config.json /config/proxy-config.json && aws s3 cp --recursive s3://${CONFIG_BUCKET}/certs/ /config/certs/"],
      "mountPoints": [{"sourceVolume": "config", "containerPath": "/config"}],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/${CLUSTER_NAME}",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "config-init"
        }
      }
    },
    {
      "name": "toprf-proxy",
      "image": "${PROXY_IMAGE}",
      "essential": true,
      "dependsOn": [{"containerName": "config-init", "condition": "SUCCESS"}],
      "command": ["--config", "/etc/toprf/proxy-config.json", "--port", "3000"],
      "mountPoints": [{"sourceVolume": "config", "containerPath": "/etc/toprf"}],
      "portMappings": [{"containerPort": 3000, "protocol": "tcp"}],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -qO- http://localhost:3000/health || exit 1"],
        "interval": 10,
        "timeout": 5,
        "startPeriod": 10,
        "retries": 3
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/${CLUSTER_NAME}",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "toprf-proxy"
        }
      }
    },
    {
      "name": "api-server",
      "image": "${API_IMAGE}",
      "essential": true,
      "dependsOn": [{"containerName": "toprf-proxy", "condition": "HEALTHY"}],
      "portMappings": [{"containerPort": 3002, "protocol": "tcp"}],
      "environment": [
        {"name": "PORT", "value": "3002"},
        {"name": "PUBLIC_BASE_URL", "value": "https://${DOMAIN}"},
        {"name": "AWS_REGION", "value": "${REGION}"},
        {"name": "SIGNING_KEY_ID", "value": "${SIGNING_KEY_ID:-}"},
        {"name": "ATTESTATION_MODE", "value": "${ATTESTATION_MODE:-apple}"},
        {"name": "APPLE_APP_ID", "value": "${APPLE_APP_ID:-}"},
        {"name": "APPLE_TEAM_ID", "value": "${APPLE_TEAM_ID:-}"},
        {"name": "APPLE_APP_ATTEST_ENV", "value": "${APPLE_APP_ATTEST_ENV:-production}"},
        {"name": "REDIS_URL", "value": "${REDIS_URL:-}"},
        {"name": "TOPRF_PROXY_URL", "value": "http://localhost:3000"},
        {"name": "DEVELOPERS_TABLE", "value": "${DEVELOPERS_TABLE:-developers}"},
        {"name": "BILLING_TABLE", "value": "${BILLING_TABLE:-billing-events}"},
        {"name": "PRODUCTION_REQUESTS_TABLE", "value": "${PRODUCTION_REQUESTS_TABLE:-production-requests}"},
        {"name": "WEBHOOK_EVENTS_TABLE", "value": "${WEBHOOK_EVENTS_TABLE:-webhook-events}"},
        {"name": "FREE_VERIFICATION_QUOTA", "value": "${FREE_VERIFICATION_QUOTA:-500}"},
        {"name": "DATA_DIR", "value": "/app/data"},
        {"name": "NODE_ENV", "value": "production"}
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -qO- http://localhost:3002/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "startPeriod": 10,
        "retries": 3
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/${CLUSTER_NAME}",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "api-server"
        }
      }
    }
  ],
  "volumes": [
    {
      "name": "config"
    }
  ]
}
TASKEOF

    TASK_DEF_ARN=$(aws ecs register-task-definition --region "$REGION" \
        --cli-input-json "file://${task_file}" \
        --query 'taskDefinition.taskDefinitionArn' --output text)
    save_state "TASK_DEF_ARN" "$TASK_DEF_ARN"

    echo "  Task definition: $TASK_DEF_ARN"
    echo "  Done."
}

# ─── 12. ECS Service ────────────────────────────────────────────────────────

step_service() {
    echo ""
    info "Creating ECS service"
    load_state

    [[ -n "${CLUSTER_ARN:-}" && -n "${TASK_DEF_ARN:-}" && -n "${TG_ARN:-}" && -n "${ECS_SG:-}" ]] \
        || die "Run cluster, task, alb, security steps first"

    if [[ -z "${SERVICE_ARN:-}" ]]; then
        SERVICE_ARN=$(aws ecs create-service --region "$REGION" \
            --cluster "$CLUSTER_NAME" \
            --service-name "$SERVICE_NAME" \
            --task-definition "$SERVICE_NAME" \
            --desired-count 1 \
            --launch-type FARGATE \
            --network-configuration "awsvpcConfiguration={subnets=[$PRIV_SUBNET_1,$PRIV_SUBNET_2],securityGroups=[$ECS_SG],assignPublicIp=DISABLED}" \
            --load-balancers "targetGroupArn=$TG_ARN,containerName=api-server,containerPort=3002" \
            --query 'service.serviceArn' --output text)
        save_state "SERVICE_ARN" "$SERVICE_ARN"
        echo "  Service: $SERVICE_ARN"
    else
        echo "  Service: $SERVICE_ARN (exists)"
        echo "  Updating to latest task definition..."
        aws ecs update-service --region "$REGION" \
            --cluster "$CLUSTER_NAME" \
            --service "$SERVICE_NAME" \
            --task-definition "$SERVICE_NAME" \
            --force-new-deployment > /dev/null
        echo "  Deployment triggered."
    fi

    echo "  Done."
}

# ─── 13. Redis VPC Peering ──────────────────────────────────────────────────

step_redis_peering() {
    echo ""
    info "Setting up VPC peering for ElastiCache Redis"
    load_state

    [[ -n "${VPC_ID:-}" && -n "${PRIV_RT:-}" ]] || die "Run 'vpc' step first"

    # Find Redis VPC
    echo "  Finding Redis cluster VPC..."
    local redis_sg
    redis_sg=$(aws elasticache describe-cache-clusters --region "$REGION" \
        --cache-cluster-id "${REDIS_CLUSTER_ID:?Set REDIS_CLUSTER_ID in config.env}" \
        --query 'CacheClusters[0].SecurityGroups[0].SecurityGroupId' --output text 2>/dev/null) \
        || die "Redis cluster '${REDIS_CLUSTER_ID}' not found in $REGION"

    local redis_vpc
    redis_vpc=$(aws ec2 describe-security-groups --region "$REGION" \
        --group-ids "$redis_sg" \
        --query 'SecurityGroups[0].VpcId' --output text)

    if [[ "$redis_vpc" == "$VPC_ID" ]]; then
        echo "  Redis is already in the ECS VPC. No peering needed."
        # Just allow inbound from ECS SG
        aws ec2 authorize-security-group-ingress --region "$REGION" \
            --group-id "$redis_sg" --protocol tcp --port 6379 \
            --source-group "$ECS_SG" 2>/dev/null || warn "rule may already exist"
        echo "  Done."
        return
    fi

    echo "  Redis VPC: $redis_vpc"
    local redis_cidr
    redis_cidr=$(aws ec2 describe-vpcs --region "$REGION" \
        --vpc-ids "$redis_vpc" \
        --query 'Vpcs[0].CidrBlock' --output text)
    echo "  Redis CIDR: $redis_cidr"

    # Create peering connection
    if [[ -z "${PEERING_ID:-}" ]]; then
        PEERING_ID=$(aws ec2 create-vpc-peering-connection --region "$REGION" \
            --vpc-id "$VPC_ID" --peer-vpc-id "$redis_vpc" \
            --query 'VpcPeeringConnection.VpcPeeringConnectionId' --output text)
        save_state "PEERING_ID" "$PEERING_ID"
        echo "  Peering: $PEERING_ID"

        # Accept (same account, same region)
        aws ec2 accept-vpc-peering-connection --region "$REGION" \
            --vpc-peering-connection-id "$PEERING_ID" > /dev/null
        echo "  Peering accepted."
    else
        echo "  Peering: $PEERING_ID (exists)"
    fi

    # Routes: ECS private subnets → Redis VPC via peering
    aws ec2 create-route --region "$REGION" --route-table-id "$PRIV_RT" \
        --destination-cidr-block "$redis_cidr" \
        --vpc-peering-connection-id "$PEERING_ID" 2>/dev/null || warn "route may exist"

    # Routes: Redis VPC → ECS VPC via peering
    local redis_rt
    redis_rt=$(aws ec2 describe-route-tables --region "$REGION" \
        --filters "Name=vpc-id,Values=$redis_vpc" \
        --query 'RouteTables[0].RouteTableId' --output text)
    aws ec2 create-route --region "$REGION" --route-table-id "$redis_rt" \
        --destination-cidr-block "$VPC_CIDR" \
        --vpc-peering-connection-id "$PEERING_ID" 2>/dev/null || warn "route may exist"

    # Allow ECS → Redis on port 6379
    aws ec2 authorize-security-group-ingress --region "$REGION" \
        --group-id "$redis_sg" --protocol tcp --port 6379 \
        --cidr "$VPC_CIDR" 2>/dev/null || warn "rule may already exist"

    echo "  Done."
}

# ─── 14. Status ──────────────────────────────────────────────────────────────

step_status() {
    echo ""
    info "Deployment status"
    load_state

    echo "  NAT Gateway EIP:  ${NAT_EIP:-not created}"
    echo "  ALB DNS:          ${ALB_DNS:-not created}"
    echo "  ACM Certificate:  ${CERT_ARN:-not requested}"
    echo "  ECS Cluster:      ${CLUSTER_ARN:-not created}"
    echo "  ECS Service:      ${SERVICE_ARN:-not created}"
    echo ""

    if [[ -n "${NAT_EIP:-}" ]]; then
        echo "  ┌──────────────────────────────────────────────┐"
        echo "  │  PROXY_IP=${NAT_EIP}  │"
        echo "  │  Add this to deploy/config.env                │"
        echo "  └──────────────────────────────────────────────┘"
        echo ""
    fi

    if [[ -n "${ALB_DNS:-}" ]]; then
        echo "  DNS: Point $DOMAIN → $ALB_DNS (CNAME or alias)"
    fi

    if [[ -n "${SERVICE_ARN:-}" ]]; then
        echo ""
        echo "  Service status:"
        aws ecs describe-services --region "$REGION" \
            --cluster "$CLUSTER_NAME" --services "$SERVICE_NAME" \
            --query 'services[0].{desired:desiredCount,running:runningCount,status:status}' \
            --output table 2>/dev/null || true
    fi
}

# =============================================================================
# CLI
# =============================================================================

usage() {
    cat <<'EOF'
Usage: setup-ecs.sh <step> [step...]

Infrastructure (run once, in order):
  vpc             VPC, subnets, IGW, NAT Gateway, route tables
  security        Security groups (ALB + ECS)
  alb             Application Load Balancer + target group
  cert            Request ACM certificate for \${DOMAIN}
  roles           IAM roles (task execution + task runtime)
  config-bucket   S3 bucket for proxy config + certs
  ecr             ECR repo for api-server image
  cluster         ECS Fargate cluster
  task            Register task definition
  service         Create ECS service
  redis-peering   VPC peering for ElastiCache Redis

After cert validation:
  add-https       Add HTTPS listener + HTTP→HTTPS redirect

Operations:
  upload-config   Upload proxy-config.json + certs to S3
  status          Show resource IDs, NAT EIP, service health

Shortcuts:
  all             Run all infrastructure steps in order
  redeploy        Update task definition + force new deployment
EOF
}

# Help without config
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
    usage; exit 0
fi

if [[ $# -eq 0 ]]; then
    usage; exit 0
fi

for step in "$@"; do
    case "$step" in
        vpc)            step_vpc ;;
        security)       step_security ;;
        alb)            step_alb ;;
        cert)           step_cert ;;
        add-https)      step_add_https ;;
        roles)          step_roles ;;
        config-bucket)  step_config_bucket ;;
        upload-config)  step_upload_config ;;
        ecr)            step_ecr ;;
        cluster)        step_cluster ;;
        task)           step_task ;;
        service)        step_service ;;
        redis-peering)  step_redis_peering ;;
        status)         step_status ;;
        redeploy)
            step_task
            load_state
            if [[ -n "${SERVICE_ARN:-}" ]]; then
                aws ecs update-service --region "$REGION" \
                    --cluster "$CLUSTER_NAME" --service "$SERVICE_NAME" \
                    --task-definition "$SERVICE_NAME" \
                    --force-new-deployment > /dev/null
                echo "  Redeployment triggered."
            fi
            ;;
        all)
            step_vpc
            step_security
            step_alb
            step_cert
            step_roles
            step_config_bucket
            step_ecr
            step_cluster
            step_task
            step_service
            step_redis_peering
            echo ""
            echo "═══════════════════════════════════════════════════════"
            step_status
            ;;
        *)
            echo "Unknown step: $step"; usage; exit 1 ;;
    esac
done
