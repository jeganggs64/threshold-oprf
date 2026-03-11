#!/usr/bin/env bash
# =============================================================================
# provision.sh — Provision TEE VMs on AWS with Amazon Linux 2023 + AMD SEV-SNP.
#
# Creates (or manages) individual node VMs. Each node is a c6a.large instance
# running AL2023 with SEV-SNP enabled, tagged for auto-config discovery.
#
# Usage:
#   ./provision.sh <node>             Launch a new node VM
#   ./provision.sh <node> --status    Show node instance status
#   ./provision.sh <node> --terminate Terminate node instance
#   ./provision.sh all                Launch all 3 nodes
#
# Examples:
#   ./provision.sh 1                  Provision node 1 in ap-southeast-1
#   ./provision.sh 2 --status         Check node 2 status
#   ./provision.sh 3 --terminate      Terminate node 3
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ─── Load config ─────────────────────────────────────────────────────────────

CONFIG_FILE="${SCRIPT_DIR}/config.env"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "ERROR: config.env not found at $CONFIG_FILE"
    echo "  cp deploy/config.env.example deploy/config.env"
    exit 1
fi
source "$CONFIG_FILE"

# ─── Helpers ─────────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
warn()  { echo "  WARN: $*"; }
die()   { echo "  ERROR: $*" >&2; exit 1; }

node_region() {
    case "$1" in
        1) echo "$NODE1_REGION" ;;
        2) echo "$NODE2_REGION" ;;
        3) echo "$NODE3_REGION" ;;
        *) die "Invalid node: $1" ;;
    esac
}

node_key_name() {
    case "$1" in
        1) echo "$NODE1_KEY_NAME" ;;
        2) echo "$NODE2_KEY_NAME" ;;
        3) echo "$NODE3_KEY_NAME" ;;
        *) die "Invalid node: $1" ;;
    esac
}

node_s3_bucket() {
    case "$1" in
        1) echo "$NODE1_S3_BUCKET" ;;
        2) echo "$NODE2_S3_BUCKET" ;;
        3) echo "$NODE3_S3_BUCKET" ;;
        *) die "Invalid node: $1" ;;
    esac
}

# ─── Find running instance by tag ────────────────────────────────────────────

find_instance() {
    local n="$1"
    local region
    region=$(node_region "$n")
    aws ec2 describe-instances --region "$region" \
        --filters "Name=tag:Name,Values=toprf-node-${n}" \
                  "Name=instance-state-name,Values=pending,running,stopping,stopped" \
        --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null
}

# ─── Provision a single node ─────────────────────────────────────────────────

provision_node() {
    local n="$1"
    local region key_name instance_type
    region=$(node_region "$n")
    key_name=$(node_key_name "$n")
    instance_type="${INSTANCE_TYPE:-c6a.large}"

    info "Provisioning node $n in $region"

    # Check for existing instance
    local existing
    existing=$(find_instance "$n")
    if [[ -n "$existing" && "$existing" != "None" && "$existing" != "null" ]]; then
        echo "  Instance already exists: $existing"
        echo "  Terminate it first with: ./provision.sh $n --terminate"
        return 1
    fi

    # Create EC2 key pair if it doesn't exist
    local key_file="${SCRIPT_DIR}/${key_name}.pem"
    if ! aws ec2 describe-key-pairs --region "$region" --key-names "$key_name" > /dev/null 2>&1; then
        echo "  Creating EC2 key pair: $key_name..."
        aws ec2 create-key-pair --region "$region" \
            --key-name "$key_name" \
            --key-type ed25519 \
            --query 'KeyMaterial' --output text > "$key_file"
        chmod 600 "$key_file"
        echo "  Key saved to: $key_file"
    else
        echo "  Key pair $key_name already exists in $region"
        if [[ ! -f "$key_file" ]]; then
            warn "Key pair exists but $key_file not found locally — you may not be able to SSH"
        fi
    fi

    # Find latest Amazon Linux 2023 AMI
    echo "  Finding latest AL2023 AMI..."
    local ami
    ami=$(aws ec2 describe-images --region "$region" \
        --owners amazon \
        --filters "Name=name,Values=al2023-ami-*-x86_64" \
                  "Name=state,Values=available" \
        --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)

    [[ -n "$ami" && "$ami" != "None" ]] || die "No AL2023 AMI found in $region"
    echo "  AMI: $ami"

    # Launch instance
    echo "  Launching $instance_type with SEV-SNP..."
    local instance_id
    instance_id=$(aws ec2 run-instances --region "$region" \
        --instance-type "$instance_type" \
        --image-id "$ami" \
        --key-name "$key_name" \
        --cpu-options AmdSevSnp=enabled \
        --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=50,VolumeType=gp3}' \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=toprf-node-${n}}]" \
        --query 'Instances[0].InstanceId' --output text)

    echo "  Instance: $instance_id"

    # Wait for running state
    echo "  Waiting for instance to be running..."
    aws ec2 wait instance-running --region "$region" --instance-ids "$instance_id"

    # Set IMDS hop limit to 2 (required for Docker containers to reach IMDS)
    echo "  Setting IMDS hop limit to 2..."
    aws ec2 modify-instance-metadata-options \
        --region "$region" \
        --instance-id "$instance_id" \
        --http-put-response-hop-limit 2 > /dev/null

    # Open SSH from the caller's public IP
    local my_ip sg_id_inst
    my_ip=$(curl -s https://checkip.amazonaws.com)
    sg_id_inst=$(aws ec2 describe-instances --region "$region" \
        --instance-ids "$instance_id" \
        --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text)
    if [[ -n "$my_ip" && -n "$sg_id_inst" && "$sg_id_inst" != "None" ]]; then
        echo "  Opening SSH from $my_ip..."
        aws ec2 authorize-security-group-ingress --region "$region" \
            --group-id "$sg_id_inst" --protocol tcp --port 22 \
            --cidr "${my_ip}/32" 2>/dev/null \
            || warn "SSH rule may already exist"
    fi

    # Attach IAM instance profile if configured
    local iam_profile="${IAM_INSTANCE_PROFILE:-}"
    if [[ -n "$iam_profile" ]]; then
        echo "  Attaching IAM instance profile: $iam_profile..."
        aws ec2 associate-iam-instance-profile \
            --region "$region" \
            --instance-id "$instance_id" \
            --iam-instance-profile "Name=$iam_profile" > /dev/null
    else
        warn "IAM_INSTANCE_PROFILE not set — attach manually for S3 access"
    fi

    # Fetch IPs
    local instance_data
    instance_data=$(aws ec2 describe-instances --region "$region" \
        --instance-ids "$instance_id" \
        --query 'Reservations[0].Instances[0]' --output json)

    local pub_ip priv_ip sg_id vpc_id
    pub_ip=$(echo "$instance_data" | jq -r '.PublicIpAddress // "pending"')
    priv_ip=$(echo "$instance_data" | jq -r '.PrivateIpAddress // "pending"')
    sg_id=$(echo "$instance_data" | jq -r '.SecurityGroups[0].GroupId // empty')
    vpc_id=$(echo "$instance_data" | jq -r '.VpcId // empty')

    echo ""
    echo "  Node $n provisioned:"
    echo "    Instance:   $instance_id"
    echo "    Region:     $region"
    echo "    Public IP:  $pub_ip"
    echo "    Private IP: $priv_ip"
    echo "    SG:         $sg_id"
    echo "    VPC:        $vpc_id"
    echo ""
    echo "  Next steps:"
    echo "    1. Update config.env (or run ./deploy.sh auto-config)"
    echo "    2. Run ./deploy.sh --nodes $n pre-seal"
    echo "    3. Run ./deploy.sh --nodes $n init-seal"
    echo "    4. Run ./deploy.sh --nodes $n post-seal"
}

# ─── Show node status ────────────────────────────────────────────────────────

show_status() {
    local n="$1"
    local region
    region=$(node_region "$n")

    info "Node $n status ($region)"

    local result
    result=$(aws ec2 describe-instances --region "$region" \
        --filters "Name=tag:Name,Values=toprf-node-${n}" \
        --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,Type:InstanceType,PublicIp:PublicIpAddress,PrivateIp:PrivateIpAddress,LaunchTime:LaunchTime}' \
        --output table 2>/dev/null) || true

    if [[ -n "$result" ]]; then
        echo "$result"
    else
        echo "  No instances found with tag toprf-node-${n}"
    fi
}

# ─── Terminate node ──────────────────────────────────────────────────────────

terminate_node() {
    local n="$1"
    local region
    region=$(node_region "$n")

    local instance_id
    instance_id=$(find_instance "$n")

    if [[ -z "$instance_id" || "$instance_id" == "None" || "$instance_id" == "null" ]]; then
        echo "  No running instance found for node $n in $region"
        return 0
    fi

    info "Terminating node $n: $instance_id ($region)"
    echo "  Press Enter to confirm, or Ctrl-C to abort:"
    read -r _ < /dev/tty

    aws ec2 terminate-instances --region "$region" --instance-ids "$instance_id" > /dev/null
    echo "  Terminated: $instance_id"

    # Optionally clear sealed blob
    local bucket
    bucket=$(node_s3_bucket "$n")
    if [[ -n "$bucket" ]]; then
        echo "  Clearing sealed blob from s3://${bucket}..."
        aws s3 rm "s3://${bucket}/node-${n}-sealed.bin" --region "$region" 2>/dev/null || true
    fi

    echo "  Done."
}

# ─── CLI ─────────────────────────────────────────────────────────────────────

usage() {
    cat <<'EOF'
Usage: provision.sh <node> [action]

Arguments:
  node              Node number (1, 2, 3) or "all"

Actions:
  (default)         Launch a new VM
  --status          Show instance status
  --terminate       Terminate the instance and clear sealed blob

Examples:
  ./provision.sh 1                  Launch node 1
  ./provision.sh all                Launch all 3 nodes
  ./provision.sh 2 --status         Check node 2
  ./provision.sh 3 --terminate      Tear down node 3
EOF
}

if [[ $# -eq 0 || "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
    usage
    exit 0
fi

NODE="$1"
ACTION="${2:---provision}"

case "$NODE" in
    1|2|3)
        case "$ACTION" in
            --provision) provision_node "$NODE" ;;
            --status)    show_status "$NODE" ;;
            --terminate) terminate_node "$NODE" ;;
            *) die "Unknown action: $ACTION" ;;
        esac
        ;;
    all)
        case "$ACTION" in
            --provision)
                for n in 1 2 3; do
                    provision_node "$n"
                    echo ""
                done
                ;;
            --status)
                for n in 1 2 3; do
                    show_status "$n"
                    echo ""
                done
                ;;
            --terminate)
                for n in 1 2 3; do
                    terminate_node "$n"
                    echo ""
                done
                ;;
            *) die "Unknown action: $ACTION" ;;
        esac
        ;;
    *)
        die "Invalid node: $NODE (expected 1, 2, 3, or all)"
        ;;
esac
