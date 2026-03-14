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
#   ./provision.sh all                Launch all nodes
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

# ─── Load nodes.json ────────────────────────────────────────────────────────

NODES_JSON="${NODES_JSON:-${SCRIPT_DIR}/nodes.json}"
if [[ ! -f "$NODES_JSON" ]]; then
    echo "ERROR: nodes.json not found at $NODES_JSON"
    echo "  cp deploy/nodes.json.example deploy/nodes.json"
    exit 1
fi
command -v jq >/dev/null || { echo "ERROR: jq is required but not installed" >&2; exit 1; }

_vm_tag() { echo "toprf-node-${1}${_STAGING_SUFFIX:-}"; }

# ─── Helpers ─────────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
warn()  { echo "  WARN: $*"; }
die()   { echo "  ERROR: $*" >&2; exit 1; }

# Node lookup helpers (read from nodes.json)
_node_field() {
    local id="$1" field="$2"
    local val
    val=$(jq -r --argjson id "$id" ".nodes[] | select(.id == \$id) | .$field // empty" "$NODES_JSON")
    echo "$val"
}

node_region()    { _node_field "$1" region; }
node_key_name()  { _node_field "$1" key_name; }
node_s3_bucket() { _node_field "$1" s3_bucket; }
node_ssh_key()   { _node_field "$1" ssh_key; }

# All node IDs from nodes.json
all_node_ids() { jq -r '.nodes[].id' "$NODES_JSON" | tr '\n' ' '; }

# ─── Ensure IAM instance profile exists ─────────────────────────────────────

ensure_iam_profile_for_node() {
    local n="$1"
    local bucket
    bucket=$(node_s3_bucket "$n" 2>/dev/null) || return 1
    [[ -n "$bucket" ]] || return 1

    local role_name="toprf-node-${n}-role"
    local profile_name="toprf-node-${n}-profile"

    # Create per-node role if it doesn't exist
    if ! aws iam get-role --role-name "$role_name" > /dev/null 2>&1; then
        echo "  Creating IAM role: $role_name..."
        aws iam create-role --role-name "$role_name" \
            --assume-role-policy-document '{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }' > /dev/null

        # Grant S3 access scoped to ONLY this node's bucket
        aws iam put-role-policy --role-name "$role_name" \
            --policy-name "sealed-s3-access" \
            --policy-document "{
                \"Version\": \"2012-10-17\",
                \"Statement\": [{
                    \"Effect\": \"Allow\",
                    \"Action\": [\"s3:GetObject\", \"s3:PutObject\"],
                    \"Resource\": [\"arn:aws:s3:::${bucket}/*\"]
                }]
            }"
        echo "  S3 policy attached: $bucket"

    else
        echo "  IAM role $role_name already exists"
    fi

    # Attach SSM managed policy for automated rotation via Lambda (idempotent)
    aws iam attach-role-policy --role-name "$role_name" \
        --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore" 2>/dev/null || true

    # Create instance profile if it doesn't exist
    if ! aws iam get-instance-profile --instance-profile-name "$profile_name" > /dev/null 2>&1; then
        echo "  Creating instance profile: $profile_name..."
        aws iam create-instance-profile --instance-profile-name "$profile_name" > /dev/null
        aws iam add-role-to-instance-profile \
            --instance-profile-name "$profile_name" \
            --role-name "$role_name"
        echo "  Waiting for instance profile to propagate..."
        aws iam wait instance-profile-exists --instance-profile-name "$profile_name" 2>/dev/null || true
        # Verify the profile is actually available (IAM is eventually consistent)
        local _iam_attempts=0
        while true; do
            if aws iam get-instance-profile --instance-profile-name "$profile_name" > /dev/null 2>&1; then
                break
            fi
            _iam_attempts=$((_iam_attempts + 1))
            if [[ $_iam_attempts -ge 15 ]]; then
                echo "  WARNING: Instance profile $profile_name may not be fully propagated"
                break
            fi
            sleep 2
        done
    else
        echo "  Instance profile $profile_name already exists"
    fi
}

# ─── Find running instance by tag ────────────────────────────────────────────

find_instance() {
    local n="$1"
    local region tag
    region=$(node_region "$n")
    tag=$(_vm_tag "$n")
    aws ec2 describe-instances --region "$region" \
        --filters "Name=tag:Name,Values=${tag}" \
                  "Name=instance-state-name,Values=pending,running,stopping,stopped" \
        --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null
}

# ─── Provision a single node ─────────────────────────────────────────────────

_auto_fill_node_defaults() {
    # Auto-generate key_name, s3_bucket, ssh_key if empty in nodes.json
    local n="$1"
    local needs_update=false
    local tmp

    local kn
    kn=$(node_key_name "$n")
    if [[ -z "$kn" ]]; then
        kn="toprf-node-${n}-key"
        needs_update=true
    fi

    local bucket
    bucket=$(node_s3_bucket "$n")
    if [[ -z "$bucket" ]]; then
        # Include account ID for global uniqueness
        local acct
        acct=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) \
            || die "Cannot determine AWS account ID — check credentials"
        bucket="toprf-sealed-${acct}-node-${n}"
        needs_update=true
    fi

    local ssh_key_path
    ssh_key_path=$(node_ssh_key "$n")
    if [[ -z "$ssh_key_path" ]]; then
        ssh_key_path="${SCRIPT_DIR}/${kn}.pem"
        needs_update=true
    fi

    if $needs_update; then
        echo "  Auto-filling defaults for node $n: key_name=$kn s3_bucket=$bucket"
        tmp=$(mktemp) || die "mktemp failed"
        jq --argjson id "$n" \
           --arg kn "$kn" --arg bucket "$bucket" --arg ssh "$ssh_key_path" \
           '(.nodes[] | select(.id == $id)) |= . + {key_name: $kn, s3_bucket: $bucket, ssh_key: $ssh}' \
           "$NODES_JSON" > "$tmp" || { rm -f "$tmp"; die "jq failed updating nodes.json"; }
        jq . "$tmp" > /dev/null 2>&1 || { rm -f "$tmp"; die "jq produced invalid JSON"; }
        mv "$tmp" "$NODES_JSON" || { rm -f "$tmp"; die "mv failed updating nodes.json"; }
    fi
}

# Staging-aware naming: used during rotation to provision a new instance
# alongside the existing node. Sets _STAGING_KEY_NAME and _STAGING_SEALED_PATH.
_staging_names() {
    local n="$1"
    _STAGING_KEY_NAME="toprf-node-${n}-staging-key"
    _STAGING_SEALED_PATH="node-${n}-staging-sealed.bin"
}

provision_node() {
    local n="$1"
    local region key_name instance_type
    local is_staging="${_STAGING:-false}"

    # Auto-fill key_name, s3_bucket, ssh_key if empty
    _auto_fill_node_defaults "$n"

    region=$(node_region "$n")
    instance_type="${INSTANCE_TYPE:-c6a.large}"

    # Use staging key name if in staging mode, otherwise use the node's key
    if $is_staging; then
        _staging_names "$n"
        key_name="$_STAGING_KEY_NAME"
        info "Provisioning STAGING node $n in $region"
    else
        key_name=$(node_key_name "$n")
        info "Provisioning node $n in $region"
    fi

    # Ensure per-node IAM role + instance profile exist (idempotent)
    # Staging reuses the same IAM role (same S3 bucket permissions)
    ensure_iam_profile_for_node "$n"

    # Check for existing instance with the same tag
    local existing
    existing=$(find_instance "$n")
    if [[ -n "$existing" && "$existing" != "None" && "$existing" != "null" ]]; then
        if $is_staging; then
            echo "  Staging instance already exists: $existing"
            echo "  Terminate it first with: ./provision.sh $n --terminate-staging"
        else
            echo "  Instance already exists: $existing"
            echo "  Terminate it first with: ./provision.sh $n --terminate"
        fi
        return 1
    fi

    # Create EC2 key pair if it doesn't exist
    local key_file="${SCRIPT_DIR}/${key_name}.pem"
    if ! aws ec2 describe-key-pairs --region "$region" --key-names "$key_name" > /dev/null 2>&1; then
        echo "  Creating EC2 key pair: $key_name..."
        aws ec2 create-key-pair --region "$region" \
            --key-name "$key_name" \
            --key-type ed25519 \
            --tag-specifications "ResourceType=key-pair,Tags=[{Key=Project,Value=toprf}]" \
            --query 'KeyMaterial' --output text > "$key_file"
        chmod 600 "$key_file"
        echo "  Key saved to: $key_file"
    else
        echo "  Key pair $key_name already exists in $region"
        if [[ ! -f "$key_file" ]]; then
            warn "Key pair exists but $key_file not found locally — you may not be able to SSH"
        fi
    fi

    # Find latest Amazon Linux 2023 AMI (pinned at deploy time)
    echo "  Finding latest AL2023 AMI..."
    local ami
    ami=$(aws ec2 describe-images --region "$region" \
        --owners amazon \
        --filters "Name=name,Values=al2023-ami-*-x86_64" \
                  "Name=state,Values=available" \
        --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)

    [[ -n "$ami" && "$ami" != "None" ]] || die "No AL2023 AMI found in $region"
    echo "  AMI: $ami"

    # Save AMI ID to nodes.json so Lambda reuses the same AMI
    local tmp
    tmp=$(mktemp) || die "mktemp failed"
    jq --argjson id "$n" --arg ami "$ami" \
       '(.nodes[] | select(.id == $id)) |= . + {ami_id: $ami}' \
       "$NODES_JSON" > "$tmp" || { rm -f "$tmp"; die "jq failed updating nodes.json"; }
    jq . "$tmp" > /dev/null 2>&1 || { rm -f "$tmp"; die "jq produced invalid JSON"; }
    mv "$tmp" "$NODES_JSON" || { rm -f "$tmp"; die "mv failed updating nodes.json"; }

    # Launch instance
    echo "  Launching $instance_type with SEV-SNP..."
    local instance_id
    instance_id=$(aws ec2 run-instances --region "$region" \
        --instance-type "$instance_type" \
        --image-id "$ami" \
        --key-name "$key_name" \
        --cpu-options AmdSevSnp=enabled \
        --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=50,VolumeType=gp3}' \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$(_vm_tag "$n")},{Key=Project,Value=toprf}]" \
        --query 'Instances[0].InstanceId' --output text)

    echo "  Instance: $instance_id"

    # Wait for instance to be fully initialized
    echo "  Waiting for instance to be running..."
    aws ec2 wait instance-running --region "$region" --instance-ids "$instance_id"
    echo "  Waiting for instance status checks..."
    aws ec2 wait instance-status-ok --region "$region" --instance-ids "$instance_id"

    # Set IMDS hop limit to 2 (required for Docker containers to reach IMDS)
    echo "  Setting IMDS hop limit to 2..."
    aws ec2 modify-instance-metadata-options \
        --region "$region" \
        --instance-id "$instance_id" \
        --http-put-response-hop-limit 2 > /dev/null
    # Verify the change took effect (retry if needed)
    local _hop_limit _hop_attempts=0
    while true; do
        _hop_limit=$(aws ec2 describe-instances --region "$region" \
            --instance-ids "$instance_id" \
            --query 'Reservations[0].Instances[0].MetadataOptions.HttpPutResponseHopLimit' --output text 2>/dev/null)
        [[ "$_hop_limit" == "2" ]] && break
        _hop_attempts=$((_hop_attempts + 1))
        if [[ $_hop_attempts -ge 5 ]]; then
            warn "IMDS hop limit may not have applied (got: $_hop_limit) — Docker containers may fail to reach IMDS"
            break
        fi
        sleep 2
    done

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

    # Attach per-node IAM instance profile
    local node_profile="toprf-node-${n}-profile"
    echo "  Attaching IAM instance profile: ${node_profile}..."
    aws ec2 associate-iam-instance-profile \
        --region "$region" \
        --instance-id "$instance_id" \
        --iam-instance-profile "Name=${node_profile}" > /dev/null

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
    if $is_staging; then
        echo "  STAGING node $n provisioned:"
    else
        echo "  Node $n provisioned:"
    fi
    echo "    Instance:   $instance_id"
    echo "    Region:     $region"
    echo "    Key pair:   $key_name"
    echo "    Public IP:  $pub_ip"
    echo "    Private IP: $priv_ip"
    echo "    SG:         $sg_id"
    echo "    VPC:        $vpc_id"
    echo ""
    if $is_staging; then
        echo "  Next steps:"
        echo "    1. Run ./deploy.sh rotate $n   (reshare → verify → swap → cleanup)"
    else
        echo "  Next steps:"
        echo "    1. Run ./deploy.sh auto-config (or update nodes.json manually)"
        echo "    2. Run ./deploy.sh --nodes $n pre-seal"
        echo "    3. Run ./deploy.sh --nodes $n init-seal"
        echo "    4. Run ./deploy.sh --nodes $n post-seal"
    fi
}

# ─── Show node status ────────────────────────────────────────────────────────

show_status() {
    local n="$1"
    local region
    region=$(node_region "$n")

    info "Node $n status ($region)"

    local result
    local tag
    tag=$(_vm_tag "$n")
    result=$(aws ec2 describe-instances --region "$region" \
        --filters "Name=tag:Name,Values=${tag}" \
        --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,Type:InstanceType,PublicIp:PublicIpAddress,PrivateIp:PrivateIpAddress,LaunchTime:LaunchTime}' \
        --output table 2>/dev/null) || true

    if [[ -n "$result" ]]; then
        echo "$result"
    else
        echo "  No instances found with tag ${tag}"
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

    # Clear sealed blob (staging or permanent depending on which is being terminated)
    local bucket
    bucket=$(node_s3_bucket "$n")
    if [[ -n "$bucket" ]]; then
        if [[ "${_STAGING:-false}" == "true" ]]; then
            _staging_names "$n"
            echo "  Clearing staging sealed blob from s3://${bucket}..."
            aws s3 rm "s3://${bucket}/${_STAGING_SEALED_PATH}" --region "$region" 2>/dev/null || true
            # Clean up staging key pair
            aws ec2 delete-key-pair --region "$region" --key-name "$_STAGING_KEY_NAME" 2>/dev/null || true
            rm -f "${SCRIPT_DIR}/${_STAGING_KEY_NAME}.pem"
            echo "  Deleted staging key pair: $_STAGING_KEY_NAME"
            # Clean up reshare artifacts
            aws s3 rm "s3://${bucket}/reshare/" --recursive --region "$region" 2>/dev/null || true
        else
            echo "  Clearing sealed blob from s3://${bucket}..."
            aws s3 rm "s3://${bucket}/node-${n}-sealed.bin" --region "$region" 2>/dev/null || true
        fi
    fi

    echo "  Done."
}

# ─── CLI ─────────────────────────────────────────────────────────────────────

usage() {
    local valid_ids
    valid_ids=$(jq -r '[.nodes[].id] | join(", ")' "$NODES_JSON" 2>/dev/null || echo "?")
    cat <<EOF
Usage: provision.sh <node> [action]

Arguments:
  node              Node ID (${valid_ids}) or "all"

Actions:
  (default)           Launch a new VM
  --staging           Launch a staging VM for rotation (alongside existing node)
  --status            Show instance status
  --terminate         Terminate the instance and clear sealed blob
  --terminate-staging Terminate the staging instance and clear staging artifacts

Examples:
  ./provision.sh 1                    Launch node 1
  ./provision.sh all                  Launch all nodes
  ./provision.sh 2 --status           Check node 2
  ./provision.sh 3 --terminate        Tear down node 3
  ./provision.sh 1 --staging          Provision staging node for rotation
  ./provision.sh 1 --terminate-staging Abort rotation, clean up staging
EOF
}

# Check if a node ID exists in nodes.json
_valid_node_id() {
    jq -e --argjson id "$1" '.nodes[] | select(.id == $id)' "$NODES_JSON" > /dev/null 2>&1
}

if [[ $# -eq 0 || "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
    usage
    exit 0
fi

NODE="$1"
ACTION="${2:---provision}"

if [[ "$NODE" == "all" ]]; then
    case "$ACTION" in
        --provision)
            for n in $(all_node_ids); do
                provision_node "$n"
                echo ""
            done
            ;;
        --status)
            for n in $(all_node_ids); do
                show_status "$n"
                echo ""
            done
            ;;
        --terminate)
            for n in $(all_node_ids); do
                terminate_node "$n"
                echo ""
            done
            ;;
        *) die "Unknown action: $ACTION" ;;
    esac
elif _valid_node_id "$NODE"; then
    case "$ACTION" in
        --provision) provision_node "$NODE" ;;
        --staging)
            _STAGING=true _STAGING_SUFFIX="-staging" provision_node "$NODE"
            ;;
        --status)    show_status "$NODE" ;;
        --terminate) terminate_node "$NODE" ;;
        --terminate-staging)
            _STAGING=true _STAGING_SUFFIX="-staging" terminate_node "$NODE"
            ;;
        *) die "Unknown action: $ACTION" ;;
    esac
else
    die "Invalid node: $NODE (valid IDs: $(jq -r '[.nodes[].id] | join(", ")' "$NODES_JSON"))"
fi
