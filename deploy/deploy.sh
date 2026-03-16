#!/usr/bin/env bash
# =============================================================================
# deploy.sh — Automated deployment for threshold OPRF nodes on AWS.
#
# Deploys TEE nodes (Amazon Linux 2023) across AWS regions. Node count and
# threshold are defined in nodes.json. Each node can act as coordinator:
# receiving a client request, computing its own partial evaluation, calling
# (threshold-1) peer nodes via PrivateLink, verifying DLEQ proofs, and
# returning the combined OPRF evaluation.
#
# Architecture:
#   Client → API Gateway → NLB → Coordinator Node → PrivateLink → Peer Node
#
# Node-to-node communication:
#   Same-VPC peers use internal NLB DNS directly.
#   Cross-VPC peers use AWS PrivateLink (Endpoint Service + Interface VPC
#   Endpoints in the consumer VPC).
#
# Usage:
#   ./deploy.sh <step> [step...]
#   ./deploy.sh all                  # Full deployment
#   ./deploy.sh pre-seal             # Everything before init-seal
#   ./deploy.sh init-seal            # Interactive key injection
#   ./deploy.sh post-seal            # Everything after init-seal
#   ./deploy.sh verify               # Health check
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Show help without requiring config
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
    cat <<'EOF'
Usage: deploy.sh [--nodes 1,2,3] <step> [step...]

Options:
  --nodes N     Operate on specific node(s) only (comma-separated)

Steps (run in order for fresh deployment):
  setup-vms     Install Docker on VMs
  pull          Pull node image from ghcr.io on each VM
  storage       Create S3 buckets for sealed key blobs
  measure       Fetch SEV-SNP measurement from a running node (saves to config.env)
  init-seal     S3-mediated ECIES key injection (attested)
  privatelink   Create NLBs, Endpoint Services, cross-VPC VPC Endpoints
  coordinator-config  Generate per-node coordinator configs (peer endpoints)
  start         Start nodes in coordinator mode (unseal + serve)
  verify        Health check all nodes (via SSH)
  e2e           End-to-end verify: OPRF evaluate via coordinator
  cloudwatch    Create CloudWatch alarms for unhealthy node detection
  frontend-nlb  Create frontend NLB targeting same-region nodes (Lambda failover)

Rotation:
  rotate <N>    Zero-downtime node replacement (staging-based reshare)
                Requires: ./provision.sh <N> --staging first

Utilities:
  auto-config   Auto-populate nodes.json from AWS
  show-ips      Fetch public/private IPs for all nodes
  lambda-config Auto-generate lambda/config.env from deployment state
  sync-state    Push local state to SSM Parameter Store (for rotation Lambda)
  lock          Remove SSH access + delete keys (irreversible)

Shortcuts:
  pre-seal      setup-vms → pull → storage → measure
  post-seal     privatelink → coordinator-config → start → verify → frontend-nlb
  all           pre-seal → init-seal → post-seal
  redeploy      pull latest image → restart nodes
EOF
    exit 0
fi

# ─── Load config ─────────────────────────────────────────────────────────────

CONFIG_FILE="${SCRIPT_DIR}/config.env"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "ERROR: config.env not found at $CONFIG_FILE"
    echo "  cp deploy/config.env.example deploy/config.env"
    echo "  # then fill in your values"
    exit 1
fi
source "$CONFIG_FILE"

# ─── Load nodes.json ────────────────────────────────────────────────────────

NODES_JSON="${NODES_JSON:-${SCRIPT_DIR}/nodes.json}"
if [[ ! -f "$NODES_JSON" ]]; then
    die "nodes.json not found at $NODES_JSON. Copy nodes.json.example and fill in values."
fi
command -v jq >/dev/null || die "jq is required but not installed"

# ─── Derived values ──────────────────────────────────────────────────────────

NODE_IMAGE="${NODE_IMAGE:-ghcr.io/${GHCR_OWNER:-jeganggs64}/toprf-node:latest}"

# ─── Resource naming ──────────────────────────────────────────────────────────

vm_tag()         { echo "toprf-node-${1}"; }
nlb_name()       { echo "toprf-node-${1}-nlb"; }
tg_name()        { echo "toprf-node-${1}-tg"; }
vpce_sg_name()   { echo "toprf-privatelink-vpce-${1}"; }
pl_state_file()  { echo "${SCRIPT_DIR}/privatelink-state.env"; }
coord_config_dir() { echo "${SCRIPT_DIR}/coordinator-configs"; }

project_tags() {
    echo "Key=Project,Value=toprf"
}

# ─── Helpers ─────────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
warn()  { echo "  WARN: $*"; }
die()   { echo "  ERROR: $*" >&2; exit 1; }

# ─── Node lookup helpers (read from nodes.json) ─────────────────────────────

_node_field() {
    local id="$1" field="$2"
    local val
    val=$(jq -r --argjson id "$id" ".nodes[] | select(.id == \$id) | .$field // empty" "$NODES_JSON")
    echo "$val"
}

node_region()     { _node_field "$1" region; }
node_ip()         { _node_field "$1" ip; }
node_private_ip() { _node_field "$1" private_ip; }
node_ssh_key()    { _node_field "$1" ssh_key; }
node_sg_id()      { _node_field "$1" sg_id; }
node_vpc_id()     { _node_field "$1" vpc_id; }
node_subnet_id()  { _node_field "$1" subnet_id; }
node_s3_bucket()  { _node_field "$1" s3_bucket; }
node_key_name()   { _node_field "$1" key_name; }

# Convert VPC ID to variable-safe identifier: vpc-0abc → vpc_0abc
vpc_ident() { echo "${1//-/_}"; }

sealed_url() {
    local bucket
    bucket=$(node_s3_bucket "$1")
    echo "s3://${bucket}/node-${1}-sealed.bin"
}

# All node IDs from nodes.json
all_node_ids() { jq -r '.nodes[].id' "$NODES_JSON" | tr '\n' ' '; }

# Node filter: set via --nodes flag (e.g. --nodes 1,3)
_NODE_FILTER=""

active_nodes() {
    if [[ -n "$_NODE_FILTER" ]]; then
        echo "$_NODE_FILTER"
        return
    fi
    all_node_ids
}

# Unique regions across all nodes
all_regions() {
    jq -r '[.nodes[].region] | unique | .[]' "$NODES_JSON"
}

ssh_node() {
    local n="$1"; shift
    local key ip
    key=$(node_ssh_key "$n")
    ip=$(node_ip "$n")
    ssh -o StrictHostKeyChecking=accept-new -i "$key" "ec2-user@${ip}" "$*"
}

scp_to_node() {
    local n="$1"; shift
    local key ip
    key=$(node_ssh_key "$n")
    ip=$(node_ip "$n")
    scp -o StrictHostKeyChecking=accept-new -i "$key" "$@" "ec2-user@${ip}:/tmp/"
}

# Load node shares data from public-config.json
_ceremony_loaded=false
load_ceremony() {
    if $_ceremony_loaded; then return; fi
    local config="${NODE_SHARES_DIR}/public-config.json"
    [[ -f "$config" ]] || die "$config not found. Run toprf-keygen node-shares first."
    GROUP_PUBLIC_KEY=$(jq -r '.group_public_key' "$config")
    CEREMONY_THRESHOLD=$(jq -r '.threshold' "$config")
    _ceremony_loaded=true
}

node_vs() {
    load_ceremony
    local config="${NODE_SHARES_DIR}/public-config.json"
    jq -r --argjson id "$1" '.verification_shares[] | select(.node_id == $id) | .verification_share' "$config"
}

# Validate that the number of active nodes meets the threshold requirement
validate_threshold() {
    load_ceremony
    local count=0
    for _ in $(active_nodes); do count=$((count + 1)); done
    if [[ "$count" -lt "$CEREMONY_THRESHOLD" ]]; then
        die "Only $count active node(s) but threshold is $CEREMONY_THRESHOLD. Need at least $CEREMONY_THRESHOLD nodes."
    fi
}

# =============================================================================
# Steps
# =============================================================================

# ─── 1. Pull Docker image ────────────────────────────────────────────────────

step_pull() {
    echo ""
    info "Pulling node image on each VM: ${NODE_IMAGE}"

    for i in $(active_nodes); do
        local ip
        ip=$(node_ip "$i")
        echo "  Node $i ($ip)..."
        if ! ssh_node "$i" "sudo docker pull ${NODE_IMAGE}" < /dev/null; then
            die "Docker pull failed on node $i ($ip). Check image name and registry credentials."
        fi
    done

    echo "  Done."
}

# ─── 2. Create S3 storage buckets ────────────────────────────────────────────

step_storage() {
    echo ""
    info "Creating S3 buckets for sealed key blobs"

    for i in $(active_nodes); do
        local bucket region
        bucket=$(node_s3_bucket "$i")
        region=$(node_region "$i")
        echo "  Node $i: s3://${bucket} ($region)"
        # Check if bucket already exists (owned by us)
        if aws s3api head-bucket --bucket "$bucket" 2>/dev/null; then
            echo "    Bucket already exists."
        else
            if ! aws s3 mb "s3://${bucket}" --region "$region"; then
                die "Failed to create S3 bucket ${bucket} in ${region}. Check permissions and bucket name availability."
            fi
        fi
    done

    echo "  Done."
}

# ─── 3. Setup VMs (Docker) ───────────────────────────────────────────────────

step_setup_vms() {
    echo ""
    info "Setting up VMs (Docker)"

    for i in $(active_nodes); do
        local ip
        ip=$(node_ip "$i")
        echo "  Node $i ($ip)..."

        ssh_node "$i" "$(cat <<'SETUP'
set -e
if ! command -v docker &>/dev/null; then
    echo "    Installing Docker..."
    sudo dnf install -y docker
    sudo systemctl enable docker
    sudo systemctl start docker
    sudo usermod -aG docker $USER
else
    echo "    Docker already installed."
fi
echo "    Done."
SETUP
)" < /dev/null
    done

    echo "  Done."
}

# ─── 4. AWS PrivateLink (NLBs + Endpoint Services + VPC Endpoints) ──────────
#
# Architecture: node-to-node PrivateLink for coordinator mode.
#
#   Same-VPC peers (e.g. nodes 1↔2 in eu-west-1): reachable via internal
#   NLB DNS directly — no PrivateLink needed.
#
#   Cross-VPC peers (e.g. nodes 1,2 ↔ node 3): reachable via Interface
#   VPC Endpoints in the consumer VPC connecting to the provider's
#   Endpoint Service.
#
# Creates per node:  NLB → Target Group → Listener → Endpoint Service
# Creates per cross-VPC pair:  Security Group + Interface VPC Endpoint

step_privatelink() {
    echo ""
    info "Setting up AWS PrivateLink (node-to-node)"

    local pl_state
    pl_state=$(pl_state_file)

    # Load existing state for idempotency
    [[ -f "$pl_state" ]] && source "$pl_state"

    # ── Phase 1: Per-node NLB + Target Group + Listener + Endpoint Service ──

    for i in $(active_nodes); do
        local region vpc_id subnet_id private_ip
        region=$(node_region "$i")
        vpc_id=$(node_vpc_id "$i")
        subnet_id=$(node_subnet_id "$i")
        private_ip=$(node_private_ip "$i")

        [[ -n "$subnet_id" ]] || die "subnet_id not set for node $i in nodes.json. Run auto-config or set manually."

        echo ""
        echo "  ━━━ Node $i ($region, $private_ip) ━━━"

        # ── 1. Network Load Balancer ──
        local nlb_var="NLB_ARN_NODE${i}"
        local nlb_arn="${!nlb_var:-}"
        if [[ -z "$nlb_arn" ]]; then
            # NLB needs ≥2 AZs for cross-region PrivateLink
            local second_subnet
            second_subnet=$(aws ec2 describe-subnets --region "$region" \
                --filters "Name=vpc-id,Values=$vpc_id" \
                --query "Subnets[?SubnetId!='${subnet_id}'] | [0].SubnetId" --output text)
            [[ -n "$second_subnet" && "$second_subnet" != "None" ]] || die "No second subnet found in VPC $vpc_id ($region). NLB requires ≥2 AZs."

            local _nlb_name
            _nlb_name=$(nlb_name "$i")
            echo "  Creating NLB $_nlb_name (2 AZs: $subnet_id, $second_subnet)..."
            nlb_arn=$(aws elbv2 create-load-balancer \
                --region "$region" \
                --name "$_nlb_name" \
                --type network \
                --scheme internal \
                --subnets "$subnet_id" "$second_subnet" \
                --query 'LoadBalancers[0].LoadBalancerArn' --output text)
            echo "${nlb_var}=${nlb_arn}" >> "$pl_state"
            aws elbv2 add-tags --region "$region" --resource-arns "$nlb_arn" \
                --tags $(project_tags) 2>/dev/null || true
            echo "    NLB: $nlb_arn"

            # Wait for NLB to be active before creating target groups / listeners
            echo "  Waiting for NLB to become active..."
            aws elbv2 wait load-balancer-available \
                --region "$region" \
                --load-balancer-arns "$nlb_arn" 2>/dev/null || true
            # Verify NLB is actually active (wait can exit early or silently fail)
            local _nlb_state
            _nlb_state=$(aws elbv2 describe-load-balancers --region "$region" \
                --load-balancer-arns "$nlb_arn" \
                --query 'LoadBalancers[0].State.Code' --output text 2>/dev/null)
            [[ "$_nlb_state" == "active" ]] || die "NLB $nlb_arn is not active (state: $_nlb_state)"
            echo "    NLB active."
        else
            echo "    NLB: $nlb_arn (exists)"
        fi

        # Save NLB DNS (needed for same-VPC peer resolution)
        local nlb_dns_var="NLB_DNS_NODE${i}"
        if [[ -z "${!nlb_dns_var:-}" ]]; then
            local nlb_dns
            nlb_dns=$(aws elbv2 describe-load-balancers --region "$region" \
                --load-balancer-arns "$nlb_arn" \
                --query 'LoadBalancers[0].DNSName' --output text)
            echo "${nlb_dns_var}=${nlb_dns}" >> "$pl_state"
            eval "${nlb_dns_var}=${nlb_dns}"
            echo "    NLB DNS: $nlb_dns"
        else
            echo "    NLB DNS: ${!nlb_dns_var} (exists)"
        fi

        # ── Ensure node SG allows port 3001 from its own VPC CIDR ──
        # NLB health checks and same-VPC peer traffic originate from within the VPC.
        local sg_id
        sg_id=$(node_sg_id "$i")
        local vpc_cidr
        vpc_cidr=$(aws ec2 describe-vpcs --region "$region" \
            --vpc-ids "$vpc_id" \
            --query 'Vpcs[0].CidrBlock' --output text)
        aws ec2 authorize-security-group-ingress \
            --region "$region" \
            --group-id "$sg_id" \
            --protocol tcp --port 3001 \
            --cidr "$vpc_cidr" 2>/dev/null \
            && echo "    SG: allowed TCP 3001 from $vpc_cidr" \
            || true  # rule may already exist

        # ── 2. Target Group ──
        local tg_var="PL_TG_ARN_NODE${i}"
        local tg_arn="${!tg_var:-}"
        if [[ -z "$tg_arn" ]]; then
            local _tg_name
            _tg_name=$(tg_name "$i")
            echo "  Creating Target Group $_tg_name..."
            tg_arn=$(aws elbv2 create-target-group \
                --region "$region" \
                --name "$_tg_name" \
                --protocol TCP --port 3001 \
                --vpc-id "$vpc_id" \
                --target-type ip \
                --health-check-protocol HTTP \
                --health-check-path /health \
                --health-check-interval-seconds 30 \
                --healthy-threshold-count 2 \
                --unhealthy-threshold-count 2 \
                --query 'TargetGroups[0].TargetGroupArn' --output text)
            echo "${tg_var}=${tg_arn}" >> "$pl_state"
            aws elbv2 add-tags --region "$region" --resource-arns "$tg_arn" \
                --tags $(project_tags) 2>/dev/null || true
            echo "    TG: $tg_arn"

            aws elbv2 register-targets --region "$region" \
                --target-group-arn "$tg_arn" \
                --targets "Id=${private_ip},Port=3001"
            echo "    Registered target: ${private_ip}:3001"
        else
            echo "    TG: $tg_arn (exists)"
        fi

        # ── Reconcile TG targets (handles IP changes after reprovisioning) ──
        local current_targets
        current_targets=$(aws elbv2 describe-target-health --region "$region" \
            --target-group-arn "$tg_arn" \
            --query 'TargetHealthDescriptions[*].Target.Id' --output text 2>/dev/null) || true
        # Deregister stale IPs, register current IP
        for old_ip in $current_targets; do
            if [[ "$old_ip" != "$private_ip" ]]; then
                aws elbv2 deregister-targets --region "$region" \
                    --target-group-arn "$tg_arn" \
                    --targets "Id=${old_ip},Port=3001" 2>/dev/null || true
                echo "    Deregistered stale target: ${old_ip}"
            fi
        done
        if [[ ! " $current_targets " =~ " $private_ip " ]]; then
            aws elbv2 register-targets --region "$region" \
                --target-group-arn "$tg_arn" \
                --targets "Id=${private_ip},Port=3001"
            echo "    Registered target: ${private_ip}:3001"
        fi

        # ── 3. NLB Listener ──
        local listener_var="NLB_LISTENER_NODE${i}"
        local listener_arn="${!listener_var:-}"
        if [[ -z "$listener_arn" ]]; then
            echo "  Creating NLB listener (TCP :3001)..."
            listener_arn=$(aws elbv2 create-listener \
                --region "$region" \
                --load-balancer-arn "$nlb_arn" \
                --protocol TCP --port 3001 \
                --default-actions "Type=forward,TargetGroupArn=${tg_arn}" \
                --query 'Listeners[0].ListenerArn' --output text)
            echo "${listener_var}=${listener_arn}" >> "$pl_state"
            echo "    Listener: $listener_arn"
        else
            echo "    Listener: exists"
        fi

        # ── 4. VPC Endpoint Service ──
        local svc_var="ENDPOINT_SVC_ID_NODE${i}"
        local svc_id="${!svc_var:-}"
        if [[ -z "$svc_id" ]]; then
            # Check if an endpoint service already exists for this NLB
            svc_id=$(aws ec2 describe-vpc-endpoint-service-configurations \
                --region "$region" \
                --query "ServiceConfigurations[?NetworkLoadBalancerArns[?contains(@, '${nlb_arn}')]].ServiceId | [0]" \
                --output text 2>/dev/null)
            if [[ -n "$svc_id" && "$svc_id" != "None" ]]; then
                echo "  Reusing existing VPC Endpoint Service: $svc_id"
                echo "${svc_var}=${svc_id}" >> "$pl_state"
            fi
        fi
        if [[ -z "$svc_id" || "$svc_id" == "None" ]]; then
            echo "  Creating VPC Endpoint Service..."
            svc_id=$(aws ec2 create-vpc-endpoint-service-configuration \
                --region "$region" \
                --network-load-balancer-arns "$nlb_arn" \
                --no-acceptance-required \
                --query 'ServiceConfiguration.ServiceId' --output text)
            echo "${svc_var}=${svc_id}" >> "$pl_state"
            aws ec2 create-tags --region "$region" --resources "$svc_id" \
                --tags $(project_tags) 2>/dev/null || true
            echo "    Endpoint Service: $svc_id"

            # Wait for endpoint service to be available before modifying
            echo "    Waiting for endpoint service to be available..."
            local svc_attempts=0
            while true; do
                local svc_state
                svc_state=$(aws ec2 describe-vpc-endpoint-service-configurations \
                    --region "$region" --service-ids "$svc_id" \
                    --query 'ServiceConfigurations[0].ServiceState' --output text 2>/dev/null)
                [[ "$svc_state" == "Available" ]] && break
                svc_attempts=$((svc_attempts + 1))
                [[ $svc_attempts -ge 30 ]] && die "Endpoint service $svc_id not available after 60 seconds"
                sleep 2
            done

            # Allow our AWS account to connect
            aws ec2 modify-vpc-endpoint-service-permissions \
                --region "$region" \
                --service-id "$svc_id" \
                --add-allowed-principals "arn:aws:iam::${AWS_ACCOUNT_ID}:root"
            echo "    Allowed principal: account ${AWS_ACCOUNT_ID}"

            # Add supported regions for cross-region consumers
            local added_regions=""
            for j in $(active_nodes); do
                [[ "$j" != "$i" ]] || continue
                local peer_vpc peer_region
                peer_vpc=$(node_vpc_id "$j")
                peer_region=$(node_region "$j")
                if [[ "$peer_vpc" != "$vpc_id" && "$peer_region" != "$region" ]]; then
                    if [[ ! " $added_regions " =~ " $peer_region " ]]; then
                        aws ec2 modify-vpc-endpoint-service-configuration \
                            --region "$region" \
                            --service-id "$svc_id" \
                            --add-supported-regions "$peer_region"
                        added_regions="$added_regions $peer_region"
                        echo "    Added supported region: $peer_region"
                    fi
                fi
            done
        else
            echo "    Endpoint Service: $svc_id (exists)"
            eval "${svc_var}='${svc_id}'"
        fi

        # Get the service name (needed to create VPC endpoints)
        local svc_name_var="ENDPOINT_SVC_NAME_NODE${i}"
        local svc_name="${!svc_name_var:-}"
        if [[ -z "$svc_name" ]]; then
            svc_name=$(aws ec2 describe-vpc-endpoint-service-configurations \
                --region "$region" \
                --service-ids "$svc_id" \
                --query 'ServiceConfigurations[0].ServiceName' --output text)
            echo "${svc_name_var}=${svc_name}" >> "$pl_state"
            eval "${svc_name_var}='${svc_name}'"
        fi
        echo "    Service name: $svc_name"
    done

    # ── Phase 2: Per-VPC security groups for VPC endpoints ──

    echo ""
    echo "  ━━━ Cross-VPC security groups ━━━"

    # Collect unique VPCs that need VPCEs (have peers in a different VPC)
    local vpcs_done=""
    for i in $(active_nodes); do
        local my_vpc my_region
        my_vpc=$(node_vpc_id "$i")
        my_region=$(node_region "$i")
        local my_vi
        my_vi=$(vpc_ident "$my_vpc")

        # Skip if we already handled this VPC
        [[ ! " $vpcs_done " =~ " $my_vpc " ]] || continue

        # Check if this VPC has any cross-VPC peers
        local needs_vpce=false
        for j in $(active_nodes); do
            [[ "$j" != "$i" ]] || continue
            if [[ "$(node_vpc_id "$j")" != "$my_vpc" ]]; then
                needs_vpce=true
                break
            fi
        done
        $needs_vpce || continue

        local sg_var="VPCE_SG_${my_vi}"
        if [[ -z "${!sg_var:-}" ]]; then
            local vpc_cidr
            vpc_cidr=$(aws ec2 describe-vpcs --region "$my_region" \
                --vpc-ids "$my_vpc" \
                --query 'Vpcs[0].CidrBlock' --output text)

            local _vpce_sg_name
            _vpce_sg_name=$(vpce_sg_name "$my_vi")
            echo "  Creating VPCE security group in $my_vpc ($my_region)..."
            local sg_id
            # Reuse existing SG if it already exists
            sg_id=$(aws ec2 describe-security-groups \
                --region "$my_region" \
                --filters "Name=group-name,Values=$_vpce_sg_name" "Name=vpc-id,Values=$my_vpc" \
                --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)
            if [[ -n "$sg_id" && "$sg_id" != "None" ]]; then
                echo "    Reusing existing SG: $sg_id"
            else
                sg_id=$(aws ec2 create-security-group \
                    --region "$my_region" \
                    --vpc-id "$my_vpc" \
                    --group-name "$_vpce_sg_name" \
                    --description "Allow nodes to reach peers via PrivateLink" \
                    --query 'GroupId' --output text)
                aws ec2 authorize-security-group-ingress \
                    --region "$my_region" \
                    --group-id "$sg_id" \
                    --protocol tcp --port 3001 \
                    --cidr "$vpc_cidr" 2>/dev/null || true
            fi
            echo "${sg_var}=${sg_id}" >> "$pl_state"
            eval "${sg_var}=${sg_id}"
            aws ec2 create-tags --region "$my_region" --resources "$sg_id" \
                --tags $(project_tags) 2>/dev/null || true
            echo "    SG: $sg_id (allows TCP 3001 from $vpc_cidr)"
        else
            echo "    SG in $my_vpc: ${!sg_var} (exists)"
        fi

        vpcs_done="$vpcs_done $my_vpc"
    done

    # ── Phase 3: Cross-VPC Interface VPC Endpoints ──

    echo ""
    echo "  ━━━ Cross-VPC endpoints ━━━"

    for i in $(active_nodes); do
        local my_vpc my_region my_subnet
        my_vpc=$(node_vpc_id "$i")
        my_region=$(node_region "$i")
        my_subnet=$(node_subnet_id "$i")
        local my_vi
        my_vi=$(vpc_ident "$my_vpc")

        for j in $(active_nodes); do
            [[ "$j" != "$i" ]] || continue
            local peer_vpc
            peer_vpc=$(node_vpc_id "$j")

            # Skip same-VPC peers — reachable via NLB DNS directly
            [[ "$my_vpc" != "$peer_vpc" ]] || continue

            local vpce_id_var="VPCE_ID_NODE${j}_IN_${my_vi}"
            local vpce_id="${!vpce_id_var:-}"

            if [[ -z "$vpce_id" ]]; then
                local peer_region svc_name_var svc_name sg_var sg_id
                peer_region=$(node_region "$j")
                svc_name_var="ENDPOINT_SVC_NAME_NODE${j}"
                svc_name="${!svc_name_var:-}"
                [[ -n "$svc_name" ]] || die "No endpoint service name for node $j. Run privatelink for node $j first."
                sg_var="VPCE_SG_${my_vi}"
                sg_id="${!sg_var:-}"
                [[ -n "$sg_id" ]] || die "No VPCE security group for VPC $my_vi."

                # Check if a VPCE already exists for this service in this VPC
                vpce_id=$(aws ec2 describe-vpc-endpoints --region "$my_region" \
                    --filters "Name=service-name,Values=$svc_name" "Name=vpc-id,Values=$my_vpc" \
                    --query "VpcEndpoints[?State!='deleted'] | [0].VpcEndpointId" --output text 2>/dev/null)
                if [[ -n "$vpce_id" && "$vpce_id" != "None" ]]; then
                    echo "  Reusing existing VPCE for node $j in $my_vpc: $vpce_id"
                    echo "${vpce_id_var}=${vpce_id}" >> "$pl_state"
                    eval "${vpce_id_var}=${vpce_id}"
                else
                echo "  Creating VPCE for node $j in $my_vpc ($my_region)..."

                # Find a second subnet in a different AZ within the consumer VPC
                local second_subnet
                second_subnet=$(aws ec2 describe-subnets --region "$my_region" \
                    --filters "Name=vpc-id,Values=$my_vpc" \
                    --query "Subnets[?SubnetId!='${my_subnet}'] | [0].SubnetId" --output text)
                [[ -n "$second_subnet" && "$second_subnet" != "None" ]] || die "No second subnet found in VPC $my_vpc ($my_region). VPCE requires ≥2 AZs."

                local vpce_args=(
                    --region "$my_region"
                    --vpc-id "$my_vpc"
                    --service-name "$svc_name"
                    --vpc-endpoint-type Interface
                    --subnet-ids "$my_subnet" "$second_subnet"
                    --security-group-ids "$sg_id"
                    --no-private-dns-enabled
                )

                # Cross-region PrivateLink requires --service-region
                if [[ "$peer_region" != "$my_region" ]]; then
                    vpce_args+=(--service-region "$peer_region")
                    echo "    Cross-region: $peer_region → $my_region"

                    # Wait for endpoint service to accept connections from this region
                    local _svc_wait=0
                    while true; do
                        if aws ec2 describe-vpc-endpoint-services --region "$my_region" \
                            --service-names "$svc_name" > /dev/null 2>&1; then
                            break
                        fi
                        _svc_wait=$((_svc_wait + 1))
                        if [[ $_svc_wait -ge 30 ]]; then
                            warn "Endpoint service $svc_name not yet visible in $my_region after 60s — attempting VPCE creation anyway"
                            break
                        fi
                        sleep 2
                    done
                fi

                vpce_id=$(aws ec2 create-vpc-endpoint \
                    "${vpce_args[@]}" \
                    --query 'VpcEndpoint.VpcEndpointId' --output text)
                echo "${vpce_id_var}=${vpce_id}" >> "$pl_state"
                eval "${vpce_id_var}=${vpce_id}"
                aws ec2 create-tags --region "$my_region" --resources "$vpce_id" \
                    --tags $(project_tags) 2>/dev/null || true
                echo "    VPCE: $vpce_id"
                fi
            else
                echo "    VPCE for node $j in $my_vpc: $vpce_id (exists)"
            fi

            # Wait for DNS
            local vpce_dns_var="VPCE_DNS_NODE${j}_IN_${my_vi}"
            local vpce_dns="${!vpce_dns_var:-}"
            if [[ -z "$vpce_dns" ]]; then
                echo "    Waiting for VPCE DNS..."
                local attempts=0
                while true; do
                    vpce_dns=$(aws ec2 describe-vpc-endpoints \
                        --region "$my_region" \
                        --vpc-endpoint-ids "$vpce_id" \
                        --query 'VpcEndpoints[0].DnsEntries[0].DnsName' --output text 2>/dev/null)
                    if [[ -n "$vpce_dns" && "$vpce_dns" != "None" && "$vpce_dns" != "null" ]]; then
                        echo "${vpce_dns_var}=${vpce_dns}" >> "$pl_state"
                        eval "${vpce_dns_var}='${vpce_dns}'"
                        break
                    fi
                    attempts=$((attempts + 1))
                    if [[ $attempts -ge 60 ]]; then
                        die "Could not get DNS for $vpce_id after 5 minutes"
                    fi
                    sleep 5
                done
            fi
            if [[ -n "$vpce_dns" ]]; then
                echo "    DNS: $vpce_dns"
            fi
        done
    done

    echo ""
    echo "  PrivateLink setup complete."
    echo "  State saved to: $pl_state"
    echo ""
    echo "  Next: ./deploy.sh coordinator-config  (generates per-node peer configs)"
}

# ─── 6b. Measure — fetch SEV-SNP measurement from a running node ────────────

step_measure() {
    echo ""
    info "Fetching SEV-SNP measurement from a running node"
    echo ""

    # Pick the first active node
    local first_node
    first_node=$(active_nodes | awk '{print $1}')
    local ip
    ip=$(node_ip "$first_node")

    echo "  Using node $first_node ($ip)..."
    echo "  Running toprf-measure in Docker container..."

    local raw_output measurement
    raw_output=$(ssh_node "$first_node" "sudo docker run --rm \
        --device /dev/sev-guest:/dev/sev-guest \
        --user root \
        --entrypoint /usr/local/bin/toprf-measure \
        ${NODE_IMAGE} --json" < /dev/null 2>&1) || {
        echo "  SSH/Docker command failed. Output:"
        echo "$raw_output" | sed 's/^/    /'
        die "Failed to get measurement from node $first_node. Is the node running with SEV-SNP and is the image pulled?"
    }

    measurement=$(echo "$raw_output" | jq -r '.measurement' 2>/dev/null) || true

    if [[ -z "$measurement" || "$measurement" == "null" ]]; then
        echo "  Raw output from node:"
        echo "$raw_output" | sed 's/^/    /'
        die "Failed to parse measurement from node $first_node. Is the node running with SEV-SNP?"
    fi

    echo "  Measurement: $measurement"

    # Save to config.env
    if grep -q "^EXPECTED_MEASUREMENT=" "$CONFIG_FILE"; then
        sed -i.bak "s|^EXPECTED_MEASUREMENT=.*|EXPECTED_MEASUREMENT=${measurement}|" "$CONFIG_FILE" && rm -f "${CONFIG_FILE}.bak"
    else
        echo "" >> "$CONFIG_FILE"
        echo "# SEV-SNP measurement (auto-detected by deploy.sh measure)" >> "$CONFIG_FILE"
        echo "EXPECTED_MEASUREMENT=${measurement}" >> "$CONFIG_FILE"
    fi
    EXPECTED_MEASUREMENT="$measurement"

    echo "  Saved to config.env as EXPECTED_MEASUREMENT"

    # Fetch AMD ARK fingerprint from KDS (try VLEK chain first, fall back to VCEK)
    echo ""
    echo "  Fetching AMD ARK certificate fingerprint from KDS..."
    local ark_fingerprint=""
    for key_type in vlek vcek; do
        local chain_pem
        chain_pem=$(curl -sf "https://kdsintf.amd.com/${key_type}/v1/Milan/cert_chain" 2>/dev/null) || continue

        # Extract the second PEM certificate (ARK) and compute SHA-256 of its DER
        ark_fingerprint=$(echo "$chain_pem" \
            | awk '/-----BEGIN CERTIFICATE-----/{n++} n==2' \
            | openssl x509 -inform PEM -outform DER 2>/dev/null \
            | shasum -a 256 \
            | awk '{print $1}')

        if [[ -n "$ark_fingerprint" ]]; then
            echo "  ARK fingerprint (${key_type}): ${ark_fingerprint}"
            break
        fi
    done

    if [[ -z "$ark_fingerprint" ]]; then
        die "Failed to fetch AMD ARK certificate from KDS"
    fi

    if grep -q "^AMD_ARK_FINGERPRINT=" "$CONFIG_FILE"; then
        sed -i.bak "s|^AMD_ARK_FINGERPRINT=.*|AMD_ARK_FINGERPRINT=${ark_fingerprint}|" "$CONFIG_FILE" && rm -f "${CONFIG_FILE}.bak"
    else
        echo "# AMD ARK certificate fingerprint (auto-detected by deploy.sh measure)" >> "$CONFIG_FILE"
        echo "AMD_ARK_FINGERPRINT=${ark_fingerprint}" >> "$CONFIG_FILE"
    fi
    AMD_ARK_FINGERPRINT="$ark_fingerprint"

    echo "  Saved to config.env as AMD_ARK_FINGERPRINT"
    echo ""
    echo "  Measurement is tied to the AMI firmware, not the Docker image."
    echo "  It only changes when AWS updates the Amazon Linux AMI."
}

# ─── 7. Init-seal (interactive) ──────────────────────────────────────────────

step_init_seal() {
    echo ""
    info "Init-seal — S3-mediated ECIES key injection"
    echo ""
    echo "  For each node, the script will:"
    echo "    1. Start the node in init-seal mode (generates keypair, uploads attestation + pubkey to S3)"
    echo "    2. Download and verify the attestation report"
    echo "    3. Encrypt the key share with ECIES to the attested public key"
    echo "    4. Upload the encrypted share to S3 for the node to pick up"
    echo ""

    load_ceremony

    # Build the toprf-init-encrypt binary if not already built
    local init_encrypt="$REPO_ROOT/target/release/toprf-init-encrypt"
    if [[ ! -x "$init_encrypt" ]]; then
        echo "  Building toprf-init-encrypt..."
        (cd "$REPO_ROOT" && cargo build --release -p toprf-seal --bin toprf-init-encrypt 2>&1 | tail -3)
    fi

    # Get expected measurement (set in config.env, or auto-detected by 'measure' step)
    local expected_measurement="${EXPECTED_MEASUREMENT:-}"
    if [[ -z "$expected_measurement" ]]; then
        echo ""
        echo "  EXPECTED_MEASUREMENT not set in config.env."
        echo "  Run './deploy.sh measure' first to auto-detect from a running node,"
        echo "  or enter the expected measurement (96 hex chars) now:"
        read -r expected_measurement < /dev/tty
        if [[ -z "$expected_measurement" ]]; then
            die "EXPECTED_MEASUREMENT is required. Run './deploy.sh measure' to auto-detect it."
        fi
    fi

    for i in $(active_nodes); do
        local ip vs url share bucket
        ip=$(node_ip "$i")
        vs=$(node_vs "$i")
        url=$(sealed_url "$i")
        share="${NODE_SHARES_DIR}/node-${i}-share.json"
        bucket=$(node_s3_bucket "$i")

        [[ -f "$share" ]] || die "Key share not found: $share"

        echo "━━━ Node $i ($ip) ━━━"
        echo "  S3 bucket: $bucket"
        echo "  Starting init-seal container..."

        # Clean up any previous init-seal container
        ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true" < /dev/null

        ssh_node "$i" "sudo docker run -d --name toprf-init-seal \
            -e EXPECTED_VERIFICATION_SHARE=${vs} \
            --device /dev/sev-guest:/dev/sev-guest \
            --user root \
            ${NODE_IMAGE} \
            --init-seal \
            --s3-bucket '${bucket}' \
            --upload-url '${url}'" < /dev/null

        echo "  Node started in init-seal mode. Waiting for attestation artifacts in S3..."

        # Poll for attestation.bin in S3
        local s3_attestation="s3://${bucket}/init/attestation.bin"
        local s3_pubkey="s3://${bucket}/init/pubkey.bin"
        local s3_certs="s3://${bucket}/init/certs.bin"
        local s3_encrypted="s3://${bucket}/init/encrypted-share.bin"
        local tmpdir
        tmpdir=$(mktemp -d)

        local waited=0
        while ! aws s3 cp "$s3_attestation" "$tmpdir/attestation.bin" --quiet 2>/dev/null; do
            local running
            running=$(ssh_node "$i" "sudo docker inspect -f '{{.State.Running}}' toprf-init-seal 2>/dev/null || echo false" < /dev/null)
            if [[ "$running" != "true" ]]; then
                echo "  Container exited prematurely. Logs:"
                ssh_node "$i" "sudo docker logs --tail 20 toprf-init-seal 2>&1" < /dev/null || true
                echo ""
                echo "  Press Enter to skip this node and continue, or Ctrl-C to abort:"
                read -r _ < /dev/tty
                ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true" < /dev/null
                rm -rf "$tmpdir"
                continue 2
            fi
            sleep 3
            waited=$((waited + 1))
            if [[ $waited -ge 40 ]]; then
                echo "  Timed out after 120s. Check container logs:"
                echo "    ssh → sudo docker logs toprf-init-seal"
                rm -rf "$tmpdir"
                die "init-seal: attestation not uploaded to S3"
            fi
        done

        aws s3 cp "$s3_pubkey" "$tmpdir/pubkey.bin" --quiet
        aws s3 cp "$s3_certs" "$tmpdir/certs.bin" --quiet
        echo "  Attestation, pubkey, and certs downloaded from S3."

        # Run the operator-side verification + encryption
        local encrypt_args=(
            --attestation "$tmpdir/attestation.bin"
            --pubkey "$tmpdir/pubkey.bin"
            --certs "$tmpdir/certs.bin"
            --output "$tmpdir/encrypted-share.bin"
            --share-file "$share"
        )

        encrypt_args+=(--expected-measurement "$expected_measurement")

        echo "  Verifying attestation and encrypting key share..."
        AMD_ARK_FINGERPRINT="${AMD_ARK_FINGERPRINT:-}" \
            "$init_encrypt" "${encrypt_args[@]}" 2>&1 | sed 's/^/  /'

        # Upload encrypted share to S3
        echo "  Uploading encrypted share to S3..."
        aws s3 cp "$tmpdir/encrypted-share.bin" "$s3_encrypted" --quiet

        echo "  Encrypted share uploaded. Node will pick it up and seal."

        # Wait for the init-seal container to finish (it seals and exits)
        local seal_waited=0
        while true; do
            local running
            running=$(ssh_node "$i" "sudo docker inspect -f '{{.State.Running}}' toprf-init-seal 2>/dev/null || echo false" < /dev/null)
            if [[ "$running" != "true" ]]; then
                break
            fi
            sleep 3
            seal_waited=$((seal_waited + 1))
            if [[ $seal_waited -ge 60 ]]; then
                echo "  Timed out waiting for seal to complete."
                break
            fi
        done

        # Check container exit code
        local exit_code
        exit_code=$(ssh_node "$i" "sudo docker inspect -f '{{.State.ExitCode}}' toprf-init-seal 2>/dev/null || echo 1" < /dev/null)
        if [[ "$exit_code" == "0" ]]; then
            echo "  Node $i sealed successfully."
        else
            echo "  WARNING: init-seal container exited with code $exit_code"
            echo "  Logs:"
            ssh_node "$i" "sudo docker logs --tail 20 toprf-init-seal 2>&1" < /dev/null | sed 's/^/    /' || true
        fi

        ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true" < /dev/null
        rm -rf "$tmpdir"
        echo ""
    done

    echo "  Init-seal complete."
}

# ─── 8. Start nodes in normal mode ───────────────────────────────────────────

step_start() {
    echo ""
    info "Starting nodes in normal mode"

    load_ceremony
    validate_threshold

    local config_dir
    config_dir=$(coord_config_dir)

    for i in $(active_nodes); do
        local ip vs url
        ip=$(node_ip "$i")
        vs=$(node_vs "$i")
        url=$(sealed_url "$i")

        echo "  Node $i ($ip)..."

        ssh_node "$i" "sudo docker rm -f toprf-node 2>/dev/null || true" < /dev/null

        # Upload coordinator config if it exists
        local coord_config="${config_dir}/coordinator-node-${i}.json"
        local coord_args=""
        if [[ -f "$coord_config" ]]; then
            scp_to_node "$i" "$coord_config" < /dev/null || die "Failed to upload coordinator config to node $i"
            ssh_node "$i" "sudo mkdir -p /etc/toprf && sudo mv /tmp/coordinator-node-${i}.json /etc/toprf/coordinator.json" < /dev/null
            coord_args="-v /etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro"
            echo "    Coordinator config uploaded"
        fi

        # EXPECTED_PEER_MEASUREMENT: used by /reshare to verify target attestation
        local peer_measurement="${EXPECTED_PEER_MEASUREMENT:-${EXPECTED_MEASUREMENT:-}}"

        ssh_node "$i" "sudo docker run -d --name toprf-node --restart=unless-stopped \
            -e SEALED_KEY_URL='${url}' \
            -e EXPECTED_VERIFICATION_SHARE=${vs} \
            -e EXPECTED_PEER_MEASUREMENT='${peer_measurement}' \
            -e AMD_ARK_FINGERPRINT='${AMD_ARK_FINGERPRINT:-}' \
            ${coord_args} \
            --device /dev/sev-guest:/dev/sev-guest \
            --user root \
            -p 3001:3001 \
            ${NODE_IMAGE} \
            --port 3001 \
            --coordinator-config /etc/toprf/coordinator.json" < /dev/null
    done

    echo "  Waiting for nodes to boot..."
    local boot_ok=true
    for i in $(active_nodes); do
        local ip attempts=0
        ip=$(node_ip "$i")
        echo -n "    Node $i ($ip): "
        while true; do
            if ssh_node "$i" "curl -sf http://localhost:3001/health" < /dev/null > /dev/null 2>&1; then
                echo "healthy"
                break
            fi
            attempts=$((attempts + 1))
            if [[ $attempts -ge 30 ]]; then
                echo "NOT healthy after 60s"
                boot_ok=false
                break
            fi
            sleep 2
        done
    done
    $boot_ok && echo "  All nodes healthy." || warn "Some nodes did not become healthy — check logs with: ssh_node <N> 'sudo docker logs toprf-node'"
}

# ─── 9. Generate coordinator configs ─────────────────────────────────────────

step_coordinator_config() {
    echo ""
    info "Generating coordinator configs (per-node peer endpoints)"

    load_ceremony

    local pl_state
    pl_state=$(pl_state_file)
    [[ -f "$pl_state" ]] || die "$(basename "$pl_state") not found. Run './deploy.sh privatelink' first."
    source "$pl_state"

    local config_dir
    config_dir=$(coord_config_dir)
    mkdir -p "$config_dir"

    for i in $(active_nodes); do
        local out="${config_dir}/coordinator-node-${i}.json"
        local my_vpc
        my_vpc=$(node_vpc_id "$i")
        local my_vi
        my_vi=$(vpc_ident "$my_vpc")
        local peers_json=""
        local first=true

        for j in $(active_nodes); do
            [[ "$j" != "$i" ]] || continue

            local vs peer_endpoint peer_vpc
            vs=$(node_vs "$j")
            peer_vpc=$(node_vpc_id "$j")

            if [[ "$my_vpc" == "$peer_vpc" ]]; then
                # Same VPC: use internal NLB DNS (directly reachable)
                local nlb_dns_var="NLB_DNS_NODE${j}"
                local nlb_dns="${!nlb_dns_var:-}"
                [[ -n "$nlb_dns" ]] || die "NLB_DNS_NODE${j} not found. Run './deploy.sh privatelink' first."
                peer_endpoint="http://${nlb_dns}:3001"
            else
                # Different VPC: use PrivateLink VPCE DNS
                local vpce_dns_var="VPCE_DNS_NODE${j}_IN_${my_vi}"
                local vpce_dns="${!vpce_dns_var:-}"
                [[ -n "$vpce_dns" ]] || die "No VPCE DNS for node $j in VPC $my_vpc. Run './deploy.sh privatelink' first."
                peer_endpoint="http://${vpce_dns}:3001"
            fi

            $first || peers_json+=","
            peers_json+="
    {
      \"node_id\": $j,
      \"endpoint\": \"${peer_endpoint}\",
      \"verification_share\": \"${vs}\"
    }"
            first=false
        done

        cat > "$out" <<CFGEOF
{
  "peers": [${peers_json}
  ]
}
CFGEOF

        echo "  Node $i config: $out"
    done

    echo "  Done."
}

# ─── 10. Verify ──────────────────────────────────────────────────────────────

step_verify() {
    echo ""
    info "Verifying node health"

    local pass=0 fail=0

    for i in $(active_nodes); do
        local ip
        ip=$(node_ip "$i")
        echo "  Node $i ($ip)..."

        # Health check via SSH (port 3001 is not open from local machine)
        local resp
        resp=$(ssh_node "$i" "curl -s --connect-timeout 5 http://localhost:3001/health 2>&1" < /dev/null) || true

        if echo "$resp" | jq -e '.status == "ready"' > /dev/null 2>&1; then
            echo "    PASS: ready"
            pass=$((pass + 1))
        else
            echo "    FAIL: $resp"
            fail=$((fail + 1))
        fi
    done

    echo ""
    echo "  Results: $pass passed, $fail failed"

    if [[ $fail -gt 0 ]]; then
        echo ""
        echo "  Troubleshooting:"
        echo "    ssh → sudo docker logs toprf-node"
        echo "    ssh → sudo docker ps -a"
        return 1
    fi
}

# ─── 10b. End-to-end verify ──────────────────────────────────────────────────

step_e2e() {
    echo ""
    info "End-to-end verification"

    local domain="${DOMAIN:?DOMAIN not set in config.env}"
    local pass=0 fail=0 total=0

    # 1. Node health (via SSH)
    echo ""
    echo "  [1/3] Node health (via SSH)"
    for i in $(active_nodes); do
        local ip
        ip=$(node_ip "$i")
        total=$((total + 1))

        local resp
        resp=$(ssh_node "$i" "curl -s --connect-timeout 5 http://localhost:3001/health 2>&1" < /dev/null) || true

        if echo "$resp" | jq -e '.status == "ready"' > /dev/null 2>&1; then
            echo "    Node $i ($ip): PASS"
            pass=$((pass + 1))
        else
            echo "    Node $i ($ip): FAIL — $resp"
            fail=$((fail + 1))
        fi
    done

    # 2. Coordinator test (via SSH, calls /evaluate which coordinates with peers)
    local coord_node
    coord_node=$(active_nodes | awk '{print $1}')
    echo ""
    echo "  [2/3] Coordinator evaluate (node $coord_node → peers via PrivateLink)"
    total=$((total + 1))

    # Use a known test blinded point (valid secp256k1 point)
    local test_point="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

    local eval_resp
    eval_resp=$(ssh_node "$coord_node" "curl -s --connect-timeout 10 \
        -X POST http://localhost:3001/evaluate \
        -H 'Content-Type: application/json' \
        -d '{\"blinded_point\":\"${test_point}\"}'" < /dev/null 2>&1) || true

    if echo "$eval_resp" | jq -e '.evaluation' > /dev/null 2>&1; then
        local eval_point partials_count
        eval_point=$(echo "$eval_resp" | jq -r '.evaluation')
        partials_count=$(echo "$eval_resp" | jq '.partials | length')
        echo "    Evaluate: PASS (partials=$partials_count, evaluation=${eval_point:0:16}...)"
        pass=$((pass + 1))
    else
        echo "    Evaluate: FAIL — $eval_resp"
        fail=$((fail + 1))
    fi

    # 3. OPRF domain endpoint (oprf.ruonlabs.com)
    local oprf_domain="${OPRF_DOMAIN:-oprf.ruonlabs.com}"
    echo ""
    echo "  [3/3] Domain endpoint (https://${oprf_domain})"
    total=$((total + 1))

    local domain_resp
    domain_resp=$(curl -s --connect-timeout 10 \
        -X POST "https://${oprf_domain}/evaluate" \
        -H "Content-Type: application/json" \
        -d "{\"blinded_point\":\"${test_point}\"}" 2>&1) || true

    if echo "$domain_resp" | jq -e '.evaluation' > /dev/null 2>&1; then
        echo "    Domain: PASS"
        pass=$((pass + 1))
    else
        echo "    Domain: SKIP (API Gateway not configured yet) — $domain_resp"
        # Don't count as failure — API Gateway setup is a separate step
    fi

    # Summary
    echo ""
    echo "  ────────────────────────────────"
    echo "  Results: $pass/$total passed, $fail failed"

    if [[ $fail -gt 0 ]]; then
        echo ""
        echo "  Troubleshooting:"
        echo "    Nodes:  ssh → sudo docker logs toprf-node"
        echo "    Config: check coordinator-configs/coordinator-node-<N>.json"
        echo "    PrivateLink: verify VPC endpoint state in privatelink-state.env"
        return 1
    else
        echo "  All checks passed."
    fi
}

# ─── 11. CloudWatch alarms (unhealthy node detection) ────────────────────────

step_cloudwatch() {
    echo ""
    info "Setting up CloudWatch alarms for NLB target health"

    local sns_topic="${SNS_ALERT_TOPIC:-toprf-node-alerts}"
    local pl_state
    pl_state=$(pl_state_file)
    [[ -f "$pl_state" ]] || die "$(basename "$pl_state") not found. Run privatelink first."
    source "$pl_state"

    for i in $(active_nodes); do
        local region tg_arn
        region=$(node_region "$i")
        local tg_var="PL_TG_ARN_NODE${i}"
        tg_arn="${!tg_var:-}"
        [[ -n "$tg_arn" ]] || { warn "No target group ARN for node $i — skipping"; continue; }

        echo ""
        echo "  ━━━ Node $i ($region) ━━━"

        # Ensure SNS topic exists in this region
        local topic_arn
        topic_arn=$(aws sns create-topic --region "$region" --name "$sns_topic" \
            --query 'TopicArn' --output text 2>/dev/null) || die "Failed to create SNS topic in $region"
        echo "    SNS topic: $topic_arn"

        # Extract target group ID from ARN for CloudWatch dimension
        # ARN format: arn:aws:elasticloadbalancing:region:account:targetgroup/name/id
        local tg_suffix
        tg_suffix=$(echo "$tg_arn" | sed 's|.*targetgroup/|targetgroup/|')

        # Extract NLB ID for the dimension
        local nlb_var="NLB_ARN_NODE${i}"
        local nlb_arn="${!nlb_var:-}"
        local nlb_suffix
        nlb_suffix=$(echo "$nlb_arn" | sed 's|.*loadbalancer/|net/|')

        local alarm_name="toprf-node-${i}-unhealthy"

        # Create/update CloudWatch alarm on UnHealthyHostCount
        aws cloudwatch put-metric-alarm --region "$region" \
            --alarm-name "$alarm_name" \
            --alarm-description "TOPRF node $i has unhealthy NLB targets — triggers rotation" \
            --namespace "AWS/NetworkELB" \
            --metric-name UnHealthyHostCount \
            --dimensions \
                "Name=TargetGroup,Value=${tg_suffix}" \
                "Name=LoadBalancer,Value=${nlb_suffix}" \
            --statistic Maximum \
            --period 60 \
            --evaluation-periods 3 \
            --threshold 1 \
            --comparison-operator GreaterThanOrEqualToThreshold \
            --treat-missing-data notBreaching \
            --alarm-actions "$topic_arn" \
            --ok-actions "$topic_arn" \
            --tags Key=Project,Value=toprf
        echo "    Alarm: $alarm_name (3 consecutive unhealthy checks → alert)"
    done

    echo ""
    echo "  CloudWatch alarms created."
    echo "  Subscribe the rotation Lambda to the SNS topic to auto-trigger recovery."
    echo "  Example: aws sns subscribe --topic-arn <ARN> --protocol lambda --notification-endpoint <LAMBDA_ARN>"
}

# ─── 13. Show IPs ────────────────────────────────────────────────────────────

step_show_ips() {
    echo ""
    info "Fetching VM IPs from AWS"

    for i in $(active_nodes); do
        local region
        region=$(node_region "$i")
        echo "  Node $i ($region):"

        local result
        local _vm_tag
        _vm_tag=$(vm_tag "$i")
        result=$(aws ec2 describe-instances --region "$region" \
            --filters "Name=tag:Name,Values=${_vm_tag}" "Name=instance-state-name,Values=running" \
            --query 'Reservations[0].Instances[0].[PublicIpAddress,PrivateIpAddress]' \
            --output text 2>/dev/null) || true

        if [[ -n "$result" && "$result" != *"None"* ]]; then
            local pub_ip priv_ip
            pub_ip=$(echo "$result" | awk '{print $1}')
            priv_ip=$(echo "$result" | awk '{print $2}')
            echo "    Public:  ${pub_ip}"
            echo "    Private: ${priv_ip}"
        else
            echo "    NOT FOUND"
        fi
    done
}

# ─── 14. Auto-config ─────────────────────────────────────────────────────────

step_auto_config() {
    echo ""
    info "Auto-populating nodes.json from AWS"
    echo ""

    # AWS Account ID (still in config.env)
    echo "  Fetching AWS account ID..."
    local aws_id
    aws_id=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || true
    if [[ -n "$aws_id" ]]; then
        if grep -q "^AWS_ACCOUNT_ID=" "$CONFIG_FILE"; then
            sed -i.bak "s|^AWS_ACCOUNT_ID=.*|AWS_ACCOUNT_ID=${aws_id}|" "$CONFIG_FILE" && rm -f "${CONFIG_FILE}.bak"
            echo "  AWS_ACCOUNT_ID=${aws_id}"
        fi
    else
        warn "Could not fetch AWS account ID"
    fi

    # Per-node IPs, SGs, VPCs → update nodes.json
    for i in $(all_node_ids); do
        local region
        region=$(node_region "$i")
        echo "  Fetching Node $i info ($region)..."

        local instance_data
        local _vm_tag
        _vm_tag=$(vm_tag "$i")
        instance_data=$(aws ec2 describe-instances --region "$region" \
            --filters "Name=tag:Name,Values=${_vm_tag}" "Name=instance-state-name,Values=running" \
            --query 'Reservations[0].Instances[0]' --output json 2>/dev/null) || true

        if [[ -n "$instance_data" && "$instance_data" != "null" ]]; then
            local pub_ip priv_ip sg_id vpc_id subnet_id ami_id
            pub_ip=$(echo "$instance_data" | jq -r '.PublicIpAddress // empty')
            priv_ip=$(echo "$instance_data" | jq -r '.PrivateIpAddress // empty')
            sg_id=$(echo "$instance_data" | jq -r '.SecurityGroups[0].GroupId // empty')
            vpc_id=$(echo "$instance_data" | jq -r '.VpcId // empty')
            subnet_id=$(echo "$instance_data" | jq -r '.SubnetId // empty')
            ami_id=$(echo "$instance_data" | jq -r '.ImageId // empty')

            # Set ssh_key if still empty (derive from key_name)
            local key_name ssh_key_val
            key_name=$(node_key_name "$i")
            ssh_key_val=$(node_ssh_key "$i")
            if [[ -z "$ssh_key_val" && -n "$key_name" ]]; then
                ssh_key_val="${SCRIPT_DIR}/${key_name}.pem"
            fi

            # Update nodes.json in place
            local tmp
            tmp=$(mktemp) || die "mktemp failed"
            jq --argjson id "$i" \
               --arg ip "$pub_ip" --arg pip "$priv_ip" \
               --arg sg "$sg_id" --arg vpc "$vpc_id" --arg sub "$subnet_id" \
               --arg ssh "$ssh_key_val" --arg ami "$ami_id" \
               '(.nodes[] | select(.id == $id)) |= . + {ip: $ip, private_ip: $pip, sg_id: $sg, vpc_id: $vpc, subnet_id: $sub, ssh_key: $ssh, ami_id: $ami}' \
               "$NODES_JSON" > "$tmp" || { rm -f "$tmp"; die "jq failed updating nodes.json"; }
            jq . "$tmp" > /dev/null 2>&1 || { rm -f "$tmp"; die "jq produced invalid JSON"; }
            mv "$tmp" "$NODES_JSON" || { rm -f "$tmp"; die "mv failed updating nodes.json"; }

            echo "    ip=$pub_ip private_ip=$priv_ip sg=$sg_id vpc=$vpc_id subnet=$subnet_id ami=$ami_id"
        else
            warn "Could not find Node $i in $region"
        fi
    done

    echo ""
    echo "  Done. Review nodes.json and fill in any remaining empty fields."
}

# ─── 15. Lock nodes (remove SSH access) ──────────────────────────────────────

step_lock() {
    echo ""
    info "Locking nodes — removing SSH access"
    echo ""
    echo "  WARNING: This will permanently remove SSH access to all nodes."
    echo "  You will NOT be able to SSH in again. If a node fails, reprovision it."
    echo ""
    echo "  Press Enter to confirm, or Ctrl-C to abort:"
    read -r _ < /dev/tty

    for i in $(active_nodes); do
        local ip region key_name
        ip=$(node_ip "$i")
        region=$(node_region "$i")
        key_name=$(node_key_name "$i")
        echo "  Node $i ($ip)..."

        # Remove SSH authorized keys and disable sshd
        ssh_node "$i" "sudo rm -f /home/ec2-user/.ssh/authorized_keys && \
            sudo systemctl stop sshd && \
            sudo systemctl disable sshd" < /dev/null || warn "Failed to lock node $i"

        # Delete the EC2 key pair from AWS
        aws ec2 delete-key-pair --region "$region" --key-name "$key_name" 2>/dev/null \
            || warn "Could not delete key pair $key_name in $region"

        # Delete the local .pem file
        local key_file="${SCRIPT_DIR}/${key_name}.pem"
        if [[ -f "$key_file" ]]; then
            rm -f "$key_file"
            echo "    Deleted: $key_file"
        fi

        echo "    Locked."
    done

    echo ""
    echo "  All nodes locked. SSH access removed."
    echo "  Nodes are now only reachable via port 3001 (NLB / PrivateLink)."
}

# ─── 16. Redeploy ────────────────────────────────────────────────────────────

step_redeploy() {
    echo ""
    info "Redeploying (pull latest image → restart)"
    step_pull
    for i in $(active_nodes); do
        echo "  Restarting node $i..."
        ssh_node "$i" "sudo docker rm -f toprf-node 2>/dev/null || true" < /dev/null
    done
    step_start
}

# ─── 17. Rotate node (staging-based zero-downtime replacement) ────────────────
#
# Replaces a single node via staging: provision staging instance alongside the
# existing node, reshare from donors, verify, swap NLB targets, clean up.
# Requires: ./provision.sh <N> --staging already run.

step_rotate() {
    local target_node="${ROTATE_NODE:?rotate requires a node ID}"
    echo ""
    info "Rotating node $target_node (staging-based)"

    local region bucket
    region=$(node_region "$target_node")
    bucket=$(node_s3_bucket "$target_node")

    local staging_tag="toprf-node-${target_node}-staging"
    local staging_key="toprf-node-${target_node}-staging-key"
    local staging_sealed_path="node-${target_node}-staging-sealed.bin"
    local staging_sealed_url="s3://${bucket}/${staging_sealed_path}"

    # ── Verify staging instance exists ──
    local staging_instance
    staging_instance=$(aws ec2 describe-instances --region "$region" \
        --filters "Name=tag:Name,Values=${staging_tag}" \
                  "Name=instance-state-name,Values=running" \
        --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null)
    [[ -n "$staging_instance" && "$staging_instance" != "None" && "$staging_instance" != "null" ]] \
        || die "No running staging instance found (${staging_tag}). Run './provision.sh ${target_node} --staging' first."

    local staging_ip staging_priv_ip staging_sg
    staging_ip=$(aws ec2 describe-instances --region "$region" \
        --instance-ids "$staging_instance" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    staging_priv_ip=$(aws ec2 describe-instances --region "$region" \
        --instance-ids "$staging_instance" \
        --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)
    staging_sg=$(aws ec2 describe-instances --region "$region" \
        --instance-ids "$staging_instance" \
        --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text 2>/dev/null)

    local staging_key_file="${SCRIPT_DIR}/${staging_key}.pem"
    [[ -f "$staging_key_file" ]] || die "Staging key file not found: $staging_key_file"

    echo "  Staging instance: $staging_instance ($staging_ip / $staging_priv_ip)"

    # SSH helper for staging node
    _ssh_staging() {
        ssh -o StrictHostKeyChecking=accept-new -i "$staging_key_file" "ec2-user@${staging_ip}" "$@"
    }
    _scp_staging() {
        scp -o StrictHostKeyChecking=accept-new -i "$staging_key_file" "$@" "ec2-user@${staging_ip}:/tmp/"
    }

    # Cleanup trap: remove reshare artifacts on failure
    local tmpdir
    tmpdir=$(mktemp -d)
    _rotate_cleanup() {
        rm -rf "$tmpdir"
        aws s3 rm "s3://${bucket}/reshare/" --recursive --quiet 2>/dev/null || true
    }
    trap _rotate_cleanup EXIT

    # ── Pre-flight: verify donor nodes are healthy ──
    echo ""
    echo "  ━━━ Pre-flight: donor health check ━━━"
    local donor_ids=""
    for i in $(active_nodes); do
        [[ "$i" != "$target_node" ]] || continue
        donor_ids="$donor_ids $i"
        local donor_ip
        donor_ip=$(node_ip "$i")
        local health_resp
        health_resp=$(ssh_node "$i" "curl -sf --connect-timeout 5 http://localhost:3001/health" < /dev/null 2>&1) || true
        if echo "$health_resp" | jq -e '.status == "ready"' > /dev/null 2>&1; then
            echo "    Node $i ($donor_ip): healthy"
        else
            die "Donor node $i ($donor_ip) is not healthy — cannot proceed with rotation"
        fi
    done

    # ── Step 1: Setup staging VM ──
    echo ""
    echo "  ━━━ Step 1: Setup staging VM ━━━"
    _ssh_staging "sudo yum install -y docker > /dev/null 2>&1 && sudo systemctl enable --now docker" < /dev/null
    echo "    Docker installed"

    _ssh_staging "sudo docker pull ${NODE_IMAGE}" < /dev/null
    echo "    Image pulled: ${NODE_IMAGE}"

    # ── Step 2: Init-reshare on staging node ──
    echo ""
    echo "  ━━━ Step 2: Init-reshare ━━━"

    load_ceremony
    local threshold total_shares
    threshold=$(jq -r '.threshold // empty' "$NODES_JSON")
    total_shares=$(jq -r '.nodes | length' "$NODES_JSON")
    [[ -n "$threshold" && "$threshold" =~ ^[0-9]+$ ]] || die "Invalid threshold in nodes.json: '$threshold'"
    [[ -n "$total_shares" && "$total_shares" =~ ^[0-9]+$ && "$total_shares" -ge "$threshold" ]] \
        || die "Invalid total_shares in nodes.json: '$total_shares' (threshold=$threshold)"

    echo "  Starting staging node in init-reshare mode..."
    echo "    node_id=$target_node threshold=$threshold total=$total_shares"

    _ssh_staging "sudo docker rm -f toprf-init-reshare 2>/dev/null || true" < /dev/null
    _ssh_staging "sudo docker run -d --name toprf-init-reshare \
        --device /dev/sev-guest:/dev/sev-guest \
        --user root \
        ${NODE_IMAGE} \
        --init-reshare \
        --s3-bucket '${bucket}' \
        --upload-url '${staging_sealed_url}' \
        --new-node-id ${target_node} \
        --new-threshold ${threshold} \
        --new-total-shares ${total_shares} \
        --group-public-key '${GROUP_PUBLIC_KEY}' \
        --min-contributions ${threshold}" < /dev/null

    echo "  Waiting for attestation artifacts in S3..."
    local s3_attestation="s3://${bucket}/reshare/attestation.bin"
    local s3_pubkey="s3://${bucket}/reshare/pubkey.bin"
    local s3_certs="s3://${bucket}/reshare/certs.bin"

    local waited=0
    while ! aws s3 ls "$s3_attestation" > /dev/null 2>&1; do
        sleep 3
        waited=$((waited + 1))
        [[ $waited -lt 40 ]] || die "Timed out waiting for staging node attestation in S3"
    done
    echo "    Attestation uploaded to S3"

    aws s3 cp "$s3_attestation" "$tmpdir/attestation.bin" --quiet
    aws s3 cp "$s3_pubkey" "$tmpdir/pubkey.bin" --quiet
    aws s3 cp "$s3_certs" "$tmpdir/certs.bin" --quiet

    # ── Step 3: Trigger reshare on donor nodes ──
    echo ""
    echo "  ━━━ Step 3: Reshare from donors ━━━"

    local participant_json="["
    local first=true
    for i in $donor_ids; do
        $first || participant_json="${participant_json},"
        participant_json="${participant_json}${i}"
        first=false
    done
    participant_json="${participant_json}]"

    local target_pubkey attestation_b64 certs_b64
    target_pubkey=$(xxd -p -c 256 "$tmpdir/pubkey.bin")
    attestation_b64=$(base64 < "$tmpdir/attestation.bin")
    certs_b64=$(base64 < "$tmpdir/certs.bin")

    for donor_id in $donor_ids; do
        local donor_ip
        donor_ip=$(node_ip "$donor_id")
        echo "  Requesting reshare from node $donor_id ($donor_ip)..."

        local reshare_resp
        reshare_resp=$(ssh_node "$donor_id" "curl -sf --connect-timeout 10 \
            -X POST http://localhost:3001/reshare \
            -H 'Content-Type: application/json' \
            -d '{
                \"target_pubkey\": \"${target_pubkey}\",
                \"attestation_report\": \"${attestation_b64}\",
                \"cert_chain\": \"${certs_b64}\",
                \"new_node_id\": ${target_node},
                \"participant_ids\": ${participant_json},
                \"group_public_key\": \"${GROUP_PUBLIC_KEY}\"
            }'" < /dev/null 2>&1) || die "Reshare request to node $donor_id failed"

        echo "$reshare_resp" | aws s3 cp - "s3://${bucket}/reshare/contribution-from-${donor_id}.json" --quiet
        echo "    Contribution from node $donor_id uploaded"
    done

    # ── Step 4: Wait for staging node to combine and seal ──
    echo ""
    echo "  ━━━ Step 4: Waiting for seal ━━━"

    local seal_waited=0
    while true; do
        local running
        running=$(_ssh_staging "sudo docker inspect -f '{{.State.Running}}' toprf-init-reshare 2>/dev/null || echo false" < /dev/null)
        if [[ "$running" != "true" ]]; then
            break
        fi
        sleep 3
        seal_waited=$((seal_waited + 1))
        [[ $seal_waited -lt 120 ]] || die "Timed out waiting for staging node to seal"
    done

    local exit_code
    exit_code=$(_ssh_staging "sudo docker inspect -f '{{.State.ExitCode}}' toprf-init-reshare 2>/dev/null || echo 1" < /dev/null)
    [[ "$exit_code" == "0" ]] || {
        echo "  Init-reshare failed (exit code $exit_code). Logs:"
        _ssh_staging "sudo docker logs --tail 30 toprf-init-reshare 2>&1" < /dev/null | sed 's/^/    /' || true
        die "Staging node init-reshare failed"
    }
    echo "  Sealed blob uploaded to $staging_sealed_url"
    _ssh_staging "sudo docker rm -f toprf-init-reshare 2>/dev/null || true" < /dev/null

    # ── Step 5: Update nodes.json, generate configs, start staging node ──
    echo ""
    echo "  ━━━ Step 5: Start staging node ━━━"

    # Save old IP for NLB deregistration later
    local old_priv_ip
    old_priv_ip=$(node_private_ip "$target_node")

    # Update nodes.json NOW so coordinator config generation uses correct IPs
    echo "  Updating nodes.json with staging node IPs..."
    local tmp
    tmp=$(mktemp) || die "mktemp failed"
    jq --argjson id "$target_node" \
       --arg ip "$staging_ip" --arg pip "$staging_priv_ip" --arg sg "$staging_sg" \
       '(.nodes[] | select(.id == $id)) |= . + {ip: $ip, private_ip: $pip, sg_id: $sg}' \
       "$NODES_JSON" > "$tmp" || { rm -f "$tmp"; die "jq failed updating nodes.json"; }
    jq . "$tmp" > /dev/null 2>&1 || { rm -f "$tmp"; die "jq produced invalid JSON"; }
    mv "$tmp" "$NODES_JSON" || { rm -f "$tmp"; die "mv failed updating nodes.json"; }

    # Load PrivateLink state
    local pl_state
    pl_state=$(pl_state_file)
    [[ -f "$pl_state" ]] && source "$pl_state"

    local vs
    vs=$(node_vs "$target_node")
    local peer_measurement="${EXPECTED_PEER_MEASUREMENT:-${EXPECTED_MEASUREMENT:-}}"

    # Regenerate coordinator configs for ALL nodes (uses updated nodes.json)
    step_coordinator_config

    local config_dir
    config_dir=$(coord_config_dir)
    local coord_config="${config_dir}/coordinator-node-${target_node}.json"

    local coord_args=""
    if [[ -f "$coord_config" ]]; then
        _scp_staging "$coord_config" < /dev/null
        _ssh_staging "sudo mkdir -p /etc/toprf && sudo mv /tmp/coordinator-node-${target_node}.json /etc/toprf/coordinator.json" < /dev/null
        coord_args="-v /etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro"
        echo "    Coordinator config uploaded to staging node"
    fi

    _ssh_staging "sudo docker run -d --name toprf-node --restart=unless-stopped \
        -e SEALED_KEY_URL='${staging_sealed_url}' \
        -e EXPECTED_VERIFICATION_SHARE=${vs} \
        -e EXPECTED_PEER_MEASUREMENT='${peer_measurement}' \
        -e AMD_ARK_FINGERPRINT='${AMD_ARK_FINGERPRINT:-}' \
        ${coord_args} \
        --device /dev/sev-guest:/dev/sev-guest \
        --user root \
        -p 3001:3001 \
        ${NODE_IMAGE} \
        --port 3001 \
        --coordinator-config /etc/toprf/coordinator.json" < /dev/null

    echo "  Waiting for staging node to become healthy..."
    local attempts=0
    while true; do
        if _ssh_staging "curl -sf http://localhost:3001/health" < /dev/null > /dev/null 2>&1; then
            echo "    Staging node healthy"
            break
        fi
        attempts=$((attempts + 1))
        [[ $attempts -lt 30 ]] || die "Staging node not healthy after 60s"
        sleep 2
    done

    # ── Step 6: Swap NLB targets ──
    echo ""
    echo "  ━━━ Step 6: Swap NLB targets ━━━"

    # Helper: wait for a target to become healthy in a target group
    _wait_target_healthy() {
        local _tg_arn="$1" _target_ip="$2" _tg_region="$3" _label="$4"
        local _attempts=0
        echo "    Waiting for $_target_ip to become healthy in ${_label}..."
        while true; do
            local _health
            _health=$(aws elbv2 describe-target-health --region "$_tg_region" \
                --target-group-arn "$_tg_arn" \
                --targets "Id=${_target_ip},Port=3001" \
                --query 'TargetHealthDescriptions[0].TargetHealth.State' --output text 2>/dev/null) || true
            if [[ "$_health" == "healthy" ]]; then
                echo "    $_target_ip: healthy in ${_label}"
                return 0
            fi
            _attempts=$((_attempts + 1))
            if [[ $_attempts -ge 30 ]]; then
                warn "$_target_ip not healthy in ${_label} after 60s (state: $_health) — continuing"
                return 0
            fi
            sleep 2
        done
    }

    # Per-node NLB target group
    local tg_var="PL_TG_ARN_NODE${target_node}"
    local tg_arn="${!tg_var:-}"
    if [[ -n "$tg_arn" ]]; then
        echo "  Per-node NLB ($tg_arn):"
        aws elbv2 deregister-targets --region "$region" \
            --target-group-arn "$tg_arn" \
            --targets "Id=${old_priv_ip},Port=3001" 2>/dev/null || true
        echo "    Deregistered: $old_priv_ip"
        aws elbv2 register-targets --region "$region" \
            --target-group-arn "$tg_arn" \
            --targets "Id=${staging_priv_ip},Port=3001"
        echo "    Registered: $staging_priv_ip"
        _wait_target_healthy "$tg_arn" "$staging_priv_ip" "$region" "per-node NLB"
    fi

    # Frontend NLB target group (only if node is in the coordinator VPC)
    local frontend_tg="${FRONTEND_TG_ARN:-}"
    local coord_vpc
    coord_vpc=$(node_vpc_id 1)
    local target_vpc
    target_vpc=$(node_vpc_id "$target_node")
    if [[ -n "$frontend_tg" && "$target_vpc" == "$coord_vpc" ]]; then
        echo "  Frontend NLB ($frontend_tg):"
        aws elbv2 deregister-targets --region "$region" \
            --target-group-arn "$frontend_tg" \
            --targets "Id=${old_priv_ip},Port=3001" 2>/dev/null || true
        echo "    Deregistered: $old_priv_ip"
        aws elbv2 register-targets --region "$region" \
            --target-group-arn "$frontend_tg" \
            --targets "Id=${staging_priv_ip},Port=3001"
        echo "    Registered: $staging_priv_ip"
        _wait_target_healthy "$frontend_tg" "$staging_priv_ip" "$region" "frontend NLB"
    fi

    # ── Step 7: Terminate old, finalize new, update other nodes ──
    echo ""
    echo "  ━━━ Step 7: Finalize ━━━"

    # Terminate old instance
    local old_instance
    old_instance=$(aws ec2 describe-instances --region "$region" \
        --filters "Name=tag:Name,Values=toprf-node-${target_node}" \
                  "Name=instance-state-name,Values=running" \
        --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null)
    if [[ -n "$old_instance" && "$old_instance" != "None" && "$old_instance" != "null" ]]; then
        echo "  Terminating old instance: $old_instance"
        aws ec2 terminate-instances --region "$region" --instance-ids "$old_instance" > /dev/null
    fi

    # Retag staging instance
    echo "  Retagging staging instance..."
    aws ec2 create-tags --region "$region" --resources "$staging_instance" \
        --tags "Key=Name,Value=toprf-node-${target_node}"

    # Rename S3 blob: staging → permanent
    echo "  Renaming sealed blob..."
    local canonical_s3="s3://${bucket}/node-${target_node}-sealed.bin"
    aws s3 cp "$staging_sealed_url" "$canonical_s3" --quiet
    # Verify the copy landed before deleting the source
    if aws s3 ls "$canonical_s3" > /dev/null 2>&1; then
        aws s3 rm "$staging_sealed_url" --quiet 2>/dev/null || true
    else
        warn "Could not verify copied blob at $canonical_s3 — keeping staging blob as backup"
    fi

    # Restart container with canonical sealed URL (for future auto-unseal)
    echo "  Restarting container with canonical sealed URL..."
    _ssh_staging "sudo docker rm -f toprf-node 2>/dev/null || true" < /dev/null
    _ssh_staging "sudo docker run -d --name toprf-node --restart=unless-stopped \
        -e SEALED_KEY_URL='${canonical_s3}' \
        -e EXPECTED_VERIFICATION_SHARE=${vs} \
        -e EXPECTED_PEER_MEASUREMENT='${peer_measurement}' \
        -e AMD_ARK_FINGERPRINT='${AMD_ARK_FINGERPRINT:-}' \
        ${coord_args} \
        --device /dev/sev-guest:/dev/sev-guest \
        --user root \
        -p 3001:3001 \
        ${NODE_IMAGE} \
        --port 3001 \
        --coordinator-config /etc/toprf/coordinator.json" < /dev/null

    attempts=0
    while true; do
        if _ssh_staging "curl -sf http://localhost:3001/health" < /dev/null > /dev/null 2>&1; then
            echo "    Node healthy after restart"
            break
        fi
        attempts=$((attempts + 1))
        [[ $attempts -lt 30 ]] || die "Node not healthy after restart"
        sleep 2
    done

    # Update coordinator configs on OTHER running nodes (they need the new peer IP)
    echo "  Updating coordinator configs on other nodes..."
    for i in $donor_ids; do
        local other_config="${config_dir}/coordinator-node-${i}.json"
        if [[ -f "$other_config" ]]; then
            scp_to_node "$i" "$other_config" < /dev/null || { warn "Failed to upload config to node $i"; continue; }
            ssh_node "$i" "sudo mkdir -p /etc/toprf && sudo mv /tmp/coordinator-node-${i}.json /etc/toprf/coordinator.json" < /dev/null
            # Restart node to pick up new config
            ssh_node "$i" "sudo docker rm -f toprf-node 2>/dev/null || true" < /dev/null

            local other_vs other_url
            other_vs=$(node_vs "$i")
            other_url=$(sealed_url "$i")
            local other_coord_args="-v /etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro"

            ssh_node "$i" "sudo docker run -d --name toprf-node --restart=unless-stopped \
                -e SEALED_KEY_URL='${other_url}' \
                -e EXPECTED_VERIFICATION_SHARE=${other_vs} \
                -e EXPECTED_PEER_MEASUREMENT='${peer_measurement}' \
                -e AMD_ARK_FINGERPRINT='${AMD_ARK_FINGERPRINT:-}' \
                ${other_coord_args} \
                --device /dev/sev-guest:/dev/sev-guest \
                --user root \
                -p 3001:3001 \
                ${NODE_IMAGE} \
                --port 3001 \
                --coordinator-config /etc/toprf/coordinator.json" < /dev/null

            # Wait for donor node to come back healthy
            local _donor_attempts=0
            while true; do
                if ssh_node "$i" "curl -sf http://localhost:3001/health" < /dev/null > /dev/null 2>&1; then
                    echo "    Node $i: healthy"
                    break
                fi
                _donor_attempts=$((_donor_attempts + 1))
                if [[ $_donor_attempts -ge 30 ]]; then
                    warn "Node $i not healthy after 60s — continuing (may need manual check)"
                    break
                fi
                sleep 2
            done
        fi
    done

    # Delete staging key pair
    echo "  Cleaning up staging key..."
    aws ec2 delete-key-pair --region "$region" --key-name "$staging_key" 2>/dev/null || true
    rm -f "$staging_key_file"

    # Clear cleanup trap (artifacts cleaned up below)
    trap - EXIT
    aws s3 rm "s3://${bucket}/reshare/" --recursive --quiet 2>/dev/null || true
    rm -rf "$tmpdir"

    echo ""
    echo "  ━━━ Rotation complete ━━━"
    echo "  Node $target_node replaced successfully."
    echo "  Old instance terminated, staging instance is now the live node."
    echo "  Other nodes' coordinator configs updated."
    echo ""
    echo "  To lock the node (remove SSH): ./deploy.sh --nodes $target_node lock"
}

# ─── 18. Frontend NLB (Lambda → nodes failover) ──────────────────────────────
#
# Creates a single NLB in eu-west-1 that targets all same-region nodes.
# The evaluate Lambda hits this NLB — if one node dies, traffic routes to
# the surviving node automatically via NLB health checks.
# Per-node NLBs (used for PrivateLink) are untouched.

step_frontend_nlb() {
    echo ""
    info "Setting up frontend NLB (Lambda → nodes failover)"

    local pl_state
    pl_state=$(pl_state_file)

    # Load existing state
    [[ -f "$pl_state" ]] && source "$pl_state"

    # Determine the coordinator region (node 1's region)
    local coord_region coord_vpc coord_subnet
    coord_region=$(node_region 1)
    coord_vpc=$(node_vpc_id 1)
    coord_subnet=$(node_subnet_id 1)
    [[ -n "$coord_vpc" ]] || die "Node 1 VPC not set. Run auto-config first."

    # Find a second subnet in a different AZ
    local second_subnet
    second_subnet=$(aws ec2 describe-subnets --region "$coord_region" \
        --filters "Name=vpc-id,Values=$coord_vpc" \
        --query "Subnets[?SubnetId!='${coord_subnet}'] | [0].SubnetId" --output text)
    [[ -n "$second_subnet" && "$second_subnet" != "None" ]] || die "No second subnet in VPC $coord_vpc"

    # ── 1. Create frontend NLB ──
    local nlb_arn="${FRONTEND_NLB_ARN:-}"
    if [[ -z "$nlb_arn" ]]; then
        echo "  Creating frontend NLB (2 AZs: $coord_subnet, $second_subnet)..."
        nlb_arn=$(aws elbv2 create-load-balancer \
            --region "$coord_region" \
            --name "toprf-frontend-nlb" \
            --type network \
            --scheme internal \
            --subnets "$coord_subnet" "$second_subnet" \
            --query 'LoadBalancers[0].LoadBalancerArn' --output text)
        echo "FRONTEND_NLB_ARN=${nlb_arn}" >> "$pl_state"
        aws elbv2 add-tags --region "$coord_region" --resource-arns "$nlb_arn" \
            --tags $(project_tags) 2>/dev/null || true
        echo "    NLB: $nlb_arn"

        echo "  Waiting for NLB to become active..."
        aws elbv2 wait load-balancer-available \
            --region "$coord_region" \
            --load-balancer-arns "$nlb_arn" 2>/dev/null || true
        # Verify NLB is actually active (wait can exit early or silently fail)
        local _nlb_state
        _nlb_state=$(aws elbv2 describe-load-balancers --region "$coord_region" \
            --load-balancer-arns "$nlb_arn" \
            --query 'LoadBalancers[0].State.Code' --output text 2>/dev/null)
        [[ "$_nlb_state" == "active" ]] || die "Frontend NLB $nlb_arn is not active (state: $_nlb_state)"
        echo "    NLB active."
    else
        echo "    Frontend NLB: $nlb_arn (exists)"
    fi

    # Save DNS
    local nlb_dns="${FRONTEND_NLB_DNS:-}"
    if [[ -z "$nlb_dns" ]]; then
        nlb_dns=$(aws elbv2 describe-load-balancers --region "$coord_region" \
            --load-balancer-arns "$nlb_arn" \
            --query 'LoadBalancers[0].DNSName' --output text)
        echo "FRONTEND_NLB_DNS=${nlb_dns}" >> "$pl_state"
        echo "    DNS: $nlb_dns"
    else
        echo "    DNS: $nlb_dns (exists)"
    fi

    # ── 2. Create target group ──
    local tg_arn="${FRONTEND_TG_ARN:-}"
    if [[ -z "$tg_arn" ]]; then
        echo "  Creating target group (health check: HTTP /health)..."
        tg_arn=$(aws elbv2 create-target-group \
            --region "$coord_region" \
            --name "toprf-frontend-tg" \
            --protocol TCP --port 3001 \
            --vpc-id "$coord_vpc" \
            --target-type ip \
            --health-check-protocol HTTP \
            --health-check-path /health \
            --health-check-interval-seconds 10 \
            --healthy-threshold-count 2 \
            --unhealthy-threshold-count 2 \
            --query 'TargetGroups[0].TargetGroupArn' --output text)
        echo "FRONTEND_TG_ARN=${tg_arn}" >> "$pl_state"
        aws elbv2 add-tags --region "$coord_region" --resource-arns "$tg_arn" \
            --tags $(project_tags) 2>/dev/null || true
        echo "    TG: $tg_arn"
    else
        echo "    TG: $tg_arn (exists)"
    fi

    # ── 3. Reconcile targets (register same-region nodes, deregister stale IPs) ──
    echo "  Reconciling frontend NLB targets..."

    # Build expected target set
    local expected_ips=""
    for i in $(active_nodes); do
        local node_vpc_i
        node_vpc_i=$(node_vpc_id "$i")
        if [[ "$node_vpc_i" == "$coord_vpc" ]]; then
            local pip
            pip=$(node_private_ip "$i")
            expected_ips="$expected_ips $pip"
        fi
    done

    # Deregister stale targets
    local current_targets
    current_targets=$(aws elbv2 describe-target-health --region "$coord_region" \
        --target-group-arn "$tg_arn" \
        --query 'TargetHealthDescriptions[*].Target.Id' --output text 2>/dev/null) || true
    for old_ip in $current_targets; do
        if [[ ! " $expected_ips " =~ " $old_ip " ]]; then
            aws elbv2 deregister-targets --region "$coord_region" \
                --target-group-arn "$tg_arn" \
                --targets "Id=${old_ip},Port=3001" 2>/dev/null || true
            echo "    Deregistered stale target: ${old_ip}"
        fi
    done

    # Register current targets
    for i in $(active_nodes); do
        local node_region_i node_vpc_i private_ip
        node_region_i=$(node_region "$i")
        node_vpc_i=$(node_vpc_id "$i")
        if [[ "$node_vpc_i" == "$coord_vpc" ]]; then
            private_ip=$(node_private_ip "$i")
            if [[ ! " $current_targets " =~ " $private_ip " ]]; then
                aws elbv2 register-targets --region "$coord_region" \
                    --target-group-arn "$tg_arn" \
                    --targets "Id=${private_ip},Port=3001"
                echo "    Node $i ($private_ip): registered (new)"
            else
                echo "    Node $i ($private_ip): already registered"
            fi
        else
            echo "    Node $i: skipped (different VPC — $node_region_i)"
        fi
    done

    # ── 4. Create listener ──
    local listener_arn="${FRONTEND_NLB_LISTENER:-}"
    if [[ -z "$listener_arn" ]]; then
        echo "  Creating listener (TCP :3001)..."
        listener_arn=$(aws elbv2 create-listener \
            --region "$coord_region" \
            --load-balancer-arn "$nlb_arn" \
            --protocol TCP --port 3001 \
            --default-actions "Type=forward,TargetGroupArn=${tg_arn}" \
            --query 'Listeners[0].ListenerArn' --output text)
        echo "FRONTEND_NLB_LISTENER=${listener_arn}" >> "$pl_state"
        echo "    Listener: $listener_arn"
    else
        echo "    Listener: exists"
    fi

    echo ""
    echo "  Frontend NLB ready."
    echo "    DNS: $nlb_dns"
    echo "    URL: http://${nlb_dns}:3001"
    echo "    Targets: all nodes in VPC $coord_vpc"
    echo ""
    echo "  The evaluate Lambda should use NLB_URL=http://${nlb_dns}:3001"
    echo "  Run './deploy.sh lambda-config' to auto-update lambda/config.env."
}

# ─── 18. Lambda config auto-generation ────────────────────────────────────────

step_lambda_config() {
    echo ""
    info "Generating lambda/config.env from deployment state"

    local pl_state
    pl_state=$(pl_state_file)
    [[ -f "$pl_state" ]] || die "$(basename "$pl_state") not found. Run './deploy.sh privatelink' first."
    source "$pl_state"

    local lambda_config="${REPO_ROOT}/lambda/config.env"
    local lambda_example="${REPO_ROOT}/lambda/config.env.example"
    [[ -f "$lambda_example" ]] || die "lambda/config.env.example not found."

    # ── Gather values ──

    # Account ID
    local account_id
    account_id=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) \
        || die "Could not determine AWS account ID"

    # Frontend NLB DNS (multi-node failover) — falls back to node 1 NLB if frontend not set up
    local nlb_dns="${FRONTEND_NLB_DNS:-${NLB_DNS_NODE1:-}}"
    [[ -n "$nlb_dns" ]] || die "No NLB DNS found. Run './deploy.sh frontend-nlb' (or at least 'privatelink')."
    local nlb_url="http://${nlb_dns}:3001"
    if [[ -n "${FRONTEND_NLB_DNS:-}" ]]; then
        echo "  Using frontend NLB (multi-node failover)"
    else
        warn "Frontend NLB not set up — using node 1 NLB only. Run './deploy.sh frontend-nlb' for failover."
    fi

    # VPC subnets for the evaluate Lambda (node 1's VPC — where the NLB is)
    local coord_region coord_vpc coord_subnet
    coord_region=$(node_region 1)
    coord_vpc=$(node_vpc_id 1)
    coord_subnet=$(node_subnet_id 1)

    local second_subnet
    second_subnet=$(aws ec2 describe-subnets --region "$coord_region" \
        --filters "Name=vpc-id,Values=$coord_vpc" \
        --query "Subnets[?SubnetId!='${coord_subnet}'] | [0].SubnetId" --output text 2>/dev/null)
    [[ -n "$second_subnet" && "$second_subnet" != "None" ]] || die "No second subnet in coordinator VPC $coord_vpc"

    local vpc_subnets="${coord_subnet},${second_subnet}"

    # Security group — use the node's SG (already allows port 3001 from VPC CIDR)
    local vpc_sg
    vpc_sg=$(node_sg_id 1)
    [[ -n "$vpc_sg" ]] || die "No security group for node 1"

    # ── Write or update lambda/config.env ──

    if [[ -f "$lambda_config" ]]; then
        echo "  Updating existing lambda/config.env..."
        # Update only the auto-fillable fields, preserve the rest
        for kv in \
            "ACCOUNT_ID=${account_id}" \
            "REGION=${coord_region}" \
            "VPC_SUBNETS=${vpc_subnets}" \
            "VPC_SG=${vpc_sg}" \
            "NLB_URL=${nlb_url}"; do
            local key="${kv%%=*}"
            local val="${kv#*=}"
            if grep -q "^${key}=" "$lambda_config"; then
                sed -i.bak "s|^${key}=.*|${key}=${val}|" "$lambda_config" && rm -f "${lambda_config}.bak"
            else
                echo "${key}=${val}" >> "$lambda_config"
            fi
        done
    else
        echo "  Creating lambda/config.env from example..."
        cp "$lambda_example" "$lambda_config"
        sed -i.bak "s|^ACCOUNT_ID=.*|ACCOUNT_ID=${account_id}|" "$lambda_config" && rm -f "${lambda_config}.bak"
        sed -i.bak "s|^REGION=.*|REGION=${coord_region}|" "$lambda_config" && rm -f "${lambda_config}.bak"
        sed -i.bak "s|^VPC_SUBNETS=.*|VPC_SUBNETS=${vpc_subnets}|" "$lambda_config" && rm -f "${lambda_config}.bak"
        sed -i.bak "s|^VPC_SG=.*|VPC_SG=${vpc_sg}|" "$lambda_config" && rm -f "${lambda_config}.bak"
        sed -i.bak "s|^NLB_URL=.*|NLB_URL=${nlb_url}|" "$lambda_config" && rm -f "${lambda_config}.bak"
    fi

    echo ""
    echo "  Auto-populated:"
    echo "    ACCOUNT_ID   = ${account_id}"
    echo "    REGION       = ${coord_region}"
    echo "    VPC_SUBNETS  = ${vpc_subnets}"
    echo "    VPC_SG       = ${vpc_sg}"
    echo "    NLB_URL      = ${nlb_url}"
    echo ""
    echo "  Still manual (fill in before running lambda/deploy.sh):"
    echo "    API_ID, APPLE_APP_ID, APPLE_TEAM_ID, ROLE_ARN"
    echo "    NONCES_TABLE, DEVICE_KEYS_TABLE"
    echo ""
    echo "  File: $lambda_config"
}

# ─── Sync state to SSM Parameter Store (for rotation Lambda) ─────────────

step_sync_state() {
    echo ""
    info "Syncing local state to SSM Parameter Store"

    load_ceremony

    local pl_state
    pl_state=$(pl_state_file)
    [[ -f "$pl_state" ]] || die "$(basename "$pl_state") not found. Run './deploy.sh privatelink' first."
    source "$pl_state"

    local ssm_prefix="${SSM_PREFIX:-/toprf}"
    local coord_region
    coord_region=$(node_region 1)
    local coord_vpc
    coord_vpc=$(node_vpc_id 1)
    local coord_vi
    coord_vi=$(vpc_ident "$coord_vpc")

    # Build config JSON from nodes.json + runtime state
    local config_json
    config_json=$(jq '.' "$NODES_JSON")

    # Add per-node runtime fields
    for i in $(all_node_ids); do
        local tg_var="PL_TG_ARN_NODE${i}"
        local tg_arn="${!tg_var:-}"
        local nlb_endpoint=""

        # Determine Lambda-accessible endpoint for this node
        # (Lambda runs in the coordinator VPC)
        local node_vpc_i
        node_vpc_i=$(node_vpc_id "$i")
        if [[ "$node_vpc_i" == "$coord_vpc" ]]; then
            # Same VPC: use NLB DNS directly
            local nlb_dns_var="NLB_DNS_NODE${i}"
            nlb_endpoint="http://${!nlb_dns_var:-}:3001"
        else
            # Cross-VPC: use PrivateLink VPCE DNS
            local vpce_dns_var="VPCE_DNS_NODE${i}_IN_${coord_vi}"
            nlb_endpoint="http://${!vpce_dns_var:-}:3001"
        fi

        local vs
        vs=$(node_vs "$i")

        config_json=$(echo "$config_json" | jq \
            --argjson id "$i" \
            --arg tg "$tg_arn" \
            --arg ep "$nlb_endpoint" \
            --arg vs "$vs" \
            '(.nodes[] | select(.id == $id)) |= . + {
                tg_arn: $tg,
                nlb_endpoint: $ep,
                verification_share: $vs
            }')
    done

    # Add top-level config fields
    config_json=$(echo "$config_json" | jq \
        --arg gpk "$GROUP_PUBLIC_KEY" \
        --arg image "$NODE_IMAGE" \
        --arg itype "${INSTANCE_TYPE:-c6a.large}" \
        --arg frontend_tg "${FRONTEND_TG_ARN:-}" \
        --arg coord_vpc "$coord_vpc" \
        '. + {
            group_public_key: $gpk,
            node_image: $image,
            instance_type: $itype,
            frontend_tg_arn: $frontend_tg,
            coordinator_vpc_id: $coord_vpc
        }')

    # Push config to SSM
    echo "  Pushing config to ${ssm_prefix}/config..."
    aws ssm put-parameter \
        --name "${ssm_prefix}/config" \
        --value "$config_json" \
        --type SecureString \
        --overwrite \
        --region "$coord_region" > /dev/null
    echo "    Done."

    # Push measurement
    local measurement="${EXPECTED_PEER_MEASUREMENT:-${EXPECTED_MEASUREMENT:-}}"
    if [[ -n "$measurement" ]]; then
        echo "  Pushing measurement to ${ssm_prefix}/measurement..."
        aws ssm put-parameter \
            --name "${ssm_prefix}/measurement" \
            --value "$measurement" \
            --type String \
            --overwrite \
            --region "$coord_region" > /dev/null
        echo "    Done."
    fi

    # Push ARK fingerprint
    if [[ -n "${AMD_ARK_FINGERPRINT:-}" ]]; then
        echo "  Pushing ARK fingerprint to ${ssm_prefix}/ark-fingerprint..."
        aws ssm put-parameter \
            --name "${ssm_prefix}/ark-fingerprint" \
            --value "$AMD_ARK_FINGERPRINT" \
            --type String \
            --overwrite \
            --region "$coord_region" > /dev/null
        echo "    Done."
    fi

    # Push per-node coordinator configs
    local config_dir
    config_dir=$(coord_config_dir)
    if [[ -d "$config_dir" ]]; then
        for i in $(all_node_ids); do
            local coord_config="${config_dir}/coordinator-node-${i}.json"
            if [[ -f "$coord_config" ]]; then
                echo "  Pushing coordinator config for node $i..."
                aws ssm put-parameter \
                    --name "${ssm_prefix}/coordinator-config/${i}" \
                    --value "$(cat "$coord_config")" \
                    --type String \
                    --overwrite \
                    --region "$coord_region" > /dev/null
                echo "    Done."
            fi
        done
    fi

    echo ""
    echo "  State synced to SSM (prefix: ${ssm_prefix}, region: ${coord_region})"
}

# =============================================================================
# CLI
# =============================================================================

usage() {
    cat <<'EOF'
Usage: deploy.sh [--nodes 1,2,3] <step> [step...]

Options:
  --nodes N     Operate on specific node(s) only (comma-separated)

Steps (run in order for fresh deployment):
  setup-vms     Install Docker on VMs
  pull          Pull node image from ghcr.io on each VM
  storage       Create S3 buckets for sealed key blobs
  measure       Fetch SEV-SNP measurement from a running node (saves to config.env)
  init-seal     S3-mediated ECIES key injection (attested)
  privatelink   Create NLBs, Endpoint Services, cross-VPC VPC Endpoints
  coordinator-config  Generate per-node coordinator configs (peer endpoints)
  start         Start nodes in coordinator mode (unseal + serve)
  verify        Health check all nodes (via SSH)
  e2e           End-to-end verify: OPRF evaluate via coordinator
  cloudwatch    Create CloudWatch alarms for unhealthy node detection
  frontend-nlb  Create frontend NLB targeting same-region nodes (Lambda failover)

Rotation:
  rotate <N>    Zero-downtime node replacement (staging-based reshare)
                Requires: ./provision.sh <N> --staging first

Utilities:
  auto-config   Auto-populate nodes.json from AWS
  show-ips      Fetch public/private IPs for all nodes
  lambda-config Auto-generate lambda/config.env from deployment state
  sync-state    Push local state to SSM Parameter Store (for rotation Lambda)
  lock          Remove SSH access + delete keys (irreversible)

Shortcuts:
  pre-seal      setup-vms → pull → storage → measure
  post-seal     privatelink → coordinator-config → start → verify → frontend-nlb
  all           pre-seal → init-seal → post-seal
  redeploy      pull latest image → restart nodes
EOF
}

if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

# Parse --nodes flag and rotate argument before processing steps
steps=()
ROTATE_NODE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --nodes|-n)
            shift
            _NODE_FILTER=$(echo "$1" | tr ',' ' ')
            shift
            ;;
        rotate)
            steps+=("rotate")
            shift
            if [[ $# -gt 0 && "$1" != -* ]]; then
                ROTATE_NODE="$1"
                shift
            fi
            ;;
        *)
            steps+=("$1")
            shift
            ;;
    esac
done

if [[ ${#steps[@]} -eq 0 ]]; then
    usage
    exit 0
fi

if [[ -n "$_NODE_FILTER" ]]; then
    info "Operating on node(s): $_NODE_FILTER"
fi

for step in "${steps[@]}"; do
    case "$step" in
        pull)         step_pull ;;
        storage)      step_storage ;;
        measure)      step_measure ;;
        setup-vms)    step_setup_vms ;;
        privatelink)  step_privatelink ;;
        init-seal)    step_init_seal ;;
        start)        step_start ;;
        coordinator-config) step_coordinator_config ;;
        verify)       step_verify ;;
        e2e)          step_e2e ;;
        cloudwatch)   step_cloudwatch ;;
        frontend-nlb) step_frontend_nlb ;;
        rotate)
            [[ -n "${ROTATE_NODE:-}" ]] || die "rotate requires a node ID: ./deploy.sh rotate <N>"
            step_rotate
            ;;
        auto-config)  step_auto_config ;;
        show-ips)     step_show_ips ;;
        lambda-config) step_lambda_config ;;
        sync-state)   step_sync_state ;;
        redeploy)     step_redeploy ;;
        lock)         step_lock ;;
        pre-seal)
            step_setup_vms
            step_pull
            step_storage
            step_measure
            ;;
        post-seal)
            step_privatelink
            step_coordinator_config
            step_start
            step_verify
            step_frontend_nlb
            ;;
        all)
            step_setup_vms
            step_pull
            step_storage
            step_measure
            echo ""
            echo "═══════════════════════════════════════════════════"
            echo "  Pre-seal steps complete. Measurement saved."
            echo "  Next: init-seal (interactive key injection)."
            echo "═══════════════════════════════════════════════════"
            step_init_seal
            step_privatelink
            step_coordinator_config
            step_start
            step_verify
            step_frontend_nlb
            ;;
        -h|--help|help)
            usage ;;
        *)
            echo "Unknown step: $step"
            usage
            exit 1
            ;;
    esac
done
