#!/usr/bin/env bash
# =============================================================================
# deploy.sh — Automated deployment for threshold OPRF nodes on AWS.
#
# Deploys 3 TEE nodes (Amazon Linux 2023) across AWS regions. Each node can
# act as coordinator: receiving a client request, computing its own partial
# evaluation, calling a peer node via PrivateLink, verifying the peer's DLEQ
# proof, and returning the combined OPRF evaluation.
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
Usage: deploy.sh [--slot NAME] [--nodes 1,2,3] <step> [step...]

Options:
  --slot NAME   Blue-green slot name (e.g., blue, green). Resources are
                named and tagged with this slot for zero-downtime rotation.
  --nodes N     Operate on specific node(s) only (comma-separated)

Steps (run in order for fresh deployment):
  setup-vms     Install Docker on VMs
  pull          Pull node image from ghcr.io on each VM
  storage       Create S3 buckets for sealed key blobs
  init-seal     S3-mediated ECIES key injection (attested)
  privatelink   Create NLBs, Endpoint Services, cross-VPC VPC Endpoints
  coordinator-config  Generate per-node coordinator configs (peer endpoints)
  start         Start nodes in coordinator mode (unseal + serve)
  verify        Health check all nodes (via SSH)
  e2e           End-to-end verify: OPRF evaluate via coordinator

Blue-green:
  cutover       Update Lambda NLB_URL to this slot's coordinator NLB
  teardown      Delete all AWS resources tagged with this slot

Utilities:
  auto-config   Auto-populate config.env from AWS
  show-ips      Fetch public/private IPs for all nodes
  lock          Remove SSH access + delete keys (irreversible)

Shortcuts:
  pre-seal      setup-vms → pull → storage
  post-seal     privatelink → coordinator-config → start → verify
  all           pre-seal → init-seal → post-seal
  redeploy      pull latest image → restart nodes

Blue-green example:
  SLOT=green ./provision.sh all           # Provision new VMs
  ./deploy.sh --slot green all            # Deploy new set
  ./deploy.sh --slot green cutover        # Switch traffic
  ./deploy.sh --slot blue teardown        # Tear down old set
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

# ─── Derived values ──────────────────────────────────────────────────────────

NODE_IMAGE="${NODE_IMAGE:-ghcr.io/${GHCR_OWNER:-jeganggs64}/toprf-node:latest}"

# ─── Slot system (blue-green deployments) ─────────────────────────────────────
# Set via --slot flag. When set, resource names and state files are slot-scoped.
# Resources are tagged with Slot=<slot> for discovery during teardown.

SLOT="${SLOT:-}"

slot_suffix()    { [[ -n "$SLOT" ]] && echo "-${SLOT}" || echo ""; }
vm_tag()         { echo "toprf-node-${1}$(slot_suffix)"; }
nlb_name()       { echo "toprf-node-${1}$(slot_suffix)-nlb"; }
tg_name()        { echo "toprf-node-${1}$(slot_suffix)-tg"; }
vpce_sg_name()   { echo "toprf-privatelink-vpce-${1}$(slot_suffix)"; }
pl_state_file()  { [[ -n "$SLOT" ]] && echo "${SCRIPT_DIR}/privatelink-state-${SLOT}.env" || echo "${SCRIPT_DIR}/privatelink-state.env"; }
coord_config_dir() { [[ -n "$SLOT" ]] && echo "${SCRIPT_DIR}/coordinator-configs-${SLOT}" || echo "${SCRIPT_DIR}/coordinator-configs"; }

slot_tags() {
    # Returns AWS tag args for tagging resources with slot + project
    if [[ -n "$SLOT" ]]; then
        echo "Key=Slot,Value=${SLOT} Key=Project,Value=toprf"
    else
        echo "Key=Project,Value=toprf"
    fi
}

# ─── Helpers ─────────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
warn()  { echo "  WARN: $*"; }
die()   { echo "  ERROR: $*" >&2; exit 1; }

node_region() {
    case "$1" in
        1) echo "$NODE1_REGION" ;;
        2) echo "$NODE2_REGION" ;;
        3) echo "$NODE3_REGION" ;;
    esac
}

node_ip() {
    case "$1" in
        1) echo "$NODE1_IP" ;;
        2) echo "$NODE2_IP" ;;
        3) echo "$NODE3_IP" ;;
    esac
}

node_private_ip() {
    case "$1" in
        1) echo "$NODE1_PRIVATE_IP" ;;
        2) echo "$NODE2_PRIVATE_IP" ;;
        3) echo "$NODE3_PRIVATE_IP" ;;
    esac
}

node_ssh_key() {
    case "$1" in
        1) echo "$NODE1_SSH_KEY" ;;
        2) echo "$NODE2_SSH_KEY" ;;
        3) echo "$NODE3_SSH_KEY" ;;
    esac
}

node_sg_id() {
    case "$1" in
        1) echo "$NODE1_SG_ID" ;;
        2) echo "$NODE2_SG_ID" ;;
        3) echo "$NODE3_SG_ID" ;;
    esac
}

node_vpc_id() {
    case "$1" in
        1) echo "$NODE1_VPC_ID" ;;
        2) echo "$NODE2_VPC_ID" ;;
        3) echo "$NODE3_VPC_ID" ;;
    esac
}

node_subnet_id() {
    case "$1" in
        1) echo "$NODE1_SUBNET_ID" ;;
        2) echo "$NODE2_SUBNET_ID" ;;
        3) echo "$NODE3_SUBNET_ID" ;;
    esac
}

node_s3_bucket() {
    case "$1" in
        1) echo "$NODE1_S3_BUCKET" ;;
        2) echo "$NODE2_S3_BUCKET" ;;
        3) echo "$NODE3_S3_BUCKET" ;;
    esac
}

# Convert VPC ID to variable-safe identifier: vpc-0abc → vpc_0abc
vpc_ident() { echo "${1//-/_}"; }

sealed_url() {
    local bucket
    bucket=$(node_s3_bucket "$1")
    echo "s3://${bucket}/node-${1}-sealed.bin"
}

# Node filter: set via --nodes flag (e.g. --nodes 1,3)
_NODE_FILTER=""

active_nodes() {
    if [[ -n "$_NODE_FILTER" ]]; then
        echo "$_NODE_FILTER"
        return
    fi
    local nodes=""
    [[ -n "${NODE1_IP:-}" ]] && nodes="$nodes 1"
    [[ -n "${NODE2_IP:-}" ]] && nodes="$nodes 2"
    [[ -n "${NODE3_IP:-}" ]] && nodes="$nodes 3"
    echo $nodes
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
    THRESHOLD=$(jq -r '.threshold' "$config")
    VS_1=$(jq -r '.verification_shares[] | select(.node_id == 1) | .verification_share' "$config")
    VS_2=$(jq -r '.verification_shares[] | select(.node_id == 2) | .verification_share' "$config")
    VS_3=$(jq -r '.verification_shares[] | select(.node_id == 3) | .verification_share' "$config")
    _ceremony_loaded=true
}

node_vs() {
    load_ceremony
    case "$1" in
        1) echo "$VS_1" ;;
        2) echo "$VS_2" ;;
        3) echo "$VS_3" ;;
    esac
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
        ssh_node "$i" "sudo docker pull ${NODE_IMAGE}"
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
        aws s3 mb "s3://${bucket}" --region "$region" 2>/dev/null \
            || warn "bucket may already exist"
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
)"
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
    info "Setting up AWS PrivateLink (node-to-node)${SLOT:+ [slot: $SLOT]}"

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

        [[ -n "$subnet_id" ]] || die "NODE${i}_SUBNET_ID not set in config.env. Run auto-config or set manually."

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
                --tags $(slot_tags) 2>/dev/null || true
            echo "    NLB: $nlb_arn"
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
                --tags $(slot_tags) 2>/dev/null || true
            echo "    TG: $tg_arn"

            aws elbv2 register-targets --region "$region" \
                --target-group-arn "$tg_arn" \
                --targets "Id=${private_ip},Port=3001"
            echo "    Registered target: ${private_ip}:3001"
        else
            echo "    TG: $tg_arn (exists)"
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

        # ── 4. Wait for NLB to be active ──
        echo "  Waiting for NLB to become active..."
        aws elbv2 wait load-balancer-available \
            --region "$region" \
            --load-balancer-arns "$nlb_arn" 2>/dev/null || true
        echo "    NLB active."

        # ── 5. VPC Endpoint Service ──
        local svc_var="ENDPOINT_SVC_ID_NODE${i}"
        local svc_id="${!svc_var:-}"
        if [[ -z "$svc_id" ]]; then
            echo "  Creating VPC Endpoint Service..."
            svc_id=$(aws ec2 create-vpc-endpoint-service-configuration \
                --region "$region" \
                --network-load-balancer-arns "$nlb_arn" \
                --no-acceptance-required \
                --query 'ServiceConfiguration.ServiceId' --output text)
            echo "${svc_var}=${svc_id}" >> "$pl_state"
            aws ec2 create-tags --region "$region" --resources "$svc_id" \
                --tags $(slot_tags) 2>/dev/null || true
            echo "    Endpoint Service: $svc_id"

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
                --cidr "$vpc_cidr"
            echo "${sg_var}=${sg_id}" >> "$pl_state"
            eval "${sg_var}=${sg_id}"
            aws ec2 create-tags --region "$my_region" --resources "$sg_id" \
                --tags $(slot_tags) 2>/dev/null || true
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
                svc_name="${!svc_name_var}"
                sg_var="VPCE_SG_${my_vi}"
                sg_id="${!sg_var}"

                echo "  Creating VPCE for node $j in $my_vpc ($my_region)..."

                # Find a second subnet in a different AZ within the consumer VPC
                local second_subnet
                second_subnet=$(aws ec2 describe-subnets --region "$my_region" \
                    --filters "Name=vpc-id,Values=$my_vpc" \
                    --query "Subnets[?SubnetId!='${my_subnet}'] | [0].SubnetId" --output text)

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
                fi

                vpce_id=$(aws ec2 create-vpc-endpoint \
                    "${vpce_args[@]}" \
                    --query 'VpcEndpoint.VpcEndpointId' --output text)
                echo "${vpce_id_var}=${vpce_id}" >> "$pl_state"
                eval "${vpce_id_var}=${vpce_id}"
                aws ec2 create-tags --region "$my_region" --resources "$vpce_id" \
                    --tags $(slot_tags) 2>/dev/null || true
                echo "    VPCE: $vpce_id"
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
                        warn "Could not get DNS for $vpce_id after 5 minutes"
                        vpce_dns=""
                        break
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

    # Get expected measurement (operator should set this in config.env or env)
    local expected_measurement="${EXPECTED_MEASUREMENT:-}"
    if [[ -z "$expected_measurement" ]]; then
        echo ""
        echo "  EXPECTED_MEASUREMENT not set. Enter the expected measurement (96 hex chars),"
        echo "  or press Enter to skip attestation verification (dev only):"
        read -r expected_measurement < /dev/tty
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
            --privileged --user root \
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

        if [[ -n "$expected_measurement" ]]; then
            encrypt_args+=(--expected-measurement "$expected_measurement")
        else
            encrypt_args+=(--skip-attestation-verify --expected-measurement "$(printf '%096d' 0)")
            echo "  WARNING: skipping attestation verification (dev mode)"
        fi

        echo "  Verifying attestation and encrypting key share..."
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

    local config_dir
    config_dir=$(coord_config_dir)

    for i in $(active_nodes); do
        local ip vs url
        ip=$(node_ip "$i")
        vs=$(node_vs "$i")
        url=$(sealed_url "$i")

        echo "  Node $i ($ip)..."

        ssh_node "$i" "sudo docker rm -f toprf-node 2>/dev/null || true"

        # Upload coordinator config if it exists
        local coord_config="${config_dir}/coordinator-node-${i}.json"
        local coord_args=""
        if [[ -f "$coord_config" ]]; then
            scp_to_node "$i" "$coord_config"
            ssh_node "$i" "sudo mkdir -p /etc/toprf && sudo mv /tmp/coordinator-node-${i}.json /etc/toprf/coordinator.json"
            coord_args="-v /etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro"
            echo "    Coordinator config uploaded"
        fi

        ssh_node "$i" "sudo docker run -d --name toprf-node --restart=unless-stopped \
            -e SEALED_KEY_URL='${url}' \
            -e EXPECTED_VERIFICATION_SHARE=${vs} \
            ${coord_args} \
            --device /dev/sev-guest:/dev/sev-guest \
            --privileged --user root \
            -p 3001:3001 \
            ${NODE_IMAGE} \
            --port 3001 \
            --coordinator-config /etc/toprf/coordinator.json"
    done

    echo "  Waiting for nodes to boot..."
    sleep 5
    echo "  Done. Run './deploy.sh verify' to check health."
}

# ─── 9. Generate coordinator configs ─────────────────────────────────────────

step_coordinator_config() {
    echo ""
    info "Generating coordinator configs (per-node peer endpoints)${SLOT:+ [slot: $SLOT]}"

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

    # 2. Coordinator test (via SSH to node 1, calls /evaluate which coordinates with a peer)
    echo ""
    echo "  [2/3] Coordinator evaluate (node 1 → peer via PrivateLink)"
    total=$((total + 1))

    # Use a known test blinded point (valid secp256k1 point)
    local test_point="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

    local eval_resp
    eval_resp=$(ssh_node "1" "curl -s --connect-timeout 10 \
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

    # 3. Domain endpoint (if API Gateway is configured)
    echo ""
    echo "  [3/3] Domain endpoint (https://${domain})"
    total=$((total + 1))

    local domain_resp
    domain_resp=$(curl -s --connect-timeout 10 \
        -X POST "https://${domain}/evaluate" \
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

# ─── 11. Show IPs ────────────────────────────────────────────────────────────

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

# ─── 12. Auto-config ─────────────────────────────────────────────────────────

_set_config() {
    local key="$1" value="$2"
    if grep -q "^${key}=" "$CONFIG_FILE"; then
        if grep -q "^${key}=$" "$CONFIG_FILE" || grep -q "^${key}=\s*$" "$CONFIG_FILE"; then
            sed -i.bak "s|^${key}=.*|${key}=${value}|" "$CONFIG_FILE" && rm -f "${CONFIG_FILE}.bak"
            echo "  ${key}=${value}"
        else
            echo "  ${key} already set, skipping"
        fi
    fi
}

step_auto_config() {
    echo ""
    info "Auto-populating config.env from AWS"
    echo ""

    # AWS Account ID
    echo "  Fetching AWS account ID..."
    local aws_id
    aws_id=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || true
    if [[ -n "$aws_id" ]]; then
        _set_config "AWS_ACCOUNT_ID" "$aws_id"
    else
        warn "Could not fetch AWS account ID"
    fi

    # Per-node IPs, SGs, VPCs
    for i in 1 2 3; do
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
            local pub_ip priv_ip sg_id vpc_id subnet_id
            pub_ip=$(echo "$instance_data" | jq -r '.PublicIpAddress // empty')
            priv_ip=$(echo "$instance_data" | jq -r '.PrivateIpAddress // empty')
            sg_id=$(echo "$instance_data" | jq -r '.SecurityGroups[0].GroupId // empty')
            vpc_id=$(echo "$instance_data" | jq -r '.VpcId // empty')
            subnet_id=$(echo "$instance_data" | jq -r '.SubnetId // empty')

            [[ -n "$pub_ip" ]] && _set_config "NODE${i}_IP" "$pub_ip"
            [[ -n "$priv_ip" ]] && _set_config "NODE${i}_PRIVATE_IP" "$priv_ip"
            [[ -n "$sg_id" ]] && _set_config "NODE${i}_SG_ID" "$sg_id"
            [[ -n "$vpc_id" ]] && _set_config "NODE${i}_VPC_ID" "$vpc_id"
            [[ -n "$subnet_id" ]] && _set_config "NODE${i}_SUBNET_ID" "$subnet_id"
        else
            warn "Could not find Node $i in $region"
        fi
    done

    echo ""
    echo "  Done. Review config.env and fill in any remaining empty fields."
}

# ─── 13. Lock nodes (remove SSH access) ──────────────────────────────────────

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

# ─── 14. Redeploy ────────────────────────────────────────────────────────────

step_redeploy() {
    echo ""
    info "Redeploying (pull latest image → restart)"
    step_pull
    for i in $(active_nodes); do
        echo "  Restarting node $i..."
        ssh_node "$i" "sudo docker rm -f toprf-node 2>/dev/null || true"
    done
    step_start
}

# ─── 15. Cutover (update Lambda to new slot's NLB) ────────────────────────────

step_cutover() {
    echo ""
    [[ -n "$SLOT" ]] || die "cutover requires --slot (e.g., --slot green)"
    info "Cutting over to slot: $SLOT"

    local pl_state
    pl_state=$(pl_state_file)
    [[ -f "$pl_state" ]] || die "$(basename "$pl_state") not found. Deploy the slot first."
    source "$pl_state"

    # Use node 1's NLB as the coordinator endpoint
    local nlb_dns="${NLB_DNS_NODE1:-}"
    [[ -n "$nlb_dns" ]] || die "NLB_DNS_NODE1 not found in $(basename "$pl_state")"

    local new_url="http://${nlb_dns}:3001"
    echo "  New coordinator URL: $new_url"

    # Update Lambda environment variable
    local lambda_name="ruonid-evaluate"
    local lambda_region="eu-west-1"

    echo "  Updating Lambda $lambda_name NLB_URL..."
    local current_env
    current_env=$(aws lambda get-function-configuration \
        --region "$lambda_region" \
        --function-name "$lambda_name" \
        --query 'Environment.Variables' --output json 2>/dev/null) || die "Could not read Lambda config"

    # Merge NLB_URL into existing env vars
    local new_env
    new_env=$(echo "$current_env" | jq --arg url "$new_url" '. + {"NLB_URL": $url}')

    aws lambda update-function-configuration \
        --region "$lambda_region" \
        --function-name "$lambda_name" \
        --environment "{\"Variables\": $new_env}" > /dev/null

    echo "  Lambda updated. Verifying..."

    # Quick health check through the new NLB (via Lambda)
    sleep 2
    local verify_url="https://${DOMAIN:-api.ruonlabs.com}/evaluate"
    local test_point="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    local resp
    resp=$(curl -s --connect-timeout 10 -X POST "$verify_url" \
        -H "Content-Type: application/json" \
        -d "{\"blinded_point\":\"${test_point}\"}" 2>&1) || true

    if echo "$resp" | jq -e '.evaluation' > /dev/null 2>&1; then
        echo "  Cutover verified — OPRF evaluation working through new slot."
    else
        warn "Could not verify via domain (may need attestation token). Check manually."
        echo "  Response: $resp"
    fi

    echo ""
    echo "  Cutover complete. Traffic now routes to slot: $SLOT"
    echo "  To tear down the old slot: ./deploy.sh teardown --slot <old-slot>"
}

# ─── 16. Teardown (discover by tag, delete everything) ────────────────────────

step_teardown() {
    echo ""
    [[ -n "$SLOT" ]] || die "teardown requires --slot (e.g., --slot blue)"
    info "Tearing down slot: $SLOT"
    echo ""
    echo "  WARNING: This will permanently delete all resources tagged Slot=$SLOT."
    echo "  Press Enter to confirm, or Ctrl-C to abort:"
    read -r _ < /dev/tty

    local regions=("eu-west-1" "us-east-2")

    # ── 1. Terminate EC2 instances ──
    echo ""
    echo "  ━━━ Terminating EC2 instances ━━━"
    for region in "${regions[@]}"; do
        local instance_ids
        instance_ids=$(aws ec2 describe-instances --region "$region" \
            --filters "Name=tag:Slot,Values=$SLOT" "Name=tag:Project,Values=toprf" \
                      "Name=instance-state-name,Values=pending,running,stopping,stopped" \
            --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null) || true

        for iid in $instance_ids; do
            [[ -n "$iid" && "$iid" != "None" ]] || continue
            echo "    Terminating $iid ($region)..."
            aws ec2 terminate-instances --region "$region" --instance-ids "$iid" > /dev/null
        done
    done

    # ── 2. Delete VPC Endpoints ──
    echo ""
    echo "  ━━━ Deleting VPC Endpoints ━━━"
    for region in "${regions[@]}"; do
        local vpce_ids
        vpce_ids=$(aws ec2 describe-vpc-endpoints --region "$region" \
            --filters "Name=tag:Slot,Values=$SLOT" "Name=tag:Project,Values=toprf" \
            --query 'VpcEndpoints[].VpcEndpointId' --output text 2>/dev/null) || true

        for vpce in $vpce_ids; do
            [[ -n "$vpce" && "$vpce" != "None" ]] || continue
            echo "    Deleting $vpce ($region)..."
            aws ec2 delete-vpc-endpoints --region "$region" --vpc-endpoint-ids "$vpce" > /dev/null 2>/dev/null || true
        done
    done

    # ── 3. Delete VPC Endpoint Services ──
    echo ""
    echo "  ━━━ Deleting VPC Endpoint Services ━━━"
    for region in "${regions[@]}"; do
        local svc_ids
        svc_ids=$(aws ec2 describe-vpc-endpoint-service-configurations --region "$region" \
            --filters "Name=tag:Slot,Values=$SLOT" \
            --query 'ServiceConfigurations[].ServiceId' --output text 2>/dev/null) || true

        for svc in $svc_ids; do
            [[ -n "$svc" && "$svc" != "None" ]] || continue
            echo "    Deleting $svc ($region)..."
            aws ec2 delete-vpc-endpoint-service-configurations --region "$region" \
                --service-ids "$svc" > /dev/null 2>/dev/null || true
        done
    done

    # ── 4. Delete NLB listeners, target groups, and NLBs ──
    echo ""
    echo "  ━━━ Deleting NLBs and Target Groups ━━━"
    for region in "${regions[@]}"; do
        # Find NLBs by tag
        local nlb_arns
        nlb_arns=$(aws elbv2 describe-load-balancers --region "$region" \
            --query 'LoadBalancers[].LoadBalancerArn' --output text 2>/dev/null) || true

        for nlb_arn in $nlb_arns; do
            [[ -n "$nlb_arn" && "$nlb_arn" != "None" ]] || continue
            # Check if this NLB has our slot tag
            local tags
            tags=$(aws elbv2 describe-tags --region "$region" --resource-arns "$nlb_arn" \
                --query "TagDescriptions[0].Tags[?Key=='Slot'&&Value=='$SLOT'].Value" \
                --output text 2>/dev/null) || true
            [[ "$tags" == "$SLOT" ]] || continue

            echo "    Deleting NLB $nlb_arn ($region)..."

            # Delete listeners first
            local listeners
            listeners=$(aws elbv2 describe-listeners --region "$region" \
                --load-balancer-arn "$nlb_arn" \
                --query 'Listeners[].ListenerArn' --output text 2>/dev/null) || true
            for lis in $listeners; do
                [[ -n "$lis" && "$lis" != "None" ]] || continue
                aws elbv2 delete-listener --region "$region" --listener-arn "$lis" 2>/dev/null || true
            done

            # Delete NLB
            aws elbv2 delete-load-balancer --region "$region" --load-balancer-arn "$nlb_arn" 2>/dev/null || true
        done

        # Find and delete target groups by tag
        local tg_arns
        tg_arns=$(aws elbv2 describe-target-groups --region "$region" \
            --query 'TargetGroups[].TargetGroupArn' --output text 2>/dev/null) || true

        for tg_arn in $tg_arns; do
            [[ -n "$tg_arn" && "$tg_arn" != "None" ]] || continue
            local tags
            tags=$(aws elbv2 describe-tags --region "$region" --resource-arns "$tg_arn" \
                --query "TagDescriptions[0].Tags[?Key=='Slot'&&Value=='$SLOT'].Value" \
                --output text 2>/dev/null) || true
            [[ "$tags" == "$SLOT" ]] || continue

            echo "    Deleting TG $tg_arn ($region)..."
            aws elbv2 delete-target-group --region "$region" --target-group-arn "$tg_arn" 2>/dev/null || true
        done
    done

    # ── 5. Delete VPCE Security Groups ──
    echo ""
    echo "  ━━━ Deleting VPCE Security Groups ━━━"
    for region in "${regions[@]}"; do
        local sg_ids
        sg_ids=$(aws ec2 describe-security-groups --region "$region" \
            --filters "Name=tag:Slot,Values=$SLOT" "Name=tag:Project,Values=toprf" \
            --query 'SecurityGroups[].GroupId' --output text 2>/dev/null) || true

        for sg in $sg_ids; do
            [[ -n "$sg" && "$sg" != "None" ]] || continue
            echo "    Deleting SG $sg ($region)..."
            aws ec2 delete-security-group --region "$region" --group-id "$sg" 2>/dev/null || true
        done
    done

    # ── 6. Delete EC2 key pairs ──
    echo ""
    echo "  ━━━ Deleting EC2 key pairs ━━━"
    for region in "${regions[@]}"; do
        local key_names
        key_names=$(aws ec2 describe-key-pairs --region "$region" \
            --filters "Name=tag:Slot,Values=$SLOT" "Name=tag:Project,Values=toprf" \
            --query 'KeyPairs[].KeyName' --output text 2>/dev/null) || true

        for kn in $key_names; do
            [[ -n "$kn" && "$kn" != "None" ]] || continue
            echo "    Deleting key pair $kn ($region)..."
            aws ec2 delete-key-pair --region "$region" --key-name "$kn" 2>/dev/null || true
            rm -f "${SCRIPT_DIR}/${kn}.pem"
        done
    done

    # ── 7. Clean up local state files ──
    echo ""
    echo "  ━━━ Cleaning up local files ━━━"
    local pl_state
    pl_state=$(pl_state_file)
    [[ -f "$pl_state" ]] && rm -f "$pl_state" && echo "    Deleted $(basename "$pl_state")"

    local config_dir
    config_dir=$(coord_config_dir)
    [[ -d "$config_dir" ]] && rm -rf "$config_dir" && echo "    Deleted $(basename "$config_dir")/"

    echo ""
    echo "  Teardown of slot '$SLOT' complete."
}

# =============================================================================
# CLI
# =============================================================================

usage() {
    cat <<'EOF'
Usage: deploy.sh [--slot NAME] [--nodes 1,2,3] <step> [step...]

Options:
  --slot NAME   Blue-green slot name (e.g., blue, green). Resources are
                named and tagged with this slot for zero-downtime rotation.
  --nodes N     Operate on specific node(s) only (comma-separated)

Steps (run in order for fresh deployment):
  setup-vms     Install Docker on VMs
  pull          Pull node image from ghcr.io on each VM
  storage       Create S3 buckets for sealed key blobs
  init-seal     S3-mediated ECIES key injection (attested)
  privatelink   Create NLBs, Endpoint Services, cross-VPC VPC Endpoints
  coordinator-config  Generate per-node coordinator configs (peer endpoints)
  start         Start nodes in coordinator mode (unseal + serve)
  verify        Health check all nodes (via SSH)
  e2e           End-to-end verify: OPRF evaluate via coordinator

Blue-green:
  cutover       Update Lambda NLB_URL to this slot's coordinator NLB
  teardown      Delete all AWS resources tagged with this slot

Utilities:
  auto-config   Auto-populate config.env from AWS
  show-ips      Fetch public/private IPs for all nodes
  lock          Remove SSH access + delete keys (irreversible)

Shortcuts:
  pre-seal      setup-vms → pull → storage
  post-seal     privatelink → coordinator-config → start → verify
  all           pre-seal → init-seal → post-seal
  redeploy      pull latest image → restart nodes

Blue-green example:
  ./deploy.sh --slot green all          # Deploy new set
  ./deploy.sh --slot green cutover      # Switch traffic
  ./deploy.sh --slot blue teardown      # Tear down old set
EOF
}

if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

# Parse --nodes flag before processing steps
steps=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --slot|-s)
            shift
            SLOT="$1"
            shift
            ;;
        --nodes|-n)
            shift
            _NODE_FILTER=$(echo "$1" | tr ',' ' ')
            shift
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

if [[ -n "$SLOT" ]]; then
    info "Slot: $SLOT"
fi
if [[ -n "$_NODE_FILTER" ]]; then
    info "Operating on node(s): $_NODE_FILTER"
fi

for step in "${steps[@]}"; do
    case "$step" in
        pull)         step_pull ;;
        storage)      step_storage ;;
        setup-vms)    step_setup_vms ;;
        privatelink)  step_privatelink ;;
        init-seal)    step_init_seal ;;
        start)        step_start ;;
        coordinator-config) step_coordinator_config ;;
        verify)       step_verify ;;
        e2e)          step_e2e ;;
        auto-config)  step_auto_config ;;
        show-ips)     step_show_ips ;;
        redeploy)     step_redeploy ;;
        lock)         step_lock ;;
        cutover)      step_cutover ;;
        teardown)     step_teardown ;;
        pre-seal)
            step_setup_vms
            step_pull
            step_storage
            ;;
        post-seal)
            step_privatelink
            step_coordinator_config
            step_start
            step_verify
            ;;
        all)
            step_setup_vms
            step_pull
            step_storage
            echo ""
            echo "═══════════════════════════════════════════════════"
            echo "  Pre-seal steps complete."
            echo "  Next: init-seal (interactive key injection)."
            echo "═══════════════════════════════════════════════════"
            step_init_seal
            step_privatelink
            step_coordinator_config
            step_start
            step_verify
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
