#!/usr/bin/env bash
# =============================================================================
# deploy.sh — Automated deployment for threshold OPRF nodes on AWS.
#
# Deploys 3 TEE nodes (Amazon Linux 2023) across AWS regions with VPC peering
# to the proxy. All nodes run in AMD SEV-SNP Confidential VMs with sealed key shares.
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
  certs         Generate TLS certs (with IPs as SANs) + distribute
  init-seal     Interactive: inject key shares via attested TLS
  start         Start nodes in normal mode (unseal + serve)
  firewall      Allow port 3001 from proxy VPC CIDR to each node
  peering       Set up VPC peering between proxy and node VPCs
  proxy-config  Generate docker/proxy-config.production.json
  verify        Health check all nodes

Utilities:
  auto-config   Auto-populate config.env from AWS
  show-ips      Fetch public/private IPs for all nodes
  lock          Remove SSH access + delete keys (irreversible)

Shortcuts:
  pre-seal      setup-vms → pull → storage → certs
  post-seal     start → firewall → peering → proxy-config → verify
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

# ─── Derived values ──────────────────────────────────────────────────────────

ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${ECR_REGION}.amazonaws.com"
NODE_IMAGE="${NODE_IMAGE:-ghcr.io/${GHCR_OWNER:-jeganggs64}/toprf-node:latest}"
PROXY_IMAGE="${ECR_URI}/${PROXY_ECR_REPO:-ruonid/proxy}:latest"

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

node_s3_bucket() {
    case "$1" in
        1) echo "$NODE1_S3_BUCKET" ;;
        2) echo "$NODE2_S3_BUCKET" ;;
        3) echo "$NODE3_S3_BUCKET" ;;
    esac
}


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

# ─── 4. Generate + distribute TLS certs ──────────────────────────────────────

step_certs() {
    echo ""
    info "Generating TLS certificates (with node IPs as SANs)"

    local CERTS_DIR="$REPO_ROOT/certs"
    local CA_DIR="$CERTS_DIR/ca"
    local NODES_DIR="$CERTS_DIR/nodes"

    rm -rf "$CERTS_DIR"
    mkdir -p "$CA_DIR" "$NODES_DIR"

    # CA
    echo "  Generating CA..."
    openssl ecparam -genkey -name prime256v1 -noout -out "$CA_DIR/ca.key" 2>/dev/null
    chmod 600 "$CA_DIR/ca.key"
    openssl req -new -x509 -key "$CA_DIR/ca.key" -out "$CA_DIR/ca.pem" \
        -days 1095 -subj "/CN=toprf-ca/O=Threshold OPRF/OU=CA" -sha256

    # Node certs — SANs include public and private IPs
    for i in $(active_nodes); do
        local ip private_ip
        ip=$(node_ip "$i")
        private_ip=$(node_private_ip "$i")
        echo "  Node $i cert (SAN: $ip, $private_ip)..."

        openssl ecparam -genkey -name prime256v1 -noout \
            -out "$NODES_DIR/node${i}.key" 2>/dev/null
        chmod 600 "$NODES_DIR/node${i}.key"

        openssl req -new -key "$NODES_DIR/node${i}.key" \
            -out "$NODES_DIR/node${i}.csr" \
            -subj "/CN=node${i}/O=Threshold OPRF/OU=Node" -sha256

        # Include both public IP (for init-seal) and private IP (for proxy via VPC peering)
        cat > "$NODES_DIR/node${i}.ext" <<EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = node${i}
IP.1  = 127.0.0.1
IP.2  = ${ip}
IP.3  = ${private_ip}
EXTEOF

        openssl x509 -req -in "$NODES_DIR/node${i}.csr" \
            -CA "$CA_DIR/ca.pem" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
            -out "$NODES_DIR/node${i}.pem" -days 365 -sha256 \
            -extfile "$NODES_DIR/node${i}.ext" 2>/dev/null

        rm -f "$NODES_DIR/node${i}.csr" "$NODES_DIR/node${i}.ext"
    done

    rm -f "$CA_DIR/ca.srl"

    # Distribute certs to VMs
    echo "  Distributing certs to VMs..."
    for i in $(active_nodes); do
        echo "    Node $i..."
        scp_to_node "$i" \
            "$CA_DIR/ca.pem" \
            "$NODES_DIR/node${i}.pem" \
            "$NODES_DIR/node${i}.key"
        ssh_node "$i" "sudo mkdir -p /etc/toprf/certs && \
            sudo mv /tmp/ca.pem /tmp/node${i}.pem /tmp/node${i}.key /etc/toprf/certs/ && \
            sudo chmod 644 /etc/toprf/certs/ca.pem /etc/toprf/certs/node${i}.pem && \
            sudo chmod 600 /etc/toprf/certs/node${i}.key"
    done

    echo "  Done."
    echo "  Local certs at: $CERTS_DIR"
}

# ─── 5. Open firewall (proxy VPC → nodes on port 3001) ───────────────────────

step_firewall() {
    echo ""
    info "Allowing port 3001 from proxy VPC CIDR to nodes"

    [[ -n "${PROXY_VPC_CIDR:-}" ]] || die "PROXY_VPC_CIDR not set in config.env"

    for i in $(active_nodes); do
        local sg_id region
        sg_id=$(node_sg_id "$i")
        region=$(node_region "$i")
        echo "  Node $i: SG $sg_id ($region)..."
        aws ec2 authorize-security-group-ingress \
            --group-id "$sg_id" --protocol tcp --port 3001 \
            --cidr "$PROXY_VPC_CIDR" --region "$region" 2>/dev/null \
            || warn "rule may already exist"
    done

    echo "  Done."
}

# ─── 6. VPC peering (proxy ↔ node VPCs) ──────────────────────────────────────

step_peering() {
    echo ""
    info "Setting up VPC peering between proxy and node VPCs"

    local ecs_state="${SCRIPT_DIR}/ecs-state.env"
    [[ -f "$ecs_state" ]] || die "ecs-state.env not found. Run setup-ecs.sh vpc first."
    source "$ecs_state"

    local proxy_vpc_id="${VPC_ID:?VPC_ID not found in ecs-state.env}"
    local proxy_priv_rt="${PRIV_RT:?PRIV_RT not found in ecs-state.env}"

    for i in $(active_nodes); do
        local region vpc_id
        region=$(node_region "$i")
        vpc_id=$(node_vpc_id "$i")

        [[ -n "$vpc_id" ]] || die "NODE${i}_VPC_ID not set in config.env"

        # Skip if node is in the same VPC (shouldn't happen but guard)
        if [[ "$vpc_id" == "$proxy_vpc_id" ]]; then
            echo "  Node $i: same VPC as proxy, skipping peering"
            continue
        fi

        echo "  Node $i: Peering $vpc_id ($region) ↔ $proxy_vpc_id ($PROXY_REGION)..."

        # Create peering connection (from proxy region)
        local peering_id
        peering_id=$(aws ec2 create-vpc-peering-connection \
            --region "$PROXY_REGION" \
            --vpc-id "$proxy_vpc_id" \
            --peer-vpc-id "$vpc_id" \
            --peer-region "$region" \
            --query 'VpcPeeringConnection.VpcPeeringConnectionId' --output text 2>/dev/null) \
            || { warn "peering may already exist for node $i"; continue; }

        echo "    Peering: $peering_id"

        # Accept peering (from node's region)
        aws ec2 accept-vpc-peering-connection \
            --region "$region" \
            --vpc-peering-connection-id "$peering_id" > /dev/null
        echo "    Accepted."

        # Get node VPC CIDR
        local node_cidr
        node_cidr=$(aws ec2 describe-vpcs --region "$region" \
            --vpc-ids "$vpc_id" \
            --query 'Vpcs[0].CidrBlock' --output text)

        # Route: proxy private subnets → node VPC via peering
        aws ec2 create-route --region "$PROXY_REGION" \
            --route-table-id "$proxy_priv_rt" \
            --destination-cidr-block "$node_cidr" \
            --vpc-peering-connection-id "$peering_id" 2>/dev/null \
            || warn "proxy → node route may exist"

        # Route: node VPC → proxy VPC via peering
        local node_rt
        node_rt=$(aws ec2 describe-route-tables --region "$region" \
            --filters "Name=vpc-id,Values=$vpc_id" \
            --query 'RouteTables[0].RouteTableId' --output text)
        aws ec2 create-route --region "$region" \
            --route-table-id "$node_rt" \
            --destination-cidr-block "$PROXY_VPC_CIDR" \
            --vpc-peering-connection-id "$peering_id" 2>/dev/null \
            || warn "node → proxy route may exist"

        echo "    Routes: proxy ↔ $node_cidr"
    done

    echo "  Done."
}

# ─── 7. Init-seal (interactive) ──────────────────────────────────────────────

step_init_seal() {
    echo ""
    info "Init-seal — interactive key injection via attested TLS"
    echo ""
    echo "  For each node, the script will:"
    echo "    1. Start the node in init-seal mode"
    echo "    2. Wait for the attestation endpoint to be ready"
    echo "    3. Pause so you can verify the attestation report"
    echo "    4. Send the key share after you confirm"
    echo ""

    load_ceremony

    for i in $(active_nodes); do
        local ip vs url share
        ip=$(node_ip "$i")
        vs=$(node_vs "$i")
        url=$(sealed_url "$i")
        share="${NODE_SHARES_DIR}/node-${i}-share.json"

        [[ -f "$share" ]] || die "Key share not found: $share"

        echo "━━━ Node $i ($ip) ━━━"
        echo "  Starting init-seal container..."

        # Clean up any previous init-seal container
        ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true" < /dev/null

        ssh_node "$i" "sudo docker run -d --name toprf-init-seal \
            -e EXPECTED_VERIFICATION_SHARE=${vs} \
            --device /dev/sev-guest:/dev/sev-guest \
            --privileged --user root \
            -p 3001:3001 \
            ${NODE_IMAGE} \
            --init-seal \
            --upload-url '${url}' \
            --port 3001" < /dev/null

        echo "  Waiting for attestation endpoint..."
        local waited=0
        while ! ssh_node "$i" "curl -sk https://localhost:3001/attest > /dev/null 2>&1" < /dev/null; do
            local running
            running=$(ssh_node "$i" "sudo docker inspect -f '{{.State.Running}}' toprf-init-seal 2>/dev/null || echo false" < /dev/null)
            if [[ "$running" != "true" ]]; then
                echo "  Container exited prematurely. Logs:"
                ssh_node "$i" "sudo docker logs --tail 20 toprf-init-seal 2>&1" < /dev/null || true
                echo ""
                echo "  Press Enter to skip this node and continue, or Ctrl-C to abort:"
                read -r _ < /dev/tty
                ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true" < /dev/null
                continue 2
            fi
            sleep 2
            waited=$((waited + 1))
            if [[ $waited -ge 60 ]]; then
                echo "  Timed out after 120s. Check logs:"
                echo "    ssh → sudo docker logs toprf-init-seal"
                die "init-seal endpoint not ready"
            fi
        done

        echo ""
        echo "  Attestation endpoint ready: https://${ip}:3001/attest"
        echo ""
        echo "  To verify (from another terminal):"
        echo "    curl -k https://${ip}:3001/attest -o report-node${i}.bin"
        echo "    # Check: AMD signature chain (ARK→ASK→VCEK)"
        echo "    # Check: MEASUREMENT matches expected binary"
        echo "    # Check: REPORT_DATA[0..32] == SHA-256(TLS pubkey)"
        echo ""
        echo "  Press Enter to send key share, or 'skip' to skip this node:"
        read -r response < /dev/tty

        if [[ "$response" == "skip" ]]; then
            echo "  Skipping node $i."
            ssh_node "$i" "sudo docker rm -f toprf-init-seal" < /dev/null || true
            echo ""
            continue
        fi

        echo "  Sending key share to node $i..."
        scp_to_node "$i" "$share" < /dev/null
        local share_filename
        share_filename=$(basename "$share")
        local http_code body
        body=$(ssh_node "$i" "curl -sk https://localhost:3001/init-key \
            -X POST -H 'Content-Type: application/json' \
            -d @/tmp/${share_filename} \
            -w '\n%{http_code}' 2>&1 ; rm -f /tmp/${share_filename}" < /dev/null)

        http_code=$(echo "$body" | tail -1)
        body=$(echo "$body" | sed '$d')

        if [[ "$http_code" == "200" ]]; then
            echo "  Node $i sealed successfully."
        else
            echo "  WARNING: init-key returned HTTP $http_code"
            echo "  Response: $body"
        fi

        sleep 3
        ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true" < /dev/null
        echo ""
    done

    echo "  Init-seal complete."
}

# ─── 8. Start nodes in normal mode ───────────────────────────────────────────

step_start() {
    echo ""
    info "Starting nodes in normal mode"

    load_ceremony

    for i in $(active_nodes); do
        local ip vs url
        ip=$(node_ip "$i")
        vs=$(node_vs "$i")
        url=$(sealed_url "$i")

        echo "  Node $i ($ip)..."

        ssh_node "$i" "sudo docker rm -f toprf-node 2>/dev/null || true"

        ssh_node "$i" "sudo docker run -d --name toprf-node --restart=unless-stopped \
            -e SEALED_KEY_URL='${url}' \
            -e EXPECTED_VERIFICATION_SHARE=${vs} \
            --device /dev/sev-guest:/dev/sev-guest \
            --privileged --user root \
            -v /etc/toprf/certs:/etc/toprf/certs:ro \
            -p 3001:3001 \
            ${NODE_IMAGE} \
            --port 3001 \
            --tls-cert /etc/toprf/certs/node${i}.pem \
            --tls-key /etc/toprf/certs/node${i}.key"
    done

    echo "  Waiting for nodes to boot..."
    sleep 5
    echo "  Done. Run './deploy.sh verify' to check health."
}

# ─── 9. Generate proxy config ────────────────────────────────────────────────

step_proxy_config() {
    echo ""
    info "Generating proxy config"

    load_ceremony

    local out="$REPO_ROOT/docker/proxy-config.production.json"

    # Build nodes array using private IPs (proxy connects via VPC peering)
    local nodes_json=""
    local first=true
    for i in $(active_nodes); do
        local private_ip vs
        private_ip=$(node_private_ip "$i")
        vs=$(node_vs "$i")
        [[ -n "$private_ip" ]] || die "NODE${i}_PRIVATE_IP not set in config.env"
        $first || nodes_json+=","
        nodes_json+="
    {
      \"node_id\": $i,
      \"endpoint\": \"https://${private_ip}:3001\",
      \"verification_share\": \"${vs}\"
    }"
        first=false
    done

    cat > "$out" <<CFGEOF
{
  "group_public_key": "${GROUP_PUBLIC_KEY}",
  "threshold": ${THRESHOLD},
  "require_attestation": false,
  "rate_limit": { "per_hour": 1000, "per_day": 10000 },
  "node_ca_cert": "/etc/toprf/certs/ca/ca.pem",
  "nodes": [${nodes_json}
  ]
}
CFGEOF

    echo "  Written to: $out"
    echo "  Done."
}

# ─── 10. Verify ──────────────────────────────────────────────────────────────

step_verify() {
    echo ""
    info "Verifying node health"

    local certs_dir="$REPO_ROOT/certs"
    local pass=0 fail=0

    if [[ ! -f "$certs_dir/ca/ca.pem" ]]; then
        die "Certs not found at $certs_dir. Run './deploy.sh certs' first."
    fi

    for i in $(active_nodes); do
        local ip
        ip=$(node_ip "$i")
        echo "  Node $i ($ip)..."

        local resp
        resp=$(curl -sk --connect-timeout 5 \
            --cacert "$certs_dir/ca/ca.pem" \
            "https://${ip}:3001/health" 2>&1) || true

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

# ─── 11. Show IPs ────────────────────────────────────────────────────────────

step_show_ips() {
    echo ""
    info "Fetching VM IPs from AWS"

    for i in $(active_nodes); do
        local region
        region=$(node_region "$i")
        echo "  Node $i ($region):"

        local result
        result=$(aws ec2 describe-instances --region "$region" \
            --filters "Name=tag:Name,Values=toprf-node-${i}" "Name=instance-state-name,Values=running" \
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
        instance_data=$(aws ec2 describe-instances --region "$region" \
            --filters "Name=tag:Name,Values=toprf-node-${i}" "Name=instance-state-name,Values=running" \
            --query 'Reservations[0].Instances[0]' --output json 2>/dev/null) || true

        if [[ -n "$instance_data" && "$instance_data" != "null" ]]; then
            local pub_ip priv_ip sg_id vpc_id
            pub_ip=$(echo "$instance_data" | jq -r '.PublicIpAddress // empty')
            priv_ip=$(echo "$instance_data" | jq -r '.PrivateIpAddress // empty')
            sg_id=$(echo "$instance_data" | jq -r '.SecurityGroups[0].GroupId // empty')
            vpc_id=$(echo "$instance_data" | jq -r '.VpcId // empty')

            [[ -n "$pub_ip" ]] && _set_config "NODE${i}_IP" "$pub_ip"
            [[ -n "$priv_ip" ]] && _set_config "NODE${i}_PRIVATE_IP" "$priv_ip"
            [[ -n "$sg_id" ]] && _set_config "NODE${i}_SG_ID" "$sg_id"
            [[ -n "$vpc_id" ]] && _set_config "NODE${i}_VPC_ID" "$vpc_id"
        else
            warn "Could not find Node $i in $region"
        fi
    done

    # Proxy IP from ecs-state.env
    local ecs_state="${SCRIPT_DIR}/ecs-state.env"
    if [[ -f "$ecs_state" ]]; then
        echo "  Reading PROXY_IP from ecs-state.env..."
        local nat_eip
        nat_eip=$(grep '^NAT_EIP=' "$ecs_state" | cut -d= -f2) || true
        if [[ -n "$nat_eip" ]]; then
            _set_config "PROXY_IP" "$nat_eip"
        fi
    fi

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
    echo "  Nodes are now only reachable via port 3001 from the proxy VPC."
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
  certs         Generate TLS certs (with IPs as SANs) + distribute
  init-seal     Interactive: inject key shares via attested TLS
  start         Start nodes in normal mode (unseal + serve)
  firewall      Allow port 3001 from proxy VPC CIDR to each node
  peering       Set up VPC peering between proxy and node VPCs
  proxy-config  Generate docker/proxy-config.production.json
  verify        Health check all nodes

Utilities:
  auto-config   Auto-populate config.env from AWS
  show-ips      Fetch public/private IPs for all nodes
  lock          Remove SSH access + delete keys (irreversible)

Shortcuts:
  pre-seal      setup-vms → pull → storage → certs
  post-seal     start → firewall → peering → proxy-config → verify
  all           pre-seal → init-seal → post-seal
  redeploy      pull latest image → restart nodes
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

if [[ -n "$_NODE_FILTER" ]]; then
    info "Operating on node(s): $_NODE_FILTER"
fi

for step in "${steps[@]}"; do
    case "$step" in
        pull)         step_pull ;;
        storage)      step_storage ;;
        setup-vms)    step_setup_vms ;;
        certs)        step_certs ;;
        firewall)     step_firewall ;;
        peering)      step_peering ;;
        init-seal)    step_init_seal ;;
        start)        step_start ;;
        proxy-config) step_proxy_config ;;
        verify)       step_verify ;;
        auto-config)  step_auto_config ;;
        show-ips)     step_show_ips ;;
        redeploy)     step_redeploy ;;
        lock)         step_lock ;;
        pre-seal)
            step_setup_vms
            step_pull
            step_storage
            step_certs
            ;;
        post-seal)
            step_start
            step_firewall
            step_peering
            step_proxy_config
            step_verify
            ;;
        all)
            step_setup_vms
            step_pull
            step_storage
            step_certs
            echo ""
            echo "═══════════════════════════════════════════════════"
            echo "  Pre-seal steps complete."
            echo "  Next: init-seal (interactive key injection)."
            echo "═══════════════════════════════════════════════════"
            step_init_seal
            step_start
            step_firewall
            step_peering
            step_proxy_config
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
