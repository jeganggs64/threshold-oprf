#!/usr/bin/env bash
# =============================================================================
# deploy.sh — Automated deployment for the threshold OPRF system.
#
# Assumes VMs, IAM roles, and SSH access are already provisioned.
# See config.env.example for required configuration.
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

# Add gcloud to PATH if installed via google-cloud-sdk
[[ -d "$HOME/google-cloud-sdk/bin" ]] && export PATH="$HOME/google-cloud-sdk/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Show help without requiring config
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
    usage() {
        cat <<'EOF'
Usage: deploy.sh <step> [step...]

Steps (run in order for fresh deployment):
  pull          Pull node image from ghcr.io on each VM
  storage       Create storage buckets + bind VM identities
  setup-vms     Install Docker on all 3 VMs
  certs         Generate mTLS certs (with real IPs) + distribute
  firewall      Open port 3001 from proxy IP to each node
  init-seal     Interactive: inject key shares via attested TLS
  start         Start nodes in normal mode (unseal + serve)
  proxy-config  Generate docker/proxy-config.production.json
  verify        Health check all nodes via mTLS

Utilities:
  auto-config   Auto-populate config.env (IPs, account ID, SG, proxy IP)
  show-ips      Fetch public IPs from all 3 providers

Shortcuts:
  pre-seal      setup-vms → pull → storage → certs
  post-seal     start → firewall → proxy-config → verify
  all           pre-seal → init-seal → post-seal
  redeploy      pull latest image → restart nodes
EOF
    }
    usage
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
PROXY_IMAGE="${ECR_URI}/${PROXY_ECR_REPO:-toprf/toprf-proxy}:latest"

# ─── Helpers ─────────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
warn()  { echo "  WARN: $*"; }
die()   { echo "  ERROR: $*" >&2; exit 1; }

node_ip() {
    case "$1" in
        1) echo "$NODE1_IP" ;;
        2) echo "$NODE2_IP" ;;
        3) echo "$NODE3_IP" ;;
    esac
}

# Returns space-separated list of node IDs that have an IP configured.
active_nodes() {
    local nodes=""
    [[ -n "${NODE1_IP:-}" ]] && nodes="$nodes 1"
    [[ -n "${NODE2_IP:-}" ]] && nodes="$nodes 2"
    [[ -n "${NODE3_IP:-}" ]] && nodes="$nodes 3"
    echo $nodes
}

node_snp_provider() {
    case "$1" in
        1) echo "${NODE1_SNP_PROVIDER:-gcp}" ;;
        2) echo "${NODE2_SNP_PROVIDER:-raw}" ;;
        3) echo "${NODE3_SNP_PROVIDER:-raw}" ;;
    esac
}

sealed_url() {
    case "$1" in
        1) echo "gs://${GCP_BUCKET}/node-1-sealed.bin" ;;
        2) echo "https://${AZURE_STORAGE_ACCOUNT}.blob.core.windows.net/${AZURE_STORAGE_CONTAINER}/node-2-sealed.bin" ;;
        3) echo "s3://${AWS_S3_BUCKET}/node-3-sealed.bin" ;;
    esac
}

ssh_node() {
    local n="$1"; shift
    case "$n" in
        1) gcloud compute ssh "$GCP_VM_NAME" --zone="$GCP_ZONE" --project="$GCP_PROJECT" --command="$*" ;;
        2) ssh -o StrictHostKeyChecking=accept-new "${AZURE_USER}@${NODE2_IP}" "$*" ;;
        3) ssh -o StrictHostKeyChecking=accept-new -i "$AWS_SSH_KEY" "ubuntu@${NODE3_IP}" "$*" ;;
    esac
}

scp_to_node() {
    local n="$1"; shift
    case "$n" in
        1)
            # gcloud compute scp takes files then instance:path
            gcloud compute scp "$@" "${GCP_VM_NAME}:/tmp/" \
                --zone="$GCP_ZONE" --project="$GCP_PROJECT"
            ;;
        2) scp -o StrictHostKeyChecking=accept-new "$@" "${AZURE_USER}@${NODE2_IP}:/tmp/" ;;
        3) scp -o StrictHostKeyChecking=accept-new -i "$AWS_SSH_KEY" "$@" "ubuntu@${NODE3_IP}:/tmp/" ;;
    esac
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

# ─── 1. Pull Docker image ──────────────────────────────────────────────────

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

# ─── 3. Create storage buckets ──────────────────────────────────────────────

step_storage() {
    echo ""
    info "Creating storage buckets"

    # GCP
    echo "  GCP: gs://${GCP_BUCKET}"
    gcloud storage buckets create "gs://${GCP_BUCKET}" \
        --location=asia-southeast1 --project="$GCP_PROJECT" 2>/dev/null \
        || warn "bucket may already exist"

    local sa_email
    sa_email=$(gcloud compute instances describe "$GCP_VM_NAME" \
        --zone="$GCP_ZONE" --project="$GCP_PROJECT" \
        --format='get(serviceAccounts[0].email)' 2>/dev/null) || true
    if [[ -n "$sa_email" ]]; then
        gcloud storage buckets add-iam-policy-binding "gs://${GCP_BUCKET}" \
            --member="serviceAccount:${sa_email}" \
            --role="roles/storage.objectAdmin" \
            --project="$GCP_PROJECT" 2>/dev/null \
            || warn "IAM binding may already exist"
    fi

    # Azure
    echo "  Azure: ${AZURE_STORAGE_ACCOUNT}/${AZURE_STORAGE_CONTAINER}"
    az storage account create \
        --name "$AZURE_STORAGE_ACCOUNT" --resource-group "$AZURE_RG" \
        --location eastus --sku Standard_LRS 2>/dev/null \
        || warn "storage account may already exist"
    az storage container create \
        --name "$AZURE_STORAGE_CONTAINER" \
        --account-name "$AZURE_STORAGE_ACCOUNT" \
        --public-access off 2>/dev/null \
        || warn "container may already exist"

    az vm identity assign --resource-group "$AZURE_RG" --name "$AZURE_VM_NAME" 2>/dev/null || true
    local vm_identity
    vm_identity=$(az vm show --resource-group "$AZURE_RG" --name "$AZURE_VM_NAME" \
        --query identity.principalId -o tsv 2>/dev/null) || true
    if [[ -n "$vm_identity" ]]; then
        local sub_id
        sub_id=$(az account show --query id -o tsv)
        az role assignment create \
            --assignee "$vm_identity" \
            --role "Storage Blob Data Contributor" \
            --scope "/subscriptions/${sub_id}/resourceGroups/${AZURE_RG}/providers/Microsoft.Storage/storageAccounts/${AZURE_STORAGE_ACCOUNT}" \
            2>/dev/null \
            || warn "role assignment may already exist"
    fi

    # AWS
    echo "  AWS: s3://${AWS_S3_BUCKET}"
    aws s3 mb "s3://${AWS_S3_BUCKET}" --region "$AWS_NODE_REGION" 2>/dev/null \
        || warn "bucket may already exist"

    echo "  Done."
}

# ─── 4. Setup VMs (Docker + AWS CLI) ────────────────────────────────────────

step_setup_vms() {
    echo ""
    info "Setting up VMs (Docker)"

    for i in $(active_nodes); do
        local ip
        ip=$(node_ip "$i")
        echo "  Node $i ($ip)..."

        ssh_node "$i" "$(cat <<'SETUP'
set -e

# Docker
if ! command -v docker &>/dev/null; then
    echo "    Installing Docker..."
    curl -fsSL https://get.docker.com | sudo sh
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

# ─── 6. Generate + distribute mTLS certs ────────────────────────────────────

step_certs() {
    echo ""
    info "Generating mTLS certificates (with real node IPs as SANs)"

    local CERTS_DIR="$REPO_ROOT/certs"
    local CA_DIR="$CERTS_DIR/ca"
    local NODES_DIR="$CERTS_DIR/nodes"
    local PROXY_DIR="$CERTS_DIR/proxy"

    rm -rf "$CERTS_DIR"
    mkdir -p "$CA_DIR" "$NODES_DIR" "$PROXY_DIR"

    # CA
    echo "  Generating CA..."
    openssl ecparam -genkey -name prime256v1 -noout -out "$CA_DIR/ca.key" 2>/dev/null
    chmod 600 "$CA_DIR/ca.key"
    openssl req -new -x509 -key "$CA_DIR/ca.key" -out "$CA_DIR/ca.pem" \
        -days 1095 -subj "/CN=toprf-ca/O=Threshold OPRF/OU=CA" -sha256

    # Node certs — SANs include real public IPs so the proxy can verify them
    for i in $(active_nodes); do
        local ip
        ip=$(node_ip "$i")
        echo "  Node $i cert (SAN: $ip)..."

        openssl ecparam -genkey -name prime256v1 -noout \
            -out "$NODES_DIR/node${i}.key" 2>/dev/null
        chmod 600 "$NODES_DIR/node${i}.key"

        openssl req -new -key "$NODES_DIR/node${i}.key" \
            -out "$NODES_DIR/node${i}.csr" \
            -subj "/CN=node${i}/O=Threshold OPRF/OU=Node" -sha256

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
EXTEOF

        openssl x509 -req -in "$NODES_DIR/node${i}.csr" \
            -CA "$CA_DIR/ca.pem" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
            -out "$NODES_DIR/node${i}.pem" -days 365 -sha256 \
            -extfile "$NODES_DIR/node${i}.ext" 2>/dev/null

        rm -f "$NODES_DIR/node${i}.csr" "$NODES_DIR/node${i}.ext"
    done

    # Proxy client cert (mTLS)
    echo "  Proxy client cert..."
    openssl ecparam -genkey -name prime256v1 -noout \
        -out "$PROXY_DIR/proxy-client.key" 2>/dev/null
    chmod 600 "$PROXY_DIR/proxy-client.key"

    openssl req -new -key "$PROXY_DIR/proxy-client.key" \
        -out "$PROXY_DIR/proxy-client.csr" \
        -subj "/CN=toprf-proxy/O=Threshold OPRF/OU=Proxy" -sha256

    cat > "$PROXY_DIR/proxy-client.ext" <<EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EXTEOF

    openssl x509 -req -in "$PROXY_DIR/proxy-client.csr" \
        -CA "$CA_DIR/ca.pem" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
        -out "$PROXY_DIR/proxy-client.pem" -days 365 -sha256 \
        -extfile "$PROXY_DIR/proxy-client.ext" 2>/dev/null

    rm -f "$PROXY_DIR/proxy-client.csr" "$PROXY_DIR/proxy-client.ext" "$CA_DIR/ca.srl"

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

# ─── 7. Open firewall (proxy → nodes on port 3001) ──────────────────────────

step_firewall() {
    echo ""
    info "Opening port 3001 from proxy to nodes"

    [[ -n "${PROXY_IP:-}" ]] || die "PROXY_IP not set in config.env"

    echo "  GCP..."
    gcloud compute firewall-rules create allow-toprf-proxy \
        --allow=tcp:3001 --source-ranges="${PROXY_IP}/32" \
        --target-tags=toprf-node --project="$GCP_PROJECT" 2>/dev/null \
        || warn "rule may already exist"

    echo "  Azure..."
    az network nsg rule create --resource-group "$AZURE_RG" \
        --nsg-name "${AZURE_VM_NAME}NSG" --name allow-toprf-proxy \
        --priority 100 --access Allow --protocol Tcp \
        --destination-port-ranges 3001 \
        --source-address-prefixes "${PROXY_IP}/32" 2>/dev/null \
        || warn "rule may already exist"

    echo "  AWS..."
    aws ec2 authorize-security-group-ingress \
        --group-id "$AWS_SG_ID" --protocol tcp --port 3001 \
        --cidr "${PROXY_IP}/32" --region "$AWS_NODE_REGION" 2>/dev/null \
        || warn "rule may already exist"

    echo "  Done."
}

# ─── 8. Init-seal (interactive) ─────────────────────────────────────────────

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
        local ip provider vs url share
        ip=$(node_ip "$i")
        provider=$(node_snp_provider "$i")
        vs=$(node_vs "$i")
        url=$(sealed_url "$i")
        share="${NODE_SHARES_DIR}/node-${i}-share.json"

        [[ -f "$share" ]] || die "Key share not found: $share"

        echo "━━━ Node $i ($ip) ━━━"
        echo "  Starting init-seal container..."

        # Clean up any previous init-seal container
        ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true"

        ssh_node "$i" "sudo docker run -d --name toprf-init-seal \
            -e SNP_PROVIDER=${provider} \
            -e EXPECTED_VERIFICATION_SHARE=${vs} \
            -e TSM_REPORT_PATH=/run/tsm/report \
            --device /dev/sev-guest:/dev/sev-guest \
            --privileged --user root \
            -v /sys/kernel/config/tsm/report:/run/tsm/report \
            -p 3001:3001 \
            ${NODE_IMAGE} \
            --init-seal \
            --upload-url '${url}' \
            --port 3001"

        echo "  Waiting for attestation endpoint..."
        local waited=0
        while ! curl -sk "https://${ip}:3001/attest" > /dev/null 2>&1; do
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
        read -r response

        if [[ "$response" == "skip" ]]; then
            echo "  Skipping node $i."
            ssh_node "$i" "sudo docker rm -f toprf-init-seal" || true
            echo ""
            continue
        fi

        echo "  Sending key share to node $i..."
        local http_code body
        body=$(curl -sk "https://${ip}:3001/init-key" \
            -X POST -H "Content-Type: application/json" \
            -d @"$share" \
            -w "\n%{http_code}" 2>&1)

        http_code=$(echo "$body" | tail -1)
        body=$(echo "$body" | sed '$d')

        if [[ "$http_code" == "200" ]]; then
            echo "  Node $i sealed successfully."
        else
            echo "  WARNING: init-key returned HTTP $http_code"
            echo "  Response: $body"
        fi

        # Container exits after sealing; give it a moment then clean up
        sleep 3
        ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true"
        echo ""
    done

    echo "  Init-seal complete."
}

# ─── 9. Start nodes in normal mode ──────────────────────────────────────────

step_start() {
    echo ""
    info "Starting nodes in normal mode"

    load_ceremony

    for i in $(active_nodes); do
        local ip provider vs url
        ip=$(node_ip "$i")
        provider=$(node_snp_provider "$i")
        vs=$(node_vs "$i")
        url=$(sealed_url "$i")

        echo "  Node $i ($ip)..."

        # Stop old container if running
        ssh_node "$i" "sudo docker rm -f toprf-node 2>/dev/null || true"

        ssh_node "$i" "sudo docker run -d --name toprf-node --restart=unless-stopped \
            -e SEALED_KEY_URL='${url}' \
            -e EXPECTED_VERIFICATION_SHARE=${vs} \
            -e SNP_PROVIDER=${provider} \
            -e TSM_REPORT_PATH=/run/tsm/report \
            --device /dev/sev-guest:/dev/sev-guest \
            --privileged --user root \
            -v /sys/kernel/config/tsm/report:/run/tsm/report \
            -v /etc/toprf/certs:/etc/toprf/certs:ro \
            -p 3001:3001 \
            ${NODE_IMAGE} \
            --port 3001 \
            --tls-cert /etc/toprf/certs/node${i}.pem \
            --tls-key /etc/toprf/certs/node${i}.key \
            --client-ca /etc/toprf/certs/ca.pem"
    done

    echo "  Waiting for nodes to boot..."
    sleep 5
    echo "  Done. Run './deploy.sh verify' to check health."
}

# ─── 10. Generate proxy config ──────────────────────────────────────────────

step_proxy_config() {
    echo ""
    info "Generating proxy config"

    load_ceremony

    local out="$REPO_ROOT/docker/proxy-config.production.json"

    # Build nodes array dynamically from active nodes
    local nodes_json=""
    local first=true
    for i in $(active_nodes); do
        local ip=$(node_ip "$i")
        local vs=$(node_vs "$i")
        $first || nodes_json+=","
        nodes_json+="
    {
      \"node_id\": $i,
      \"endpoint\": \"https://${ip}:3001\",
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
  "proxy_client_cert": "/etc/toprf/certs/proxy/proxy-client.pem",
  "proxy_client_key": "/etc/toprf/certs/proxy/proxy-client.key",
  "nodes": [${nodes_json}
  ]
}
CFGEOF

    echo "  Written to: $out"
    echo "  Copy to proxy host: /etc/toprf/proxy-config.json"
    echo "  Done."
}

# ─── 11. Verify ─────────────────────────────────────────────────────────────

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
            --cert "$certs_dir/proxy/proxy-client.pem" \
            --key "$certs_dir/proxy/proxy-client.key" \
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

# ─── 12. Show IPs ───────────────────────────────────────────────────────────

step_show_ips() {
    echo ""
    info "Fetching VM public IPs"

    echo "  Node 1 (GCP ${GCP_ZONE}):"
    local ip1
    ip1=$(gcloud compute instances describe "$GCP_VM_NAME" \
        --zone="$GCP_ZONE" --project="$GCP_PROJECT" \
        --format='get(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null) || true
    echo "    ${ip1:-NOT FOUND}"

    echo "  Node 2 (Azure ${AZURE_RG}):"
    local ip2
    ip2=$(az vm show -d --resource-group "$AZURE_RG" --name "$AZURE_VM_NAME" \
        --query publicIps -o tsv 2>/dev/null) || true
    echo "    ${ip2:-NOT FOUND}"

    echo "  Node 3 (AWS ${AWS_NODE_REGION}):"
    local ip3
    ip3=$(aws ec2 describe-instances --region "$AWS_NODE_REGION" \
        --filters "Name=instance-state-name,Values=running" \
        --query 'Reservations[*].Instances[*].PublicIpAddress' --output text 2>/dev/null) || true
    echo "    ${ip3:-NOT FOUND}"

    echo ""
    echo "  Paste into config.env:"
    echo "    NODE1_IP=${ip1:-}"
    echo "    NODE2_IP=${ip2:-}"
    echo "    NODE3_IP=${ip3:-}"
}

# ─── 13. Auto-config ────────────────────────────────────────────────────────

# Helper: update or append a key=value in config.env
_set_config() {
    local key="$1" value="$2"
    if grep -q "^${key}=" "$CONFIG_FILE"; then
        # Only update if currently empty
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
    info "Auto-populating config.env with values from cloud providers"
    echo ""

    # AWS Account ID
    echo "  Fetching AWS account ID..."
    local aws_id
    aws_id=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || true
    if [[ -n "$aws_id" ]]; then
        _set_config "AWS_ACCOUNT_ID" "$aws_id"
    else
        warn "Could not fetch AWS account ID (aws sts get-caller-identity failed)"
    fi

    # Node IPs
    echo "  Fetching Node 1 IP (GCP)..."
    local ip1
    ip1=$(gcloud compute instances describe "$GCP_VM_NAME" \
        --zone="$GCP_ZONE" --project="$GCP_PROJECT" \
        --format='get(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null) || true
    if [[ -n "$ip1" ]]; then
        _set_config "NODE1_IP" "$ip1"
    else
        warn "Could not fetch Node 1 IP"
    fi

    echo "  Fetching Node 2 IP (Azure)..."
    local ip2
    ip2=$(az vm show -d --resource-group "$AZURE_RG" --name "$AZURE_VM_NAME" \
        --query publicIps -o tsv 2>/dev/null) || true
    if [[ -n "$ip2" ]]; then
        _set_config "NODE2_IP" "$ip2"
    else
        warn "Could not fetch Node 2 IP"
    fi

    echo "  Fetching Node 3 IP (AWS)..."
    local ip3
    ip3=$(aws ec2 describe-instances --region "$AWS_NODE_REGION" \
        --filters "Name=tag:Name,Values=${AWS_VM_NAME:-toprf-node-3}" "Name=instance-state-name,Values=running" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null) || true
    if [[ -n "$ip3" && "$ip3" != "None" ]]; then
        _set_config "NODE3_IP" "$ip3"
    else
        warn "Could not fetch Node 3 IP"
    fi

    # AWS Security Group ID (from the node instance)
    echo "  Fetching AWS security group ID..."
    local sg_id
    sg_id=$(aws ec2 describe-instances --region "$AWS_NODE_REGION" \
        --filters "Name=tag:Name,Values=${AWS_VM_NAME:-toprf-node-3}" "Name=instance-state-name,Values=running" \
        --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text 2>/dev/null) || true
    if [[ -n "$sg_id" && "$sg_id" != "None" ]]; then
        _set_config "AWS_SG_ID" "$sg_id"
    else
        warn "Could not fetch AWS security group ID"
    fi

    # Proxy IP (NAT Gateway EIP from ECS state file)
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

# ─── 13. Redeploy (pull latest image + restart) ─────────────────────────────

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
Usage: deploy.sh <step> [step...]

Steps (run in order for fresh deployment):
  pull          Pull node image from ghcr.io on each VM
  storage       Create storage buckets + bind VM identities
  setup-vms     Install Docker on all 3 VMs
  certs         Generate mTLS certs (with real IPs) + distribute
  firewall      Open port 3001 from proxy IP to each node
  init-seal     Interactive: inject key shares via attested TLS
  start         Start nodes in normal mode (unseal + serve)
  proxy-config  Generate docker/proxy-config.production.json
  verify        Health check all nodes via mTLS

Utilities:
  auto-config   Auto-populate config.env (IPs, account ID, SG, proxy IP)
  show-ips      Fetch public IPs from all 3 providers

Shortcuts:
  pre-seal      setup-vms → pull → storage → certs
  post-seal     start → firewall → proxy-config → verify
  all           pre-seal → init-seal → post-seal
  redeploy      pull latest image → restart nodes
EOF
}

if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

for step in "$@"; do
    case "$step" in
        pull)         step_pull ;;
        storage)      step_storage ;;
        setup-vms)    step_setup_vms ;;
        certs)        step_certs ;;
        firewall)     step_firewall ;;
        init-seal)    step_init_seal ;;
        start)        step_start ;;
        proxy-config) step_proxy_config ;;
        verify)       step_verify ;;
        auto-config)  step_auto_config ;;
        show-ips)     step_show_ips ;;
        redeploy)     step_redeploy ;;
        pre-seal)
            step_setup_vms
            step_pull
            step_storage
            step_certs
            ;;
        post-seal)
            step_start
            step_firewall
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
