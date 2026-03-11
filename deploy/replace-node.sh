#!/usr/bin/env bash
# =============================================================================
# replace-node.sh — Replace a single failed OPRF node.
#
# Handles the full lifecycle of replacing a dead node:
#   1. Provision a new VM in the same region
#   2. Install Docker and pull the node image
#   3. Run init-seal (S3-mediated ECIES key injection)
#   4. Update the NLB target group (swap old IP → new IP)
#   5. Start the node with its coordinator config
#   6. Verify health
#
# The other nodes and their coordinator configs don't change — the NLB
# target swap is invisible to peers since the PrivateLink endpoint DNS
# stays the same.
#
# Usage:
#   ./replace-node.sh <node_number> --share-file <path>
#   ./replace-node.sh 3 --share-file ../ceremony/node-shares/node-3-share.json
#
# Prerequisites:
#   - config.env populated (regions, S3 buckets, etc.)
#   - provision.sh available (for VM provisioning)
#   - deploy.sh available (for setup-vms, pull, init-seal, start)
#   - privatelink-state.env exists (from original deployment)
#   - The node's key share file
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ─── Helpers ─────────────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
warn()  { echo "  WARN: $*"; }
die()   { echo "  ERROR: $*" >&2; exit 1; }

# ─── Parse arguments ─────────────────────────────────────────────────────────

usage() {
    cat <<'EOF'
Usage: replace-node.sh <node_number> [OPTIONS]

Replaces a failed OPRF node with a new VM. Provisions the VM, seals the
key share, updates the NLB target group, and starts the node.

Arguments:
  <node_number>     Node to replace (1, 2, or 3)

Options:
  --share-file <PATH>           Path to the node's key share JSON file
  --expected-measurement <HEX>  Expected measurement for attestation (96 hex chars)
  --skip-provision              Skip VM provisioning (VM already exists)
  --skip-init-seal              Skip init-seal (node already has a sealed blob)
  -h, --help                    Show this help

Examples:
  # Full replacement (provision new VM + seal + start)
  ./replace-node.sh 3 --share-file ../ceremony/node-shares/node-3-share.json

  # Node VM exists but needs re-sealing
  ./replace-node.sh 3 --share-file ../ceremony/node-shares/node-3-share.json --skip-provision

  # Node already sealed, just need to update NLB target and start
  ./replace-node.sh 3 --skip-provision --skip-init-seal
EOF
}

if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

NODE_NUM="$1"
shift

if [[ ! "$NODE_NUM" =~ ^[1-3]$ ]]; then
    die "Node number must be 1, 2, or 3 (got: $NODE_NUM)"
fi

SHARE_FILE=""
EXPECTED_MEASUREMENT=""
SKIP_PROVISION=false
SKIP_INIT_SEAL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --share-file)
            shift
            [[ $# -gt 0 ]] || die "Missing value for --share-file"
            SHARE_FILE="$1"
            shift
            ;;
        --expected-measurement)
            shift
            [[ $# -gt 0 ]] || die "Missing value for --expected-measurement"
            EXPECTED_MEASUREMENT="$1"
            shift
            ;;
        --skip-provision)
            SKIP_PROVISION=true
            shift
            ;;
        --skip-init-seal)
            SKIP_INIT_SEAL=true
            shift
            ;;
        -h|--help|help)
            usage
            exit 0
            ;;
        *)
            die "Unknown argument: $1"
            ;;
    esac
done

# Validate share file is provided when init-seal is needed
if [[ "$SKIP_INIT_SEAL" != "true" && -z "$SHARE_FILE" ]]; then
    die "--share-file is required (unless --skip-init-seal is set)"
fi

if [[ -n "$SHARE_FILE" && ! -f "$SHARE_FILE" ]]; then
    die "Share file not found: $SHARE_FILE"
fi

# ─── Load configuration ─────────────────────────────────────────────────────

CONFIG_FILE="${SCRIPT_DIR}/config.env"
[[ -f "$CONFIG_FILE" ]] || die "config.env not found at $CONFIG_FILE"
source "$CONFIG_FILE"

PL_STATE="${SCRIPT_DIR}/privatelink-state.env"
[[ -f "$PL_STATE" ]] || die "privatelink-state.env not found. Original deployment required."
source "$PL_STATE"

NODE_IMAGE="${NODE_IMAGE:-ghcr.io/${GHCR_OWNER:-jeganggs64}/toprf-node:latest}"

# ─── Node config helpers ────────────────────────────────────────────────────

node_var() {
    local var="NODE${NODE_NUM}_${1}"
    echo "${!var:-}"
}

REGION=$(node_var REGION)
SSH_KEY=$(node_var SSH_KEY)
S3_BUCKET=$(node_var S3_BUCKET)

[[ -n "$REGION" ]]    || die "NODE${NODE_NUM}_REGION not set in config.env"
[[ -n "$S3_BUCKET" ]] || die "NODE${NODE_NUM}_S3_BUCKET not set in config.env"

ssh_node() {
    local key ip
    key=$(node_var SSH_KEY)
    ip=$(node_var IP)
    ssh -o StrictHostKeyChecking=accept-new -i "$key" "ec2-user@${ip}" "$@"
}

scp_to_node() {
    local key ip
    key=$(node_var SSH_KEY)
    ip=$(node_var IP)
    scp -o StrictHostKeyChecking=accept-new -i "$key" "$@" "ec2-user@${ip}:/tmp/"
}

# Load ceremony data
NODE_SHARES_DIR="${NODE_SHARES_DIR:-$REPO_ROOT/ceremony/node-shares}"
PUBLIC_CONFIG="${NODE_SHARES_DIR}/public-config.json"
[[ -f "$PUBLIC_CONFIG" ]] || die "public-config.json not found at $PUBLIC_CONFIG"

VS=$(jq -r ".verification_shares[] | select(.node_id == ${NODE_NUM}) | .verification_share" "$PUBLIC_CONFIG")
[[ -n "$VS" ]] || die "Verification share for node $NODE_NUM not found in public-config.json"

# ─── Step 1: Provision new VM ───────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Replacing node $NODE_NUM in $REGION"
echo "═══════════════════════════════════════════════════"

if [[ "$SKIP_PROVISION" == "true" ]]; then
    info "Skipping VM provisioning (--skip-provision)"
    # Verify the VM exists and we can reach it
    NODE_IP=$(node_var IP)
    [[ -n "$NODE_IP" ]] || die "NODE${NODE_NUM}_IP not set. Cannot skip provisioning without an IP."
    echo "  Using existing VM: $NODE_IP"
else
    info "Step 1: Terminating old instance and provisioning new VM"

    # Terminate old instance (if it exists)
    "$SCRIPT_DIR/provision.sh" "$NODE_NUM" --terminate 2>/dev/null || true

    # Provision new VM
    "$SCRIPT_DIR/provision.sh" "$NODE_NUM"

    # Update config.env with new IPs
    info "Updating config.env with new VM details"
    cd "$SCRIPT_DIR"
    # Use deploy.sh auto-config to update just this node's details
    _NODE_FILTER="$NODE_NUM" "$SCRIPT_DIR/deploy.sh" auto-config

    # Re-source config to pick up new IPs
    source "$CONFIG_FILE"

    NODE_IP=$(node_var IP)
    NODE_PRIVATE_IP=$(node_var PRIVATE_IP)
    echo "  New VM: $NODE_IP (private: $NODE_PRIVATE_IP)"
fi

# ─── Step 2: Install Docker + pull image ────────────────────────────────────

info "Step 2: Setting up Docker and pulling node image"
_NODE_FILTER="$NODE_NUM" "$SCRIPT_DIR/deploy.sh" setup-vms
_NODE_FILTER="$NODE_NUM" "$SCRIPT_DIR/deploy.sh" pull

# ─── Step 3: Init-seal ─────────────────────────────────────────────────────

if [[ "$SKIP_INIT_SEAL" == "true" ]]; then
    info "Skipping init-seal (--skip-init-seal)"
else
    info "Step 3: Init-seal (S3-mediated ECIES key injection)"

    # Build toprf-init-encrypt if needed
    local_init_encrypt="$REPO_ROOT/target/release/toprf-init-encrypt"
    if [[ ! -x "$local_init_encrypt" ]]; then
        echo "  Building toprf-init-encrypt..."
        (cd "$REPO_ROOT" && cargo build --release -p toprf-seal --bin toprf-init-encrypt 2>&1 | tail -3)
    fi

    SEALED_URL="s3://${S3_BUCKET}/node-${NODE_NUM}-sealed.bin"

    # Clean up any previous init-seal container
    ssh_node "sudo docker rm -f toprf-init-seal 2>/dev/null || true"

    # Start init-seal container
    echo "  Starting init-seal container..."
    ssh_node "sudo docker run -d --name toprf-init-seal \
        -e EXPECTED_VERIFICATION_SHARE=${VS} \
        --device /dev/sev-guest:/dev/sev-guest \
        --privileged --user root \
        ${NODE_IMAGE} \
        --init-seal \
        --s3-bucket '${S3_BUCKET}' \
        --upload-url '${SEALED_URL}'"

    # Wait for attestation artifacts in S3
    S3_ATTESTATION="s3://${S3_BUCKET}/init/attestation.bin"
    S3_PUBKEY="s3://${S3_BUCKET}/init/pubkey.bin"
    S3_ENCRYPTED="s3://${S3_BUCKET}/init/encrypted-share.bin"
    TMPDIR=$(mktemp -d)

    echo "  Waiting for attestation artifacts in S3..."
    waited=0
    while ! aws s3 cp "$S3_ATTESTATION" "$TMPDIR/attestation.bin" --quiet 2>/dev/null; do
        running=$(ssh_node "sudo docker inspect -f '{{.State.Running}}' toprf-init-seal 2>/dev/null || echo false")
        if [[ "$running" != "true" ]]; then
            echo "  Container exited prematurely. Logs:"
            ssh_node "sudo docker logs --tail 20 toprf-init-seal 2>&1" || true
            rm -rf "$TMPDIR"
            die "init-seal container failed"
        fi
        sleep 3
        waited=$((waited + 1))
        if [[ $waited -ge 40 ]]; then
            rm -rf "$TMPDIR"
            die "Timed out waiting for attestation in S3 (120s)"
        fi
    done

    aws s3 cp "$S3_PUBKEY" "$TMPDIR/pubkey.bin" --quiet
    echo "  Attestation and pubkey downloaded."

    # Verify attestation + encrypt share
    encrypt_args=(
        --attestation "$TMPDIR/attestation.bin"
        --pubkey "$TMPDIR/pubkey.bin"
        --output "$TMPDIR/encrypted-share.bin"
        --share-file "$SHARE_FILE"
    )

    if [[ -n "$EXPECTED_MEASUREMENT" ]]; then
        encrypt_args+=(--expected-measurement "$EXPECTED_MEASUREMENT")
    else
        echo ""
        echo "  EXPECTED_MEASUREMENT not set. Enter the expected measurement (96 hex chars),"
        echo "  or press Enter to skip attestation verification (dev only):"
        read -r EXPECTED_MEASUREMENT < /dev/tty
        if [[ -n "$EXPECTED_MEASUREMENT" ]]; then
            encrypt_args+=(--expected-measurement "$EXPECTED_MEASUREMENT")
        else
            encrypt_args+=(--skip-attestation-verify --expected-measurement "$(printf '%096d' 0)")
            echo "  WARNING: skipping attestation verification (dev mode)"
        fi
    fi

    echo "  Verifying attestation and encrypting key share..."
    "$local_init_encrypt" "${encrypt_args[@]}" 2>&1 | sed 's/^/  /'

    # Upload encrypted share
    echo "  Uploading encrypted share to S3..."
    aws s3 cp "$TMPDIR/encrypted-share.bin" "$S3_ENCRYPTED" --quiet

    # Wait for container to seal and exit
    echo "  Waiting for node to seal..."
    seal_waited=0
    while true; do
        running=$(ssh_node "sudo docker inspect -f '{{.State.Running}}' toprf-init-seal 2>/dev/null || echo false")
        if [[ "$running" != "true" ]]; then
            break
        fi
        sleep 3
        seal_waited=$((seal_waited + 1))
        if [[ $seal_waited -ge 60 ]]; then
            warn "Timed out waiting for seal (180s)"
            break
        fi
    done

    exit_code=$(ssh_node "sudo docker inspect -f '{{.State.ExitCode}}' toprf-init-seal 2>/dev/null || echo 1")
    if [[ "$exit_code" == "0" ]]; then
        echo "  Node $NODE_NUM sealed successfully."
    else
        echo "  Seal container logs:"
        ssh_node "sudo docker logs --tail 20 toprf-init-seal 2>&1" | sed 's/^/    /' || true
        rm -rf "$TMPDIR"
        die "init-seal failed (exit code $exit_code)"
    fi

    ssh_node "sudo docker rm -f toprf-init-seal 2>/dev/null || true"
    rm -rf "$TMPDIR"
fi

# ─── Step 4: Update NLB target group ───────────────────────────────────────

info "Step 4: Updating NLB target group"

# Re-source config to get latest IPs
source "$CONFIG_FILE"
NODE_PRIVATE_IP=$(node_var PRIVATE_IP)
[[ -n "$NODE_PRIVATE_IP" ]] || die "NODE${NODE_NUM}_PRIVATE_IP not set"

TG_VAR="PL_TG_ARN_NODE${NODE_NUM}"
TG_ARN="${!TG_VAR:-}"
[[ -n "$TG_ARN" ]] || die "Target group ARN not found for node $NODE_NUM in privatelink-state.env"

# Get current targets
echo "  Target group: $TG_ARN"
CURRENT_TARGETS=$(aws elbv2 describe-target-health \
    --region "$REGION" \
    --target-group-arn "$TG_ARN" \
    --query 'TargetHealthDescriptions[*].Target.Id' --output text 2>/dev/null || echo "")

# Deregister old targets
if [[ -n "$CURRENT_TARGETS" ]]; then
    for old_ip in $CURRENT_TARGETS; do
        if [[ "$old_ip" != "$NODE_PRIVATE_IP" ]]; then
            echo "  Deregistering old target: $old_ip"
            aws elbv2 deregister-targets --region "$REGION" \
                --target-group-arn "$TG_ARN" \
                --targets "Id=${old_ip},Port=3001" 2>/dev/null || true
        fi
    done
fi

# Register new target
echo "  Registering new target: ${NODE_PRIVATE_IP}:3001"
aws elbv2 register-targets --region "$REGION" \
    --target-group-arn "$TG_ARN" \
    --targets "Id=${NODE_PRIVATE_IP},Port=3001"

echo "  Target group updated."

# ─── Step 5: Start the node ────────────────────────────────────────────────

info "Step 5: Starting node"

# Upload coordinator config (if it exists)
COORD_CONFIG="${SCRIPT_DIR}/coordinator-configs/coordinator-node-${NODE_NUM}.json"
if [[ -f "$COORD_CONFIG" ]]; then
    scp_to_node "$COORD_CONFIG"
    ssh_node "sudo mkdir -p /etc/toprf && sudo mv /tmp/coordinator-node-${NODE_NUM}.json /etc/toprf/coordinator.json"
    echo "  Coordinator config uploaded."
else
    warn "No coordinator config found at $COORD_CONFIG"
    warn "Run './deploy.sh coordinator-config' to generate configs."
fi

SEALED_URL="s3://${S3_BUCKET}/node-${NODE_NUM}-sealed.bin"

ssh_node "sudo docker rm -f toprf-node 2>/dev/null || true"
ssh_node "sudo docker run -d --name toprf-node --restart=unless-stopped \
    -e SEALED_KEY_URL='${SEALED_URL}' \
    -e EXPECTED_VERIFICATION_SHARE=${VS} \
    -v /etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro \
    --device /dev/sev-guest:/dev/sev-guest \
    --privileged --user root \
    -p 3001:3001 \
    ${NODE_IMAGE} \
    --port 3001 \
    --coordinator-config /etc/toprf/coordinator.json"

echo "  Node started. Waiting for health check..."
sleep 5

# ─── Step 6: Verify health ─────────────────────────────────────────────────

info "Step 6: Verifying node health"

waited=0
while true; do
    resp=$(ssh_node "curl -s --connect-timeout 5 http://localhost:3001/health 2>&1") || true

    if echo "$resp" | jq -e '.status == "ready"' > /dev/null 2>&1; then
        echo "  Node $NODE_NUM is healthy and ready."
        break
    fi

    waited=$((waited + 1))
    if [[ $waited -ge 12 ]]; then
        echo "  Health check response: $resp"
        echo "  Container logs:"
        ssh_node "sudo docker logs --tail 20 toprf-node 2>&1" | sed 's/^/    /' || true
        die "Node $NODE_NUM failed health check after 60s"
    fi
    sleep 5
done

# ─── Done ───────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Node $NODE_NUM replaced successfully"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Region:       $REGION"
echo "  Public IP:    $(node_var IP)"
echo "  Private IP:   $NODE_PRIVATE_IP"
echo "  Status:       ready"
echo ""
echo "  The PrivateLink endpoint DNS is unchanged."
echo "  Other nodes will route to the new instance automatically."
echo ""
echo "  To verify end-to-end:"
echo "    ./deploy.sh e2e"
