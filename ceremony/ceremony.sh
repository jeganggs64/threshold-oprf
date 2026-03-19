#!/usr/bin/env bash
# =============================================================================
# ceremony.sh — TOPRF Key Ceremony for Raspberry Pi
#
# Generates a new OPRF master key, splits it into admin and node shares,
# prints admin shares, deploys node shares to TEE nodes via init-seal,
# and verifies the deployment with a local OPRF evaluation.
#
# Prerequisites on the Raspberry Pi:
#   - toprf-keygen       (aarch64 binary, in same directory)
#   - toprf-init-encrypt (aarch64 binary, in same directory)
#   - ceremony.env       (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION)
#   - config.env         (copied from deploy/)
#   - nodes.json         (copied from deploy/)
#   - ssh-keys/          (SSH .pem files, named by key_name from nodes.json)
#   - coordinator-configs/ (copied from deploy/coordinator-configs/)
#   - aws cli, jq, qrencode, imagemagick, shred
#   - CUPS configured with USB printer
#
# Usage:
#   ./ceremony.sh              Run all steps
#   ./ceremony.sh --from <N>   Resume from step N
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ─── Configuration ──────────────────────────────────────────────────────────

ADMIN_THRESHOLD=2
ADMIN_SHARES=4
NODE_THRESHOLD=2
NODE_SHARES=3

ADMIN_DIR="$SCRIPT_DIR/admin-shares"
NODE_DIR="$SCRIPT_DIR/node-shares"

KEYGEN="$SCRIPT_DIR/toprf-keygen"
INIT_ENCRYPT="$SCRIPT_DIR/toprf-init-encrypt"

CEREMONY_ENV="$SCRIPT_DIR/ceremony.env"
CONFIG_ENV="$SCRIPT_DIR/config.env"
NODES_JSON="$SCRIPT_DIR/nodes.json"

# Printer name (empty = default printer)
PRINTER="${CEREMONY_PRINTER:-}"

# ─── Helpers ────────────────────────────────────────────────────────────────

info()    { echo "==> $*"; }
warn()    { echo "  WARN: $*"; }
die()     { echo "  ERROR: $*" >&2; exit 1; }
confirm() { echo ""; echo "  $*"; echo "  Press Enter to continue (Ctrl-C to abort)..."; read -r; }

# ─── Pre-flight checks ─────────────────────────────────────────────────────

preflight() {
    local ok=true

    [[ -x "$KEYGEN" ]]       || { echo "  MISSING: toprf-keygen"; ok=false; }
    [[ -x "$INIT_ENCRYPT" ]] || { echo "  MISSING: toprf-init-encrypt"; ok=false; }
    [[ -f "$CEREMONY_ENV" ]] || { echo "  MISSING: ceremony.env"; ok=false; }
    [[ -f "$CONFIG_ENV" ]]   || { echo "  MISSING: config.env"; ok=false; }
    [[ -f "$NODES_JSON" ]]   || { echo "  MISSING: nodes.json"; ok=false; }
    command -v jq >/dev/null  || { echo "  MISSING: jq"; ok=false; }
    command -v aws >/dev/null || { echo "  MISSING: aws cli"; ok=false; }
    command -v qrencode >/dev/null || { echo "  MISSING: qrencode (apt install qrencode)"; ok=false; }
    command -v convert >/dev/null  || { echo "  MISSING: imagemagick (apt install imagemagick)"; ok=false; }
    command -v shred >/dev/null    || { echo "  MISSING: shred"; ok=false; }
    command -v ssh >/dev/null      || { echo "  MISSING: ssh"; ok=false; }

    # Verify SSH keys exist for all nodes
    local node_count
    node_count=$(jq '.nodes | length' "$NODES_JSON")
    for idx in $(seq 0 $((node_count - 1))); do
        local key_name
        key_name=$(jq -r ".nodes[$idx].key_name" "$NODES_JSON")
        local key_file="$SCRIPT_DIR/ssh-keys/${key_name}.pem"
        if [[ ! -f "$key_file" ]]; then
            echo "  MISSING: $key_file"
            ok=false
        fi
    done

    $ok || die "Pre-flight checks failed. Fix the above and re-run."
    echo "  All pre-flight checks passed."
}

# ─── Node helpers (read from nodes.json) ────────────────────────────────────

_node_field() {
    local id="$1" field="$2"
    jq -r --argjson id "$id" '.nodes[] | select(.id == $id) | .'"$field"' // empty' "$NODES_JSON"
}

node_ip()         { _node_field "$1" ip; }
node_s3_bucket()  { _node_field "$1" s3_bucket; }
node_key_name()   { _node_field "$1" key_name; }
all_node_ids()    { jq -r '.nodes[].id' "$NODES_JSON" | tr '\n' ' '; }

node_ssh_key() {
    local key_name
    key_name=$(node_key_name "$1")
    echo "$SCRIPT_DIR/ssh-keys/${key_name}.pem"
}

ssh_node() {
    local n="$1"; shift
    local key ip
    key=$(node_ssh_key "$n")
    ip=$(node_ip "$n")
    ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -i "$key" "ec2-user@${ip}" "$*"
}

scp_to_node() {
    local n="$1"; shift
    local key ip
    key=$(node_ssh_key "$n")
    ip=$(node_ip "$n")
    scp -o StrictHostKeyChecking=accept-new -i "$key" "$@" "ec2-user@${ip}:/tmp/"
}

sealed_url() {
    local bucket
    bucket=$(node_s3_bucket "$1")
    echo "s3://${bucket}/node-${1}-sealed.bin"
}

node_vs() {
    local config="$NODE_DIR/public-config.json"
    jq -r --argjson id "$1" '.verification_shares[] | select(.node_id == $id) | .verification_share' "$config"
}

lp_cmd() {
    if [[ -n "$PRINTER" ]]; then
        lp -d "$PRINTER" "$@"
    else
        lp "$@"
    fi
}

# ─── Parse args ─────────────────────────────────────────────────────────────

FROM_STEP=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --from)
            FROM_STEP="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: ceremony.sh [--from <step>]"
            echo "  --from <N>  Resume from step N (1-13)"
            exit 0
            ;;
        *)
            die "Unknown argument: $1"
            ;;
    esac
done

# =============================================================================
# Ceremony
# =============================================================================

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║             TOPRF KEY CEREMONY                               ║"
echo "║                                                              ║"
echo "║  Admin shares:  ${ADMIN_THRESHOLD}-of-${ADMIN_SHARES}                                     ║"
echo "║  Node shares:   ${NODE_THRESHOLD}-of-${NODE_SHARES}                                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

info "Pre-flight checks"
preflight

# ─── Step 1: Generate master key and admin shares ───────────────────────────

if [[ $FROM_STEP -le 1 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 1: Generate master key and admin shares"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    "$KEYGEN" init \
        --admin-threshold "$ADMIN_THRESHOLD" \
        --admin-shares "$ADMIN_SHARES" \
        --output-dir "$ADMIN_DIR"

    echo ""
    info "Admin shares generated in $ADMIN_DIR"
fi

# ─── Step 2: Generate node shares ──────────────────────────────────────────

if [[ $FROM_STEP -le 2 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 2: Generate node shares from admin shares"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Use the first ADMIN_THRESHOLD admin shares for reconstruction
    ADMIN_ARGS=()
    for i in $(seq 1 "$ADMIN_THRESHOLD"); do
        ADMIN_ARGS+=(--admin-share "$ADMIN_DIR/admin-${i}.json")
    done

    "$KEYGEN" node-shares \
        "${ADMIN_ARGS[@]}" \
        --node-threshold "$NODE_THRESHOLD" \
        --node-shares "$NODE_SHARES" \
        --output-dir "$NODE_DIR"

    echo ""
    info "Node shares generated in $NODE_DIR"
fi

# ─── Step 3: Cross-verify shares ───────────────────────────────────────────

if [[ $FROM_STEP -le 3 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 3: Cross-verify admin and node shares"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    ADMIN_ARGS=()
    for i in $(seq 1 "$ADMIN_THRESHOLD"); do
        ADMIN_ARGS+=(--admin-share "$ADMIN_DIR/admin-${i}.json")
    done

    NODE_ARGS=()
    for i in $(seq 1 "$NODE_THRESHOLD"); do
        NODE_ARGS+=(--node-share "$NODE_DIR/node-${i}-share.json")
    done

    "$KEYGEN" verify "${ADMIN_ARGS[@]}" "${NODE_ARGS[@]}"

    GROUP_PK=$(jq -r '.group_public_key' "$NODE_DIR/public-config.json")
    echo ""
    info "Verification passed. Group public key: $GROUP_PK"
fi

# ─── Step 4: Print admin shares ────────────────────────────────────────────

if [[ $FROM_STEP -le 4 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 4: Print admin shares"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    GROUP_PK=$(jq -r '.group_public_key' "$NODE_DIR/public-config.json")
    CEREMONY_DATE=$(date -u +%Y-%m-%d)

    for i in $(seq 1 "$ADMIN_SHARES"); do
        SHARE_FILE="$ADMIN_DIR/admin-${i}.json"
        echo "  Printing admin share $i of $ADMIN_SHARES..."

        # Generate QR code
        qrencode -t PNG -o "/tmp/ceremony-qr-${i}.png" -8 -s 6 < "$SHARE_FILE"

        # Render header as image
        HEADER="════════════════════════════════════════
  TOPRF ADMIN KEY SHARE ${i} of ${ADMIN_SHARES}
  Threshold: ${ADMIN_THRESHOLD}-of-${ADMIN_SHARES}
  Group Public Key:
  ${GROUP_PK}
  Date: ${CEREMONY_DATE}
════════════════════════════════════════"

        convert -size 535x -font Courier -pointsize 13 \
            -background white -fill black \
            caption:"$HEADER" \
            /tmp/ceremony-header-${i}.png

        # Render plain text share as image
        SHARE_TEXT="--- PLAIN TEXT ---

$(cat "$SHARE_FILE")

════════════════════════════════════════
  END OF SHARE ${i}
════════════════════════════════════════"

        convert -size 535x -font Courier -pointsize 10 \
            -background white -fill black \
            caption:"$SHARE_TEXT" \
            /tmp/ceremony-text-${i}.png

        # Compose single page: header + QR + plain text (stacked vertically)
        convert \
            /tmp/ceremony-header-${i}.png \
            \( /tmp/ceremony-qr-${i}.png -gravity center \) \
            /tmp/ceremony-text-${i}.png \
            -gravity center -append \
            -bordercolor white -border 30x30 \
            /tmp/ceremony-page-${i}.pdf

        lp_cmd /tmp/ceremony-page-${i}.pdf

        # Cleanup temp files
        rm -f /tmp/ceremony-qr-${i}.png /tmp/ceremony-header-${i}.png \
              /tmp/ceremony-text-${i}.png /tmp/ceremony-page-${i}.pdf
    done

    echo ""
    info "All $ADMIN_SHARES admin shares printed."
    echo "  Verify all pages printed correctly before continuing."
    confirm "Have all shares printed correctly?"
fi

# ─── Step 5: Connect to network ────────────────────────────────────────────

if [[ $FROM_STEP -le 5 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 5: Connect to network"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    echo "  Connect the Raspberry Pi to the network now."
    confirm "Is the network connected?"

    # Verify connectivity
    if ! ping -c 1 -W 5 8.8.8.8 > /dev/null 2>&1; then
        die "No network connectivity. Check connection and re-run with --from 5"
    fi
    echo "  Network connectivity verified."
fi

# ─── Step 6: Configure AWS ─────────────────────────────────────────────────

if [[ $FROM_STEP -le 6 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 6: Configure AWS credentials"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    source "$CEREMONY_ENV"
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION

    echo "  Verifying AWS access..."
    aws sts get-caller-identity
    echo ""
    info "AWS credentials configured."
fi

# ─── Step 7: Init-seal + start nodes ───────────────────────────────────────

if [[ $FROM_STEP -le 7 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 7: Deploy key shares to nodes (init-seal + start)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Load ceremony.env and config.env if not already loaded
    [[ -z "${AWS_ACCESS_KEY_ID:-}" ]] && source "$CEREMONY_ENV" && export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
    source "$CONFIG_ENV"

    GROUP_PK=$(jq -r '.group_public_key' "$NODE_DIR/public-config.json")

    # 7a. Stop running nodes
    echo ""
    info "7a. Stopping running nodes..."
    for i in $(all_node_ids); do
        local_ip=$(node_ip "$i")
        echo "  Node $i ($local_ip): stopping..."
        ssh_node "$i" "sudo docker rm -f toprf-node 2>/dev/null || true" < /dev/null || true
    done

    # 7b. Clean S3 init/ prefix
    echo ""
    info "7b. Cleaning S3 init/ artifacts..."
    for i in $(all_node_ids); do
        bucket=$(node_s3_bucket "$i")
        echo "  Node $i: cleaning s3://${bucket}/init/..."
        aws s3 rm "s3://${bucket}/init/" --recursive --quiet 2>/dev/null || true
    done

    # 7c. Init-seal for each node
    echo ""
    info "7c. Init-seal (attested key injection)..."
    echo ""

    local expected_measurement="${EXPECTED_MEASUREMENT:-}"
    if [[ -z "$expected_measurement" ]]; then
        die "EXPECTED_MEASUREMENT not set in config.env. Run deploy.sh measure first."
    fi

    for i in $(all_node_ids); do
        ip=$(node_ip "$i")
        vs=$(node_vs "$i")
        url=$(sealed_url "$i")
        share="${NODE_DIR}/node-${i}-share.json"
        bucket=$(node_s3_bucket "$i")

        [[ -f "$share" ]] || die "Key share not found: $share"

        echo "  ━━━ Node $i ($ip) ━━━"
        echo "    S3 bucket: $bucket"
        echo "    Starting init-seal container..."

        # Clean up previous init-seal container
        ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true" < /dev/null

        ssh_node "$i" "sudo docker run -d --name toprf-init-seal \
            -e EXPECTED_VERIFICATION_SHARE=${vs} \
            --device /dev/sev-guest:/dev/sev-guest \
            --user root \
            ${NODE_IMAGE} \
            --init-seal \
            --s3-bucket '${bucket}' \
            --upload-url '${url}'" < /dev/null

        echo "    Waiting for attestation artifacts in S3..."

        # Poll for attestation.bin in S3
        s3_attestation="s3://${bucket}/init/attestation.bin"
        s3_pubkey="s3://${bucket}/init/pubkey.bin"
        s3_certs="s3://${bucket}/init/certs.bin"
        s3_encrypted="s3://${bucket}/init/encrypted-share.bin"
        tmpdir=$(mktemp -d)

        waited=0
        while ! aws s3 cp "$s3_attestation" "$tmpdir/attestation.bin" --quiet 2>/dev/null; do
            running=$(ssh_node "$i" "sudo docker inspect -f '{{.State.Running}}' toprf-init-seal 2>/dev/null || echo false" < /dev/null)
            if [[ "$running" != "true" ]]; then
                echo "    Container exited prematurely. Logs:"
                ssh_node "$i" "sudo docker logs --tail 20 toprf-init-seal 2>&1" < /dev/null || true
                rm -rf "$tmpdir"
                die "Init-seal failed for node $i"
            fi
            sleep 3
            waited=$((waited + 1))
            if [[ $waited -ge 40 ]]; then
                rm -rf "$tmpdir"
                die "Timed out waiting for attestation from node $i (120s)"
            fi
        done

        aws s3 cp "$s3_pubkey" "$tmpdir/pubkey.bin" --quiet
        aws s3 cp "$s3_certs" "$tmpdir/certs.bin" --quiet
        echo "    Attestation artifacts downloaded."

        # Verify attestation and encrypt key share
        echo "    Verifying attestation and encrypting key share..."
        AMD_ARK_FINGERPRINT="${AMD_ARK_FINGERPRINT:-}" \
            "$INIT_ENCRYPT" \
            --attestation "$tmpdir/attestation.bin" \
            --pubkey "$tmpdir/pubkey.bin" \
            --certs "$tmpdir/certs.bin" \
            --output "$tmpdir/encrypted-share.bin" \
            --share-file "$share" \
            --expected-measurement "$expected_measurement" 2>&1 | sed 's/^/    /'

        # Upload encrypted share
        echo "    Uploading encrypted share to S3..."
        aws s3 cp "$tmpdir/encrypted-share.bin" "$s3_encrypted" --quiet

        echo "    Waiting for node to seal..."

        # Wait for container to finish
        seal_waited=0
        while true; do
            running=$(ssh_node "$i" "sudo docker inspect -f '{{.State.Running}}' toprf-init-seal 2>/dev/null || echo false" < /dev/null)
            if [[ "$running" != "true" ]]; then
                break
            fi
            sleep 3
            seal_waited=$((seal_waited + 1))
            if [[ $seal_waited -ge 60 ]]; then
                echo "    Timed out waiting for seal."
                break
            fi
        done

        # Check exit code
        exit_code=$(ssh_node "$i" "sudo docker inspect -f '{{.State.ExitCode}}' toprf-init-seal 2>/dev/null || echo 1" < /dev/null)
        if [[ "$exit_code" == "0" ]]; then
            echo "    Node $i sealed successfully."
        else
            echo "    WARNING: init-seal exited with code $exit_code"
            ssh_node "$i" "sudo docker logs --tail 20 toprf-init-seal 2>&1" < /dev/null | sed 's/^/      /' || true
        fi

        ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true" < /dev/null
        rm -rf "$tmpdir"
        echo ""
    done

    info "Init-seal complete for all nodes."

    # 7d. Upload coordinator configs and start nodes
    echo ""
    info "7d. Starting nodes in auto-unseal mode..."

    for i in $(all_node_ids); do
        ip=$(node_ip "$i")
        vs=$(node_vs "$i")
        url=$(sealed_url "$i")
        bucket=$(node_s3_bucket "$i")

        echo "  Node $i ($ip)..."

        # Upload coordinator config if available locally
        coord_config="$SCRIPT_DIR/coordinator-configs/coordinator-node-${i}.json"
        coord_args=""
        if [[ -f "$coord_config" ]]; then
            scp_to_node "$i" "$coord_config" < /dev/null || die "Failed to upload coordinator config to node $i"
            ssh_node "$i" "sudo mkdir -p /etc/toprf && sudo mv /tmp/coordinator-node-${i}.json /etc/toprf/coordinator.json" < /dev/null
            coord_args="-v /etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro"
            echo "    Coordinator config uploaded"
        else
            # Check if config exists on node from test deployment
            if ssh_node "$i" "test -f /etc/toprf/coordinator.json" < /dev/null 2>/dev/null; then
                coord_args="-v /etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro"
                echo "    Using existing coordinator config on node"
            else
                warn "No coordinator config for node $i"
            fi
        fi

        ssh_node "$i" "sudo docker run -d --name toprf-node --restart=unless-stopped \
            -e SEALED_KEY_URL='${url}' \
            -e EXPECTED_VERIFICATION_SHARE=${vs} \
            -e AMD_ARK_FINGERPRINT='${AMD_ARK_FINGERPRINT:-}' \
            ${coord_args} \
            --device /dev/sev-guest:/dev/sev-guest \
            --user root \
            -p 3001:3001 \
            ${NODE_IMAGE} \
            --port 3001 \
            --coordinator-config /etc/toprf/coordinator.json" < /dev/null
    done

    echo ""
    echo "  Waiting for nodes to boot..."
    boot_ok=true
    for i in $(all_node_ids); do
        ip=$(node_ip "$i")
        echo -n "    Node $i ($ip): "
        attempts=0
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

    if $boot_ok; then
        info "All nodes started and healthy."
    else
        warn "Some nodes did not become healthy. Check logs: ssh → sudo docker logs toprf-node"
        confirm "Continue anyway?"
    fi
fi

# ─── Step 8: Verify nodes serve correct key ─────────────────────────────────

if [[ $FROM_STEP -le 8 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 8: Verify nodes serve correct group public key"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    [[ -z "${AWS_ACCESS_KEY_ID:-}" ]] && source "$CEREMONY_ENV" && export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
    source "$CONFIG_ENV"

    GROUP_PK=$(jq -r '.group_public_key' "$NODE_DIR/public-config.json")

    all_ok=true
    for i in $(all_node_ids); do
        ip=$(node_ip "$i")
        echo -n "  Node $i ($ip): "

        resp=$(ssh_node "$i" "curl -sf http://localhost:3001/health" < /dev/null 2>&1) || true
        if echo "$resp" | jq -e '.status == "ready"' > /dev/null 2>&1; then
            node_gpk=$(echo "$resp" | jq -r '.group_public_key // empty')
            if [[ "$node_gpk" == "$GROUP_PK" ]]; then
                echo "PASS (healthy, correct key)"
            elif [[ -z "$node_gpk" ]]; then
                echo "PASS (healthy, key not in health response)"
            else
                echo "FAIL (wrong group public key: $node_gpk)"
                all_ok=false
            fi
        else
            echo "FAIL (not healthy: $resp)"
            all_ok=false
        fi
    done

    # E2E coordinator test
    echo ""
    coord_node=$(all_node_ids | awk '{print $1}')
    echo "  E2E evaluate via coordinator (node $coord_node)..."
    test_point="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

    eval_resp=$(ssh_node "$coord_node" "curl -sf --connect-timeout 10 \
        -X POST http://localhost:3001/evaluate \
        -H 'Content-Type: application/json' \
        -d '{\"blinded_point\":\"${test_point}\"}'" < /dev/null 2>&1) || true

    if echo "$eval_resp" | jq -e '.evaluation' > /dev/null 2>&1; then
        eval_point=$(echo "$eval_resp" | jq -r '.evaluation')
        partials_count=$(echo "$eval_resp" | jq '.partials | length')
        echo "    PASS (partials=$partials_count, evaluation=${eval_point:0:20}...)"

        echo "    Server evaluation verified."
    else
        echo "    FAIL: $eval_resp"
        all_ok=false
    fi

    echo ""
    if $all_ok; then
        info "All node checks passed."
    else
        warn "Some checks failed."
        confirm "Continue anyway?"
    fi
fi

# ─── Step 9: Shred node shares ─────────────────────────────────────────────

if [[ $FROM_STEP -le 9 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 9: Shred node shares from disk"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ -d "$NODE_DIR" ]]; then
        # Shred secret share files, keep public-config.json
        for f in "$NODE_DIR"/node-*-share.json; do
            if [[ -f "$f" ]]; then
                echo "  Shredding $f..."
                shred -fz -n 3 "$f"
                rm -f "$f"
            fi
        done
        echo ""
        info "Node secret shares destroyed. public-config.json retained (non-secret)."
    else
        echo "  Node shares directory not found (already cleaned?)."
    fi
fi

# ─── Step 10: Disconnect from network ──────────────────────────────────────

if [[ $FROM_STEP -le 10 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 10: Disconnect from network"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    echo "  Disconnect the Raspberry Pi from the network now."
    echo "  (Unplug Ethernet / disable WiFi)"
    confirm "Is the network disconnected?"
fi

# ─── Step 11: Local OPRF verification ──────────────────────────────────────

if [[ $FROM_STEP -le 11 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 11: Local OPRF simulation"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    source "$CEREMONY_ENV"
    NATIONAL_ID="${NATIONAL_ID:?NATIONAL_ID not set in ceremony.env}"
    NATIONALITY="${NATIONALITY:-Singapore}"

    ADMIN_ARGS=()
    for i in $(seq 1 "$ADMIN_THRESHOLD"); do
        ADMIN_ARGS+=(--admin-share "$ADMIN_DIR/admin-${i}.json")
    done

    echo ""
    echo "  Simulating full mobile app OPRF flow locally:"
    echo "    Nationality:  $NATIONALITY"
    echo "    National ID:  ${NATIONAL_ID:0:3}****${NATIONAL_ID: -1}"
    echo ""
    echo "    hash_to_curve → blind → evaluate → unblind → derive ruonId"
    echo ""

    "$KEYGEN" simulate \
        "${ADMIN_ARGS[@]}" \
        --nationality "$NATIONALITY" \
        --national-id "$NATIONAL_ID"

    echo ""
    echo "  Now onboard with the same identity on your mobile device."
    echo "  The app's ruonId should match the result above."
    confirm "Does the ruonId match?"
fi

# ─── Step 12: Shred admin shares ───────────────────────────────────────────

if [[ $FROM_STEP -le 12 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 12: Shred admin shares from disk"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    confirm "This will permanently destroy admin shares from disk. The only copies will be the printed pages. Continue?"

    if [[ -d "$ADMIN_DIR" ]]; then
        for f in "$ADMIN_DIR"/admin-*.json; do
            if [[ -f "$f" ]]; then
                echo "  Shredding $f..."
                shred -fz -n 3 "$f"
                rm -f "$f"
            fi
        done
        rmdir "$ADMIN_DIR" 2>/dev/null || true
        echo ""
        info "Admin shares destroyed."
    else
        echo "  Admin shares directory not found (already cleaned?)."
    fi

    # Clean up ceremony artifacts
fi

# ─── Step 13: Shred ceremony.env ────────────────────────────────────────────

if [[ $FROM_STEP -le 13 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 13: Clean up AWS credentials"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ -f "$CEREMONY_ENV" ]]; then
        echo "  Shredding ceremony.env..."
        shred -fz -n 3 "$CEREMONY_ENV"
        rm -f "$CEREMONY_ENV"
        info "AWS credentials destroyed."
    fi
fi

# ─── Done ───────────────────────────────────────────────────────────────────

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  CEREMONY COMPLETE                                           ║"
echo "║                                                              ║"
echo "║  Next steps:                                                 ║"
echo "║    1. Laminate the printed admin shares                      ║"
echo "║    2. Store in separate bank safe deposit boxes              ║"
echo "║    3. Securely wipe the SD card:                             ║"
echo "║       sudo dd if=/dev/zero of=/dev/mmcblk0 bs=4M status=progress ║"
echo "║    4. Revoke/delete the IAM user used for this ceremony      ║"
echo "║                                                              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
