#!/usr/bin/env bash
# =============================================================================
# ceremony.sh — TOPRF Key Ceremony for Raspberry Pi
#
# Generates a new OPRF master key, deploys node shares to TEE nodes,
# verifies with local + mobile evaluation, encrypts the master key
# with age, and shreds all plaintext artifacts.
#
# Prerequisites on the Raspberry Pi:
#   - toprf-keygen       (aarch64 binary, in same directory)
#   - toprf-init-encrypt (aarch64 binary, in same directory)
#   - ceremony.env       (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, etc.)
#   - config.env         (copied from deploy/)
#   - nodes.json         (copied from deploy/)
#   - ssh-keys/          (SSH .pem files, named by key_name from nodes.json)
#   - coordinator-configs/ (copied from deploy/coordinator-configs/)
#   - aws cli, jq, age, shred
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

KEY_AGE_OUTPUT="$SCRIPT_DIR/key.age"

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
    command -v age >/dev/null || { echo "  MISSING: age (apt install age)"; ok=false; }
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
            echo "  --from <N>  Resume from step N (1-10)"
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

# ─── Step 4: Connect to network and configure AWS ─────────────────────────

if [[ $FROM_STEP -le 4 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 4: Connect to network"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    echo "  Connect the Raspberry Pi to the network now."
    confirm "Is the network connected?"

    if ! ping -c 1 -W 5 8.8.8.8 > /dev/null 2>&1; then
        die "No network connectivity. Check connection and re-run with --from 4"
    fi
    echo "  Network connectivity verified."

    source "$CEREMONY_ENV"
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION

    echo "  Verifying AWS access..."
    aws sts get-caller-identity
    echo ""
    info "AWS credentials configured."
fi

# ─── Step 5: Init-seal + start nodes ───────────────────────────────────────

if [[ $FROM_STEP -le 5 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 5: Deploy key shares to nodes (init-seal + start)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    [[ -z "${AWS_ACCESS_KEY_ID:-}" ]] && source "$CEREMONY_ENV" && export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
    source "$CONFIG_ENV"

    GROUP_PK=$(jq -r '.group_public_key' "$NODE_DIR/public-config.json")

    # Stop running nodes
    echo ""
    info "Stopping running nodes..."
    for i in $(all_node_ids); do
        local_ip=$(node_ip "$i")
        echo "  Node $i ($local_ip): stopping..."
        ssh_node "$i" "sudo docker rm -f toprf-node 2>/dev/null || true" < /dev/null || true
    done

    # Clean S3 init/ prefix
    echo ""
    info "Cleaning S3 init/ artifacts..."
    for i in $(all_node_ids); do
        bucket=$(node_s3_bucket "$i")
        echo "  Node $i: cleaning s3://${bucket}/init/..."
        aws s3 rm "s3://${bucket}/init/" --recursive --quiet 2>/dev/null || true
    done

    # Init-seal for each node
    echo ""
    info "Init-seal (attested key injection)..."
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

        ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true" < /dev/null

        ssh_node "$i" "sudo docker run -d --name toprf-init-seal \
            -e EXPECTED_VERIFICATION_SHARE='${vs}' \
            --device /dev/sev-guest:/dev/sev-guest \
            --user root \
            ${NODE_IMAGE} \
            --init-seal \
            --s3-bucket '${bucket}' \
            --upload-url '${url}'" < /dev/null

        echo "    Waiting for attestation artifacts in S3..."

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

        echo "    Verifying attestation and encrypting key share..."
        AMD_ARK_FINGERPRINT="${AMD_ARK_FINGERPRINT:-}" \
            "$INIT_ENCRYPT" \
            --attestation "$tmpdir/attestation.bin" \
            --pubkey "$tmpdir/pubkey.bin" \
            --certs "$tmpdir/certs.bin" \
            --output "$tmpdir/encrypted-share.bin" \
            --share-file "$share" \
            --expected-measurement "$expected_measurement" 2>&1 | sed 's/^/    /'

        echo "    Uploading encrypted share to S3..."
        aws s3 cp "$tmpdir/encrypted-share.bin" "$s3_encrypted" --quiet

        echo "    Waiting for node to seal..."
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

    # Start nodes in auto-unseal mode
    echo ""
    info "Starting nodes in auto-unseal mode..."

    for i in $(all_node_ids); do
        ip=$(node_ip "$i")
        vs=$(node_vs "$i")
        url=$(sealed_url "$i")
        bucket=$(node_s3_bucket "$i")

        echo "  Node $i ($ip)..."

        coord_config="$SCRIPT_DIR/coordinator-configs/coordinator-node-${i}.json"
        coord_args=""
        if [[ -f "$coord_config" ]]; then
            scp_to_node "$i" "$coord_config" < /dev/null || die "Failed to upload coordinator config to node $i"
            ssh_node "$i" "sudo mkdir -p /etc/toprf && sudo mv /tmp/coordinator-node-${i}.json /etc/toprf/coordinator.json" < /dev/null
            coord_args="-v /etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro"
            echo "    Coordinator config uploaded"
        elif ssh_node "$i" "test -f /etc/toprf/coordinator.json" < /dev/null 2>/dev/null; then
            coord_args="-v /etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro"
            echo "    Using existing coordinator config on node"
        else
            warn "No coordinator config for node $i"
        fi

        ssh_node "$i" "sudo docker run -d --name toprf-node --restart=unless-stopped \
            -e SEALED_KEY_URL='${url}' \
            -e EXPECTED_VERIFICATION_SHARE='${vs}' \
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

# ─── Step 6: Verify nodes serve correct key ─────────────────────────────────

if [[ $FROM_STEP -le 6 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 6: Verify nodes serve correct group public key"
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

# ─── Step 7: Shred node shares ─────────────────────────────────────────────

if [[ $FROM_STEP -le 7 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 7: Shred node shares from disk"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ -d "$NODE_DIR" ]]; then
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

# ─── Step 8: Disconnect from network ──────────────────────────────────────

if [[ $FROM_STEP -le 8 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 8: Disconnect from network"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    echo "  Disconnect the Raspberry Pi from the network now."
    echo "  (Unplug Ethernet / disable WiFi)"
    confirm "Is the network disconnected?"
fi

# ─── Step 9: Local OPRF verification + mobile verification ────────────────

if [[ $FROM_STEP -le 9 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 9: Local OPRF simulation + mobile verification"
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

# ─── Step 10: Encrypt master key with age + shred all artifacts ────────────

if [[ $FROM_STEP -le 10 ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    info "STEP 10: Encrypt master key and clean up"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    echo ""
    echo "  You will now encrypt the admin shares with a passphrase."
    echo "  Use 6 random diceware words separated by spaces."
    echo "  REMEMBER THIS PASSPHRASE — there is no recovery."
    echo ""

    # Bundle all admin shares into a single JSON for encryption
    BUNDLE="$SCRIPT_DIR/admin-shares-bundle.json"
    echo "{" > "$BUNDLE"
    first=true
    for i in $(seq 1 "$ADMIN_SHARES"); do
        SHARE_FILE="$ADMIN_DIR/admin-${i}.json"
        if [[ -f "$SHARE_FILE" ]]; then
            if ! $first; then echo "," >> "$BUNDLE"; fi
            echo "\"admin-${i}\": $(cat "$SHARE_FILE")" >> "$BUNDLE"
            first=false
        fi
    done
    echo "}" >> "$BUNDLE"

    # Encrypt with age (passphrase-based)
    age -p -o "$KEY_AGE_OUTPUT" "$BUNDLE"

    if [[ -f "$KEY_AGE_OUTPUT" ]]; then
        echo ""
        info "Encrypted key saved to: $KEY_AGE_OUTPUT"
        echo "  File size: $(wc -c < "$KEY_AGE_OUTPUT") bytes"
    else
        die "age encryption failed — key.age not created"
    fi

    # Shred all plaintext artifacts
    echo ""
    info "Shredding plaintext artifacts..."

    # Admin shares
    if [[ -d "$ADMIN_DIR" ]]; then
        for f in "$ADMIN_DIR"/admin-*.json; do
            if [[ -f "$f" ]]; then
                echo "  Shredding $f..."
                shred -fz -n 3 "$f"
                rm -f "$f"
            fi
        done
        rmdir "$ADMIN_DIR" 2>/dev/null || true
    fi

    # Bundle file
    if [[ -f "$BUNDLE" ]]; then
        shred -fz -n 3 "$BUNDLE"
        rm -f "$BUNDLE"
    fi

    # ceremony.env (AWS creds + national ID)
    if [[ -f "$CEREMONY_ENV" ]]; then
        echo "  Shredding ceremony.env..."
        shred -fz -n 3 "$CEREMONY_ENV"
        rm -f "$CEREMONY_ENV"
    fi

    info "All plaintext artifacts destroyed."
fi

# ─── Done ───────────────────────────────────────────────────────────────────

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  CEREMONY COMPLETE                                           ║"
echo "║                                                              ║"
echo "║  key.age is on the SD card.                                  ║"
echo "║                                                              ║"
echo "║  Next steps:                                                 ║"
echo "║    1. Power off the Pi                                       ║"
echo "║    2. Plug SD card into your Mac                             ║"
echo "║    3. Copy key.age to iCloud / secure backup                 ║"
echo "║    4. Securely wipe the SD card:                             ║"
echo "║       sudo dd if=/dev/zero of=/dev/mmcblk0 bs=4M status=progress ║"
echo "║    5. Revoke/delete the IAM user used for this ceremony      ║"
echo "║                                                              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
