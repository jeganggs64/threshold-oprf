#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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
WORDLIST="$SCRIPT_DIR/wordlist.txt"

info()    { echo "==> $*"; }
die()     { echo "  ERROR: $*" >&2; exit 1; }

wait_for_network() {
    echo "  Plug in Ethernet cable now..."
    while ! ping -c 1 -W 3 8.8.8.8 > /dev/null 2>&1; do sleep 2; done
    echo "  Network detected."
}

wait_for_disconnect() {
    echo "  Unplug Ethernet cable now..."
    while ping -c 1 -W 3 8.8.8.8 > /dev/null 2>&1; do sleep 2; done
    echo "  Network disconnected."
}

countdown() {
    local seconds=$1 msg="${2:-}"
    while [ $seconds -gt 0 ]; do
        printf "\r  %s (%d seconds remaining)  " "$msg" "$seconds"
        sleep 1
        seconds=$((seconds - 1))
    done
    printf "\r  %s — done.                          \n" "$msg"
}

_node_field() { jq -r --argjson id "$1" '.nodes[] | select(.id == $id) | .'"$2"' // empty' "$NODES_JSON"; }
node_ip()         { _node_field "$1" ip; }
node_s3_bucket()  { _node_field "$1" s3_bucket; }
node_key_name()   { _node_field "$1" key_name; }
all_node_ids()    { jq -r '.nodes[].id' "$NODES_JSON" | tr '\n' ' '; }
node_ssh_key()    { echo "$SCRIPT_DIR/ssh-keys/$(node_key_name "$1").pem"; }
ssh_node()        { local n="$1"; shift; ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -i "$(node_ssh_key "$n")" "ec2-user@$(node_ip "$n")" "$*"; }
scp_to_node()     { local n="$1"; shift; scp -o StrictHostKeyChecking=accept-new -i "$(node_ssh_key "$n")" "$@" "ec2-user@$(node_ip "$n"):/tmp/"; }
sealed_url()      { echo "s3://$(node_s3_bucket "$1")/node-${1}-sealed.bin"; }
node_vs()         { jq -r --argjson id "$1" '.verification_shares[] | select(.node_id == $id) | .verification_share' "$NODE_DIR/public-config.json"; }

preflight() {
    local ok=true
    [[ -x "$KEYGEN" ]]       || { echo "  MISSING: toprf-keygen"; ok=false; }
    [[ -x "$INIT_ENCRYPT" ]] || { echo "  MISSING: toprf-init-encrypt"; ok=false; }
    [[ -f "$CEREMONY_ENV" ]] || { echo "  MISSING: ceremony.env"; ok=false; }
    [[ -f "$CONFIG_ENV" ]]   || { echo "  MISSING: config.env"; ok=false; }
    [[ -f "$NODES_JSON" ]]   || { echo "  MISSING: nodes.json"; ok=false; }
    [[ -f "$WORDLIST" ]]     || { echo "  MISSING: wordlist.txt"; ok=false; }
    command -v jq >/dev/null    || { echo "  MISSING: jq"; ok=false; }
    command -v aws >/dev/null   || { echo "  MISSING: aws cli"; ok=false; }
    command -v age >/dev/null   || { echo "  MISSING: age"; ok=false; }
    command -v shred >/dev/null || { echo "  MISSING: shred"; ok=false; }
    command -v ssh >/dev/null   || { echo "  MISSING: ssh"; ok=false; }
    local node_count=$(jq '.nodes | length' "$NODES_JSON")
    for idx in $(seq 0 $((node_count - 1))); do
        local key_name=$(jq -r ".nodes[$idx].key_name" "$NODES_JSON")
        [[ -f "$SCRIPT_DIR/ssh-keys/${key_name}.pem" ]] || { echo "  MISSING: ssh-keys/${key_name}.pem"; ok=false; }
    done
    $ok || die "Pre-flight checks failed."
    echo "  All checks passed."
}

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║             TOPRF KEY CEREMONY (HEADLESS)                    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
info "Pre-flight checks"
preflight

# ── Step 1: Generate master key + admin shares (OFFLINE) ──
echo ""; echo "━━━ STEP 1/10: Generate master key and admin shares ━━━"
"$KEYGEN" init --admin-threshold "$ADMIN_THRESHOLD" --admin-shares "$ADMIN_SHARES" --output-dir "$ADMIN_DIR"
info "Admin shares generated."

# ── Step 2: Generate node shares (OFFLINE) ──
echo ""; echo "━━━ STEP 2/10: Generate node shares ━━━"
ADMIN_ARGS=()
for i in $(seq 1 "$ADMIN_THRESHOLD"); do ADMIN_ARGS+=(--admin-share "$ADMIN_DIR/admin-${i}.json"); done
"$KEYGEN" node-shares "${ADMIN_ARGS[@]}" --node-threshold "$NODE_THRESHOLD" --node-shares "$NODE_SHARES" --output-dir "$NODE_DIR"
info "Node shares generated."

# ── Step 3: Cross-verify (OFFLINE) ──
echo ""; echo "━━━ STEP 3/10: Cross-verify shares ━━━"
NODE_ARGS=()
for i in $(seq 1 "$NODE_THRESHOLD"); do NODE_ARGS+=(--node-share "$NODE_DIR/node-${i}-share.json"); done
"$KEYGEN" verify "${ADMIN_ARGS[@]}" "${NODE_ARGS[@]}"
GROUP_PK=$(jq -r '.group_public_key' "$NODE_DIR/public-config.json")
info "Verified. Group public key: $GROUP_PK"

# ── Step 4: Wait for network (MANUAL) ──
echo ""; echo "━━━ STEP 4/10: Connect to network ━━━"
wait_for_network
source "$CEREMONY_ENV"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
aws sts get-caller-identity
info "AWS configured."

# ── Step 5: Deploy to nodes (ONLINE) ──
echo ""; echo "━━━ STEP 5/10: Deploy key shares to nodes ━━━"
source "$CONFIG_ENV"

for i in $(all_node_ids); do
    ssh_node "$i" "sudo docker rm -f toprf-node 2>/dev/null || true" < /dev/null || true
done
for i in $(all_node_ids); do
    aws s3 rm "s3://$(node_s3_bucket "$i")/init/" --recursive --quiet 2>/dev/null || true
done

expected_measurement="${EXPECTED_MEASUREMENT:-}"
[[ -z "$expected_measurement" ]] && die "EXPECTED_MEASUREMENT not set in config.env"

for i in $(all_node_ids); do
    ip=$(node_ip "$i"); vs=$(node_vs "$i"); url=$(sealed_url "$i")
    share="${NODE_DIR}/node-${i}-share.json"; bucket=$(node_s3_bucket "$i")
    [[ -f "$share" ]] || die "Key share not found: $share"
    echo "  Node $i ($ip)..."
    ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true" < /dev/null
    ssh_node "$i" "sudo docker run -d --name toprf-init-seal -e EXPECTED_VERIFICATION_SHARE='${vs}' --device /dev/sev-guest:/dev/sev-guest --user root ${NODE_IMAGE} --init-seal --s3-bucket '${bucket}' --upload-url '${url}'" < /dev/null
    tmpdir=$(mktemp -d); waited=0
    while ! aws s3 cp "s3://${bucket}/init/attestation.bin" "$tmpdir/attestation.bin" --quiet 2>/dev/null; do
        running=$(ssh_node "$i" "sudo docker inspect -f '{{.State.Running}}' toprf-init-seal 2>/dev/null || echo false" < /dev/null)
        [[ "$running" != "true" ]] && { rm -rf "$tmpdir"; die "Init-seal failed for node $i"; }
        sleep 3; waited=$((waited + 1))
        [[ $waited -ge 40 ]] && { rm -rf "$tmpdir"; die "Timed out for node $i"; }
    done
    aws s3 cp "s3://${bucket}/init/pubkey.bin" "$tmpdir/pubkey.bin" --quiet
    aws s3 cp "s3://${bucket}/init/certs.bin" "$tmpdir/certs.bin" --quiet
    AMD_ARK_FINGERPRINT="${AMD_ARK_FINGERPRINT:-}" "$INIT_ENCRYPT" --attestation "$tmpdir/attestation.bin" --pubkey "$tmpdir/pubkey.bin" --certs "$tmpdir/certs.bin" --output "$tmpdir/encrypted-share.bin" --share-file "$share" --expected-measurement "$expected_measurement" 2>&1 | sed 's/^/    /'
    aws s3 cp "$tmpdir/encrypted-share.bin" "s3://${bucket}/init/encrypted-share.bin" --quiet
    seal_waited=0
    while true; do
        running=$(ssh_node "$i" "sudo docker inspect -f '{{.State.Running}}' toprf-init-seal 2>/dev/null || echo false" < /dev/null)
        [[ "$running" != "true" ]] && break; sleep 3; seal_waited=$((seal_waited + 1))
        [[ $seal_waited -ge 60 ]] && break
    done
    ssh_node "$i" "sudo docker rm -f toprf-init-seal 2>/dev/null || true" < /dev/null
    rm -rf "$tmpdir"
    echo "    Sealed."
done
info "Init-seal complete."

# Start nodes
for i in $(all_node_ids); do
    vs=$(node_vs "$i"); url=$(sealed_url "$i"); coord_args=""
    coord_config="$SCRIPT_DIR/coordinator-configs/coordinator-node-${i}.json"
    if [[ -f "$coord_config" ]]; then
        scp_to_node "$i" "$coord_config" < /dev/null
        ssh_node "$i" "sudo mkdir -p /etc/toprf && sudo mv /tmp/coordinator-node-${i}.json /etc/toprf/coordinator.json" < /dev/null
        coord_args="-v /etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro"
    elif ssh_node "$i" "test -f /etc/toprf/coordinator.json" < /dev/null 2>/dev/null; then
        coord_args="-v /etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro"
    fi
    ssh_node "$i" "sudo docker run -d --name toprf-node --restart=unless-stopped -e SEALED_KEY_URL='${url}' -e EXPECTED_VERIFICATION_SHARE='${vs}' -e AMD_ARK_FINGERPRINT='${AMD_ARK_FINGERPRINT:-}' ${coord_args} --device /dev/sev-guest:/dev/sev-guest --user root -p 3001:3001 ${NODE_IMAGE} --port 3001 --coordinator-config /etc/toprf/coordinator.json" < /dev/null
done

echo "  Waiting for nodes..."
for i in $(all_node_ids); do
    printf "    Node %s: " "$i"; attempts=0
    while true; do
        ssh_node "$i" "curl -sf http://localhost:3001/health" < /dev/null > /dev/null 2>&1 && { echo "healthy"; break; }
        attempts=$((attempts + 1)); [[ $attempts -ge 30 ]] && { echo "NOT healthy"; break; }; sleep 2
    done
done

# ── Step 6: Verify nodes (ONLINE) ──
echo ""; echo "━━━ STEP 6/10: Verify nodes ━━━"
for i in $(all_node_ids); do
    printf "  Node %s: " "$i"
    resp=$(ssh_node "$i" "curl -sf http://localhost:3001/health" < /dev/null 2>&1) || true
    node_gpk=$(echo "$resp" | jq -r '.group_public_key // empty' 2>/dev/null)
    [[ "$node_gpk" == "$GROUP_PK" ]] && echo "PASS" || echo "FAIL"
done
coord_node=$(all_node_ids | awk '{print $1}')
eval_resp=$(ssh_node "$coord_node" "curl -sf -X POST http://localhost:3001/evaluate -H 'Content-Type: application/json' -d '{\"blinded_point\":\"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"}'" < /dev/null 2>&1) || true
echo "$eval_resp" | jq -e '.evaluation' > /dev/null 2>&1 && echo "  E2E: PASS" || echo "  E2E: FAIL"

# ── Step 7: Shred node shares ──
echo ""; echo "━━━ STEP 7/10: Shred node shares ━━━"
for f in "$NODE_DIR"/node-*-share.json; do [[ -f "$f" ]] && { shred -fz -n 3 "$f"; rm -f "$f"; }; done
info "Node shares destroyed."

# ── Step 8: Reconstruct + re-split ──
echo ""; echo "━━━ STEP 8/10: Reconstruct master key + re-split ━━━"
MASTER_KEY_FILE="$SCRIPT_DIR/master-key.hex"
ADMIN_ARGS=()
for i in $(seq 1 "$ADMIN_THRESHOLD"); do ADMIN_ARGS+=(--admin-share "$ADMIN_DIR/admin-${i}.json"); done
"$KEYGEN" reconstruct "${ADMIN_ARGS[@]}" --output "$MASTER_KEY_FILE"
info "Master key reconstructed."
for f in "$ADMIN_DIR"/admin-*.json; do [[ -f "$f" ]] && { shred -fz -n 3 "$f"; rm -f "$f"; }; done
rmdir "$ADMIN_DIR" 2>/dev/null || true
VERIFY_DIR="$SCRIPT_DIR/verify-shares"
"$KEYGEN" init --admin-threshold "$ADMIN_THRESHOLD" --admin-shares "$ADMIN_SHARES" --existing-key-file "$MASTER_KEY_FILE" --output-dir "$VERIFY_DIR"
info "Fresh shares generated."

# ── Step 9: Disconnect + verify (OFFLINE) ──
echo ""; echo "━━━ STEP 9/10: Disconnect + OPRF verification ━━━"
wait_for_disconnect
source "$CEREMONY_ENV"
NATIONAL_ID="${NATIONAL_ID:?NATIONAL_ID not set}"
NATIONALITY="${NATIONALITY:-Singapore}"
VERIFY_ARGS=()
for i in $(seq 1 "$ADMIN_THRESHOLD"); do VERIFY_ARGS+=(--admin-share "$VERIFY_DIR/admin-${i}.json"); done
echo "  Nationality: $NATIONALITY"
echo "  National ID: ${NATIONAL_ID:0:3}****${NATIONAL_ID: -1}"
echo ""
"$KEYGEN" simulate "${VERIFY_ARGS[@]}" --nationality "$NATIONALITY" --national-id "$NATIONAL_ID"
echo ""
echo "  ┌─────────────────────────────────────────────────────────────┐"
echo "  │  Compare the ruonId above with your mobile app.            │"
echo "  │  Onboard with the same identity on your phone now.         │"
echo "  └─────────────────────────────────────────────────────────────┘"
countdown 240 "Waiting for mobile verification"
for f in "$VERIFY_DIR"/admin-*.json; do [[ -f "$f" ]] && { shred -fz -n 3 "$f"; rm -f "$f"; }; done
rm -rf "$VERIFY_DIR"

# ── Step 10: Encrypt + shred ──
echo ""; echo "━━━ STEP 10/10: Encrypt master key ━━━"
TOTAL_WORDS=$(wc -l < "$WORDLIST")
PASSPHRASE=""
for _ in $(seq 1 6); do
    IDX=$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')
    IDX=$((IDX % TOTAL_WORDS + 1))
    WORD=$(sed -n "${IDX}p" "$WORDLIST")
    PASSPHRASE="${PASSPHRASE:+$PASSPHRASE }$WORD"
done

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  YOUR PASSPHRASE — WRITE THIS DOWN NOW                      ║"
echo "║                                                              ║"
printf "║  %-60s║\n" "$PASSPHRASE"
echo "║                                                              ║"
echo "║  This is your ONLY way to decrypt the master key.            ║"
echo "║  There is NO recovery if you lose this.                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
countdown 120 "Write down the passphrase above"

echo "$PASSPHRASE" | age -p -o "$KEY_AGE_OUTPUT" "$MASTER_KEY_FILE"
[[ -f "$KEY_AGE_OUTPUT" ]] || die "age encryption failed"
info "Encrypted key saved: $KEY_AGE_OUTPUT ($(wc -c < "$KEY_AGE_OUTPUT") bytes)"

shred -fz -n 3 "$MASTER_KEY_FILE"; rm -f "$MASTER_KEY_FILE"
shred -fz -n 3 "$CEREMONY_ENV"; rm -f "$CEREMONY_ENV"
PASSPHRASE="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"; unset PASSPHRASE
info "All plaintext destroyed."

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  CEREMONY COMPLETE                                           ║"
echo "║                                                              ║"
echo "║  key.age is on the SD card.                                  ║"
echo "║                                                              ║"
echo "║  1. Power off the Pi                                         ║"
echo "║  2. Plug SD card into your Mac                               ║"
echo "║  3. Copy key.age to iCloud / secure backup                   ║"
echo "║  4. Wipe the SD card                                         ║"
echo "║  5. Revoke the IAM user used for this ceremony               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
