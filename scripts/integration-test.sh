#!/usr/bin/env bash
#
# Integration test for threshold-OPRF system.
#
# Builds the workspace, generates keys, starts 3 nodes + 1 proxy,
# and runs end-to-end HTTP tests.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"

# Binary paths (built in step 1)
KEYGEN="$REPO_ROOT/target/release/toprf-keygen"
NODE="$REPO_ROOT/target/release/toprf-node"
PROXY="$REPO_ROOT/target/release/toprf-proxy"

NODE1_PORT=7101
NODE2_PORT=7102
NODE3_PORT=7103
PROXY_PORT=7100

PIDS=()
PASS=0
FAIL=0

# ---------- cleanup ----------

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPDIR"
    echo "Temp dir removed: $TMPDIR"
}
trap cleanup EXIT

# ---------- helpers ----------

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (expected '$expected', got '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

assert_match() {
    local desc="$1" pattern="$2" actual="$3"
    if [[ "$actual" =~ $pattern ]]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (pattern '$pattern' did not match '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

wait_for_health() {
    local url="$1" label="$2" max_wait="${3:-30}"
    local waited=0
    echo "  Waiting for $label at $url ..."
    while ! curl -sf "$url" > /dev/null 2>&1; do
        sleep 0.5
        waited=$((waited + 1))
        if [[ $waited -ge $((max_wait * 2)) ]]; then
            echo "  FATAL: $label did not become healthy within ${max_wait}s"
            exit 1
        fi
    done
    echo "  $label is ready."
}

# ---------- 1. Build workspace ----------

echo "=== Step 1: Building workspace (release) ==="
cd "$REPO_ROOT"
cargo build --release 2>&1 | tail -5
echo "  Build complete."

# Verify binaries exist
for bin in "$KEYGEN" "$NODE" "$PROXY"; do
    if [[ ! -x "$bin" ]]; then
        echo "  FATAL: binary not found: $bin"
        exit 1
    fi
done

# ---------- 2. Generate keys ----------

echo ""
echo "=== Step 2: Generating keys (2-of-3 threshold) ==="

CEREMONY_DIR="$TMPDIR/ceremony"
"$KEYGEN" init \
    --admin-threshold 3 --admin-shares 5 \
    --node-threshold 2 --node-shares 3 \
    --output-dir "$CEREMONY_DIR" 2>&1

echo "  Key generation complete."

# Parse the public config
PUBLIC_CONFIG="$CEREMONY_DIR/public-config.json"
if [[ ! -f "$PUBLIC_CONFIG" ]]; then
    echo "  FATAL: public-config.json not found at $PUBLIC_CONFIG"
    exit 1
fi

GROUP_PUBLIC_KEY=$(jq -r '.group_public_key' "$PUBLIC_CONFIG")
THRESHOLD=$(jq -r '.threshold' "$PUBLIC_CONFIG")
TOTAL_SHARES=$(jq -r '.total_shares' "$PUBLIC_CONFIG")

echo "  Group public key: $GROUP_PUBLIC_KEY"
echo "  Threshold: $THRESHOLD, Total shares: $TOTAL_SHARES"

# Extract verification shares per node
VS_1=$(jq -r '.verification_shares[] | select(.node_id == 1) | .verification_share' "$PUBLIC_CONFIG")
VS_2=$(jq -r '.verification_shares[] | select(.node_id == 2) | .verification_share' "$PUBLIC_CONFIG")
VS_3=$(jq -r '.verification_shares[] | select(.node_id == 3) | .verification_share' "$PUBLIC_CONFIG")

echo "  Verification shares extracted for nodes 1, 2, 3."

# ---------- 3. Start 3 node servers (with key files) ----------

echo ""
echo "=== Step 3: Starting 3 node servers ==="

for i in 1 2 3; do
    SHARE_FILE="$CEREMONY_DIR/node-shares/node-${i}-share.json"
    if [[ ! -f "$SHARE_FILE" ]]; then
        echo "  FATAL: share file not found: $SHARE_FILE"
        exit 1
    fi
done

"$NODE" --port $NODE1_PORT --key-file "$CEREMONY_DIR/node-shares/node-1-share.json" > "$TMPDIR/node1.log" 2>&1 &
PIDS+=($!)
echo "  Node 1 started (PID $!, port $NODE1_PORT)"

"$NODE" --port $NODE2_PORT --key-file "$CEREMONY_DIR/node-shares/node-2-share.json" > "$TMPDIR/node2.log" 2>&1 &
PIDS+=($!)
echo "  Node 2 started (PID $!, port $NODE2_PORT)"

"$NODE" --port $NODE3_PORT --key-file "$CEREMONY_DIR/node-shares/node-3-share.json" > "$TMPDIR/node3.log" 2>&1 &
PIDS+=($!)
echo "  Node 3 started (PID $!, port $NODE3_PORT)"

# Wait for all nodes to be healthy and ready
wait_for_health "http://127.0.0.1:$NODE1_PORT/health" "Node 1"
wait_for_health "http://127.0.0.1:$NODE2_PORT/health" "Node 2"
wait_for_health "http://127.0.0.1:$NODE3_PORT/health" "Node 3"

# ---------- 4. Create proxy config ----------

echo ""
echo "=== Step 4: Creating proxy config ==="

PROXY_CONFIG="$TMPDIR/proxy-config.json"
cat > "$PROXY_CONFIG" <<CONFIGEOF
{
  "group_public_key": "$GROUP_PUBLIC_KEY",
  "threshold": $THRESHOLD,
  "require_attestation": false,
  "rate_limit": {
    "per_hour": 100,
    "per_day": 1000
  },
  "nodes": [
    {
      "node_id": 1,
      "endpoint": "http://127.0.0.1:$NODE1_PORT",
      "verification_share": "$VS_1"
    },
    {
      "node_id": 2,
      "endpoint": "http://127.0.0.1:$NODE2_PORT",
      "verification_share": "$VS_2"
    },
    {
      "node_id": 3,
      "endpoint": "http://127.0.0.1:$NODE3_PORT",
      "verification_share": "$VS_3"
    }
  ]
}
CONFIGEOF

echo "  Proxy config written to $PROXY_CONFIG"
echo "  Config contents:"
jq . "$PROXY_CONFIG"

# ---------- 5. Start the proxy ----------

echo ""
echo "=== Step 5: Starting proxy ==="

"$PROXY" --config "$PROXY_CONFIG" --port $PROXY_PORT > "$TMPDIR/proxy.log" 2>&1 &
PIDS+=($!)
echo "  Proxy started (PID $!, port $PROXY_PORT)"

wait_for_health "http://127.0.0.1:$PROXY_PORT/health" "Proxy"

# ---------- 6. Run test requests ----------

echo ""
echo "=== Step 6: Running tests ==="

# 6a. GET /health on proxy
echo ""
echo "--- Test 6a: GET /health ---"
HEALTH_RESP=$(curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PROXY_PORT/health")
assert_eq "proxy /health returns 200" "200" "$HEALTH_RESP"

HEALTH_BODY=$(curl -sf "http://127.0.0.1:$PROXY_PORT/health")
HEALTH_STATUS=$(echo "$HEALTH_BODY" | jq -r '.status')
assert_eq "proxy health status is 'ok'" "ok" "$HEALTH_STATUS"

HEALTH_THRESHOLD=$(echo "$HEALTH_BODY" | jq -r '.threshold')
assert_eq "proxy health threshold is 2" "2" "$HEALTH_THRESHOLD"

HEALTH_NODES=$(echo "$HEALTH_BODY" | jq -r '.total_nodes')
assert_eq "proxy health total_nodes is 3" "3" "$HEALTH_NODES"

# 6b. GET /oprf/public-key
echo ""
echo "--- Test 6b: GET /oprf/public-key ---"
PK_RESP=$(curl -sf "http://127.0.0.1:$PROXY_PORT/oprf/public-key")
PK_VALUE=$(echo "$PK_RESP" | jq -r '.group_public_key')
assert_eq "public-key matches group key" "$GROUP_PUBLIC_KEY" "$PK_VALUE"

# Verify the public key looks like a valid compressed secp256k1 point
assert_match "public key is 66 hex chars" '^(02|03)[0-9a-f]{64}$' "$PK_VALUE"

# 6c. GET /oprf/challenge
echo ""
echo "--- Test 6c: GET /oprf/challenge ---"
CHALLENGE_RESP=$(curl -sf "http://127.0.0.1:$PROXY_PORT/oprf/challenge")
NONCE=$(echo "$CHALLENGE_RESP" | jq -r '.nonce')
assert_match "challenge nonce is non-empty hex" '^[0-9a-f]+$' "$NONCE"

# 6d. POST /oprf/evaluate with a blinded point
echo ""
echo "--- Test 6d: POST /oprf/evaluate ---"

# Use the secp256k1 generator point as a valid test blinded point.
# The generator in compressed SEC1 form:
# 02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
TEST_BLINDED_POINT="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

EVAL_HTTP_CODE=$(curl -s -o "$TMPDIR/eval_resp.json" -w "%{http_code}" \
    -X POST "http://127.0.0.1:$PROXY_PORT/oprf/evaluate" \
    -H "Content-Type: application/json" \
    -d "{\"blinded_point\": \"$TEST_BLINDED_POINT\"}")

if [[ "$EVAL_HTTP_CODE" != "200" ]]; then
    echo "  DEBUG: evaluate returned HTTP $EVAL_HTTP_CODE"
    echo "  DEBUG: response body: $(cat "$TMPDIR/eval_resp.json" 2>/dev/null)"
    echo "  DEBUG: proxy log (last 20 lines):"
    tail -20 "$TMPDIR/proxy.log" 2>/dev/null || echo "(no log)"
fi
assert_eq "evaluate returns 200" "200" "$EVAL_HTTP_CODE"

if [[ -f "$TMPDIR/eval_resp.json" ]]; then
    EVAL_RESP=$(cat "$TMPDIR/eval_resp.json")
    EVAL_THRESHOLD=$(echo "$EVAL_RESP" | jq -r '.threshold')
    assert_eq "evaluate response threshold is 2" "2" "$EVAL_THRESHOLD"

    PARTIALS_COUNT=$(echo "$EVAL_RESP" | jq '.partials | length')
    assert_match "partials array has >= 2 entries" '^[2-9][0-9]*$|^[2-3]$' "$PARTIALS_COUNT"

    # 6e. Verify each partial_point is a valid compressed secp256k1 point
    echo ""
    echo "--- Test 6e: Verify partial points ---"
    for idx in $(seq 0 $((PARTIALS_COUNT - 1))); do
        NODE_ID=$(echo "$EVAL_RESP" | jq -r ".partials[$idx].node_id")
        PARTIAL_POINT=$(echo "$EVAL_RESP" | jq -r ".partials[$idx].partial_point")
        assert_match "partial_point from node $NODE_ID is valid compressed point (66 hex, starts with 02 or 03)" \
            '^(02|03)[0-9a-f]{64}$' "$PARTIAL_POINT"
    done
else
    echo "  FAIL: evaluate response file not found"
    FAIL=$((FAIL + 1))
fi

# ---------- 7. Summary ----------

echo ""
echo "========================================"
echo "  Integration Test Results"
echo "========================================"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "========================================"

if [[ $FAIL -gt 0 ]]; then
    echo "  RESULT: FAIL"
    echo ""
    echo "--- Node logs ---"
    for i in 1 2 3; do
        echo "--- Node $i log (last 10 lines) ---"
        tail -10 "$TMPDIR/node${i}.log" 2>/dev/null || echo "(no log)"
    done
    echo "--- Proxy log (last 10 lines) ---"
    tail -10 "$TMPDIR/proxy.log" 2>/dev/null || echo "(no log)"
    exit 1
else
    echo "  RESULT: PASS"
    exit 0
fi
