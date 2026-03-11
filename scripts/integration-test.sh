#!/usr/bin/env bash
#
# Integration test for threshold-OPRF nodes.
#
# Builds the workspace, generates keys, starts 3 nodes,
# and runs end-to-end HTTP tests (health checks + partial evaluations).
#
# The proxy is tested separately in the ruonid-proxy repo.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"

# Binary paths (built in step 1)
KEYGEN="$REPO_ROOT/target/release/toprf-keygen"
NODE="$REPO_ROOT/target/release/toprf-node"

NODE1_PORT=7101
NODE2_PORT=7102
NODE3_PORT=7103

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
for bin in "$KEYGEN" "$NODE"; do
    if [[ ! -x "$bin" ]]; then
        echo "  FATAL: binary not found: $bin"
        exit 1
    fi
done

# ---------- 2. Generate keys ----------

echo ""
echo "=== Step 2: Generating keys (2-of-3 threshold) ==="

ADMIN_DIR="$TMPDIR/admin-shares"
NODE_SHARES_DIR="$TMPDIR/node-shares"

"$KEYGEN" init \
    --admin-threshold 3 --admin-shares 5 \
    --output-dir "$ADMIN_DIR" 2>&1

"$KEYGEN" node-shares \
    --admin-share "$ADMIN_DIR/admin-1.json" \
    --admin-share "$ADMIN_DIR/admin-2.json" \
    --admin-share "$ADMIN_DIR/admin-3.json" \
    --node-threshold 2 --node-shares 3 \
    --output-dir "$NODE_SHARES_DIR" 2>&1

echo "  Key generation complete."

# Parse the public config
PUBLIC_CONFIG="$NODE_SHARES_DIR/public-config.json"
if [[ ! -f "$PUBLIC_CONFIG" ]]; then
    echo "  FATAL: public-config.json not found at $PUBLIC_CONFIG"
    exit 1
fi

GROUP_PUBLIC_KEY=$(jq -r '.group_public_key' "$PUBLIC_CONFIG")
THRESHOLD=$(jq -r '.threshold' "$PUBLIC_CONFIG")
TOTAL_SHARES=$(jq -r '.total_shares' "$PUBLIC_CONFIG")

echo "  Group public key: $GROUP_PUBLIC_KEY"
echo "  Threshold: $THRESHOLD, Total shares: $TOTAL_SHARES"

# ---------- 3. Start 3 node servers (with key files) ----------

echo ""
echo "=== Step 3: Starting 3 node servers ==="

for i in 1 2 3; do
    SHARE_FILE="$NODE_SHARES_DIR/node-${i}-share.json"
    if [[ ! -f "$SHARE_FILE" ]]; then
        echo "  FATAL: share file not found: $SHARE_FILE"
        exit 1
    fi
done

"$NODE" --port $NODE1_PORT --key-file "$NODE_SHARES_DIR/node-1-share.json" > "$TMPDIR/node1.log" 2>&1 &
PIDS+=($!)
echo "  Node 1 started (PID $!, port $NODE1_PORT)"

"$NODE" --port $NODE2_PORT --key-file "$NODE_SHARES_DIR/node-2-share.json" > "$TMPDIR/node2.log" 2>&1 &
PIDS+=($!)
echo "  Node 2 started (PID $!, port $NODE2_PORT)"

"$NODE" --port $NODE3_PORT --key-file "$NODE_SHARES_DIR/node-3-share.json" > "$TMPDIR/node3.log" 2>&1 &
PIDS+=($!)
echo "  Node 3 started (PID $!, port $NODE3_PORT)"

# Wait for all nodes to be healthy and ready
wait_for_health "http://127.0.0.1:$NODE1_PORT/health" "Node 1"
wait_for_health "http://127.0.0.1:$NODE2_PORT/health" "Node 2"
wait_for_health "http://127.0.0.1:$NODE3_PORT/health" "Node 3"

# ---------- 4. Run test requests ----------

echo ""
echo "=== Step 4: Running tests ==="

# 4a. GET /health on each node
echo ""
echo "--- Test 4a: Node health checks ---"
for i in 1 2 3; do
    eval PORT=\$NODE${i}_PORT
    HEALTH_RESP=$(curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/health")
    assert_eq "node $i /health returns 200" "200" "$HEALTH_RESP"

    HEALTH_BODY=$(curl -sf "http://127.0.0.1:$PORT/health")
    HEALTH_STATUS=$(echo "$HEALTH_BODY" | jq -r '.status')
    assert_eq "node $i status is 'ready'" "ready" "$HEALTH_STATUS"

    NODE_ID=$(echo "$HEALTH_BODY" | jq -r '.node_id')
    assert_eq "node $i reports node_id=$i" "$i" "$NODE_ID"
done

# 4b. POST /partial-evaluate on each node
echo ""
echo "--- Test 4b: Partial evaluations ---"

# Use the secp256k1 generator point as a valid test blinded point.
TEST_BLINDED_POINT="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

for i in 1 2 3; do
    eval PORT=\$NODE${i}_PORT
    EVAL_HTTP_CODE=$(curl -s -o "$TMPDIR/eval_node${i}.json" -w "%{http_code}" \
        -X POST "http://127.0.0.1:$PORT/partial-evaluate" \
        -H "Content-Type: application/json" \
        -d "{\"blinded_point\": \"$TEST_BLINDED_POINT\"}")

    if [[ "$EVAL_HTTP_CODE" != "200" ]]; then
        echo "  DEBUG: node $i evaluate returned HTTP $EVAL_HTTP_CODE"
        echo "  DEBUG: response: $(cat "$TMPDIR/eval_node${i}.json" 2>/dev/null)"
    fi
    assert_eq "node $i /partial-evaluate returns 200" "200" "$EVAL_HTTP_CODE"

    if [[ -f "$TMPDIR/eval_node${i}.json" ]]; then
        PARTIAL=$(cat "$TMPDIR/eval_node${i}.json")
        PARTIAL_POINT=$(echo "$PARTIAL" | jq -r '.partial_point')
        assert_match "node $i partial_point is valid compressed point" \
            '^(02|03)[0-9a-f]{64}$' "$PARTIAL_POINT"

        PROOF_C=$(echo "$PARTIAL" | jq -r '.proof.c')
        assert_match "node $i DLEQ proof.c is non-empty hex" '^[0-9a-f]+$' "$PROOF_C"
    fi
done

# 4c. Verify all nodes produce different partial points (different shares)
echo ""
echo "--- Test 4c: Partial points are distinct ---"
P1=$(jq -r '.partial_point' "$TMPDIR/eval_node1.json" 2>/dev/null || echo "")
P2=$(jq -r '.partial_point' "$TMPDIR/eval_node2.json" 2>/dev/null || echo "")
P3=$(jq -r '.partial_point' "$TMPDIR/eval_node3.json" 2>/dev/null || echo "")

if [[ -n "$P1" && -n "$P2" && -n "$P3" ]]; then
    if [[ "$P1" != "$P2" && "$P2" != "$P3" && "$P1" != "$P3" ]]; then
        echo "  PASS: all 3 partial points are distinct"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: partial points are not all distinct"
        FAIL=$((FAIL + 1))
    fi
else
    echo "  SKIP: could not compare (missing partial points)"
fi

# ---------- 5. Summary ----------

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
    exit 1
else
    echo "  RESULT: PASS"
    exit 0
fi
