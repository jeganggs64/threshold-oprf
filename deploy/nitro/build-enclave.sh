#!/usr/bin/env bash
# =============================================================================
# build-enclave.sh
#
# Builds the toprf-node Nitro Enclave image (EIF) from the Docker image and
# prints the PCR measurements needed for attestation policy configuration.
#
# Prerequisites:
#   - Docker installed and running
#   - nitro-cli installed (available on Nitro-capable EC2 instances)
#   - Run from the repository root: ./deploy/nitro/build-enclave.sh
#
# Usage:
#   ./deploy/nitro/build-enclave.sh [--tag TAG] [--output DIR]
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

IMAGE_TAG="${1:-toprf-node-nitro:latest}"
OUTPUT_DIR="${2:-$SCRIPT_DIR/output}"
EIF_NAME="toprf-node.eif"

echo "==> Building Docker image for Nitro Enclave..."
docker build \
    -f "$SCRIPT_DIR/nitro-enclave.Dockerfile" \
    -t "$IMAGE_TAG" \
    "$REPO_ROOT"

echo ""
echo "==> Converting Docker image to Enclave Image Format (EIF)..."
mkdir -p "$OUTPUT_DIR"

nitro-cli build-enclave \
    --docker-uri "$IMAGE_TAG" \
    --output-file "$OUTPUT_DIR/$EIF_NAME" \
    | tee "$OUTPUT_DIR/build-measurements.json"

echo ""
echo "============================================================"
echo " Enclave build complete"
echo "============================================================"
echo " EIF: $OUTPUT_DIR/$EIF_NAME"
echo ""
echo " PCR Measurements (save these for attestation policies):"
echo ""

# Extract and display PCR values from the build output
if command -v jq &>/dev/null; then
    jq -r '
        "  PCR0 (enclave image):  \(.Measurements.PCR0)",
        "  PCR1 (Linux kernel):   \(.Measurements.PCR1)",
        "  PCR2 (application):    \(.Measurements.PCR2)"
    ' "$OUTPUT_DIR/build-measurements.json"
else
    echo "  (install jq to see formatted PCR values)"
    cat "$OUTPUT_DIR/build-measurements.json"
fi

echo ""
echo " To run the enclave:"
echo "   nitro-cli run-enclave \\"
echo "     --eif-path $OUTPUT_DIR/$EIF_NAME \\"
echo "     --cpu-count 2 \\"
echo "     --memory 512 \\"
echo "     --enclave-cid 16"
echo ""
echo " To verify a running enclave:"
echo "   nitro-cli describe-enclaves"
echo "============================================================"
