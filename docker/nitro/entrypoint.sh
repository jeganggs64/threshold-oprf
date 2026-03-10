#!/usr/bin/env bash
# =============================================================================
# entrypoint.sh -- Nitro Enclave entry point for toprf-node
#
# Inside a Nitro Enclave there is no standard TCP/IP networking. This script
# sets up the vsock-to-TCP bridge so the node can communicate with the parent
# EC2 instance and other enclaves.
#
# Environment variables:
#   VSOCK_CID    - Enclave CID (assigned by nitro-cli, usually >= 4)
#   VSOCK_PORT   - Port to listen on via vsock (default: 3001)
#   NODE_INDEX   - This node's index in the threshold group
#   THRESHOLD    - Minimum number of signers (t)
#   TOTAL_NODES  - Total number of nodes (n)
# =============================================================================
set -euo pipefail

VSOCK_PORT="${VSOCK_PORT:-3001}"
NODE_INDEX="${NODE_INDEX:-0}"
THRESHOLD="${THRESHOLD:-2}"
TOTAL_NODES="${TOTAL_NODES:-3}"

# Validate numeric env vars
for var_name in NODE_INDEX THRESHOLD TOTAL_NODES VSOCK_PORT; do
    eval var_val=\$$var_name
    case "$var_val" in
        ''|*[!0-9]*) echo "FATAL: $var_name must be numeric, got '$var_val'"; exit 1 ;;
    esac
done

echo "[entrypoint] Starting toprf-node inside Nitro Enclave"
echo "[entrypoint]   VSOCK_PORT=$VSOCK_PORT"
echo "[entrypoint]   NODE_INDEX=$NODE_INDEX"
echo "[entrypoint]   THRESHOLD=$THRESHOLD"
echo "[entrypoint]   TOTAL_NODES=$TOTAL_NODES"

# Configure loopback so the node can bind to 127.0.0.1 internally.
# Nitro Enclaves do not start with a configured loopback interface.
if ip link show lo &>/dev/null; then
    ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
    ip link set lo up 2>/dev/null || true
fi

# Start the vsock-proxy in the background. It forwards traffic from
# vsock CID:PORT to the local TCP listener on 127.0.0.1:3001.
# The parent instance runs a matching vsock-proxy that bridges
# external TCP connections to this vsock port.
#
# NOTE: In production, you would typically run vsock-proxy on the parent
# instance, not inside the enclave. The node listens on vsock directly
# if built with vsock support, or on localhost with a proxy inside the enclave.
if command -v vsock-proxy &>/dev/null; then
    echo "[entrypoint] Starting vsock-proxy: vsock:$VSOCK_PORT -> 127.0.0.1:3001"
    vsock-proxy "$VSOCK_PORT" 127.0.0.1 3001 &
fi

# Run the node, binding to localhost (traffic arrives via vsock-proxy)
export LISTEN_ADDR="127.0.0.1:3001"
export RUST_LOG="${RUST_LOG:-info}"

# Drop to non-root user for the node process
exec gosu toprf /usr/local/bin/toprf-node
