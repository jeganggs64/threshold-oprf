#!/usr/bin/env bash
#
# gen-certs.sh - Generate TLS certificates for the threshold OPRF system.
#
# Creates:
#   - A self-signed CA (toprf-ca)
#   - Node server certificates for node1, node2, node3 (signed by the CA)
#
# All output goes into certs/ relative to the project root.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CERTS_DIR="$PROJECT_ROOT/certs"

CA_DIR="$CERTS_DIR/ca"
NODES_DIR="$CERTS_DIR/nodes"

CA_VALIDITY=1095
CERT_VALIDITY=365
KEY_TYPE="prime256v1"
NODES=("node1" "node2" "node3")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info() {
    echo "==> $*"
}

# ---------------------------------------------------------------------------
# Prepare directories
# ---------------------------------------------------------------------------

info "Cleaning and creating certificate directories under $CERTS_DIR"
rm -rf "$CERTS_DIR"
mkdir -p "$CA_DIR" "$NODES_DIR"

# ---------------------------------------------------------------------------
# 1. Self-signed CA
# ---------------------------------------------------------------------------

info "Generating CA private key (P-256)"
openssl ecparam -genkey -name "$KEY_TYPE" -noout -out "$CA_DIR/ca.key" 2>/dev/null
chmod 600 "$CA_DIR/ca.key"

info "Creating self-signed CA certificate (valid $CA_VALIDITY days)"
openssl req -new -x509 \
    -key "$CA_DIR/ca.key" \
    -out "$CA_DIR/ca.pem" \
    -days "$CA_VALIDITY" \
    -subj "/CN=toprf-ca/O=Threshold OPRF/OU=CA" \
    -sha256

# ---------------------------------------------------------------------------
# 2. Node server certificates
# ---------------------------------------------------------------------------

for node in "${NODES[@]}"; do
    info "Generating key and certificate for $node"

    # Private key
    openssl ecparam -genkey -name "$KEY_TYPE" -noout \
        -out "$NODES_DIR/$node.key" 2>/dev/null
    chmod 600 "$NODES_DIR/$node.key"

    # CSR
    openssl req -new \
        -key "$NODES_DIR/$node.key" \
        -out "$NODES_DIR/$node.csr" \
        -subj "/CN=$node/O=Threshold OPRF/OU=Node" \
        -sha256

    # Extensions file with SANs for localhost / 127.0.0.1
    cat > "$NODES_DIR/$node.ext" <<EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = $node
IP.1  = 127.0.0.1
EXTEOF

    # Sign with CA
    openssl x509 -req \
        -in "$NODES_DIR/$node.csr" \
        -CA "$CA_DIR/ca.pem" \
        -CAkey "$CA_DIR/ca.key" \
        -CAcreateserial \
        -out "$NODES_DIR/$node.pem" \
        -days "$CERT_VALIDITY" \
        -sha256 \
        -extfile "$NODES_DIR/$node.ext" 2>/dev/null

    # Clean up intermediary files
    rm -f "$NODES_DIR/$node.csr" "$NODES_DIR/$node.ext"
done

# Clean up CA serial file
rm -f "$CA_DIR/ca.srl"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "============================================"
echo "  Certificate generation complete"
echo "============================================"
echo ""
echo "CA (valid $CA_VALIDITY days):"
echo "  $CA_DIR/ca.key"
echo "  $CA_DIR/ca.pem"
echo ""
echo "Node server certs (valid $CERT_VALIDITY days, SANs: localhost, 127.0.0.1):"
for node in "${NODES[@]}"; do
    echo "  $NODES_DIR/$node.key"
    echo "  $NODES_DIR/$node.pem"
done
echo ""
echo "All certificates use P-256 (prime256v1) keys."
echo ""
echo "NOTE: For production, use './deploy.sh certs' which adds"
echo "real node IPs as SANs and distributes certs to VMs."
echo "============================================"
