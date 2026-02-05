#!/bin/bash
##########################################################################
# Create reference P12 file with sentinel key for PKCS#11 testing
# The sentinel key is all zeros (32 bytes) to trigger P12 patch behavior
##########################################################################

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <cert.pem> <output.p12> [password]"
    echo "  cert.pem    - Input certificate file"
    echo "  output.p12  - Output P12 file with sentinel key"
    echo "  password    - P12 password (default: changeit)"
    exit 1
fi

CERT_FILE="$1"
OUTPUT_P12="$2"
PASSWORD="${3:-changeit}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_BIN="${SCRIPT_DIR}/tools/make_ref_p12"

echo "[create-reference-p12] Creating reference P12 with sentinel key..."

# Verify input certificate
if [ ! -f "$CERT_FILE" ]; then
    echo "[create-reference-p12] ERROR: Certificate file not found: $CERT_FILE"
    exit 1
fi

# Build make_ref_p12 tool if not already built
if [ ! -f "$TOOL_BIN" ]; then
    echo "[create-reference-p12] Building make_ref_p12 tool..."
    if [ -f "${SCRIPT_DIR}/tools/make_ref_p12.c" ]; then
        gcc -o "$TOOL_BIN" "${SCRIPT_DIR}/tools/make_ref_p12.c" -lssl -lcrypto
        if [ $? -ne 0 ]; then
            echo "[create-reference-p12] ERROR: Failed to compile make_ref_p12"
            exit 1
        fi
    else
        echo "[create-reference-p12] ERROR: make_ref_p12.c not found"
        exit 1
    fi
fi

# Create reference P12 with sentinel key (all zeros)
"$TOOL_BIN" "$CERT_FILE" "$OUTPUT_P12" "$PASSWORD"

if [ $? -eq 0 ] && [ -f "$OUTPUT_P12" ]; then
    echo "[create-reference-p12] ✓ Reference P12 created: $OUTPUT_P12"
    echo "[create-reference-p12] Sentinel key: 32 bytes of zeros"
    exit 0
else
    echo "[create-reference-p12] ERROR: Failed to create reference P12"
    exit 1
fi
