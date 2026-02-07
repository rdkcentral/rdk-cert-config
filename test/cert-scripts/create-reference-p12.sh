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
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

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

# Generate sentinel EC private key (all zeros pattern)
echo "[create-reference-p12] Generating sentinel key..."
SENTINEL_KEY_PEM="$TEMP_DIR/sentinel_key.pem"

# Generate a valid EC key template
openssl ecparam -name prime256v1 -genkey -noout -out "$TEMP_DIR/template_key.pem"
openssl pkey -in "$TEMP_DIR/template_key.pem" -outform DER -out "$TEMP_DIR/template.der"

# Find offset of 32-byte private key value in PKCS#8 structure
HEADER_OFFSET=$(openssl asn1parse -in "$TEMP_DIR/template.der" -inform DER | \
    grep "d=1" | grep "OCTET STRING" | grep "l=  32" | head -1 | \
    awk '{print $1}' | cut -d: -f1)

if [ -z "$HEADER_OFFSET" ]; then
    echo "[create-reference-p12] ERROR: Could not parse EC key structure"
    exit 1
fi

# Calculate data offset (skip ASN.1 tag and length bytes: +2)
OFFSET=$((HEADER_OFFSET + 2))

# Create sentinel pattern: 32 bytes of 0x00
dd if=/dev/zero of="$TEMP_DIR/sentinel32.bin" bs=1 count=32 2>/dev/null

# Replace private key value with sentinel pattern
dd if="$TEMP_DIR/sentinel32.bin" of="$TEMP_DIR/template.der" bs=1 seek=$OFFSET count=32 conv=notrunc 2>/dev/null

# Convert back to PEM
openssl pkey -inform DER -in "$TEMP_DIR/template.der" -out "$SENTINEL_KEY_PEM"

if [ ! -s "$SENTINEL_KEY_PEM" ]; then
    echo "[create-reference-p12] ERROR: Failed to create sentinel key"
    exit 1
fi

# Create reference P12 with sentinel key
"$TOOL_BIN" "$CERT_FILE" "$SENTINEL_KEY_PEM" "$OUTPUT_P12" "$PASSWORD"

if [ $? -eq 0 ] && [ -f "$OUTPUT_P12" ]; then
    echo "[create-reference-p12] ✓ Reference P12 created: $OUTPUT_P12"
    echo "[create-reference-p12] Sentinel key: 32 bytes of zeros"
    exit 0
else
    echo "[create-reference-p12] ERROR: Failed to create reference P12"
    exit 1
fi
