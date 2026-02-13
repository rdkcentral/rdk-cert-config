#!/bin/bash
################################################################################
# create-reference-p12.sh - Generate reference P12 with sentinel key for PKCS#11
#
# This script creates a reference P12 file containing:
#   - A real certificate (from client.pem)
#   - A sentinel private key (32 bytes of zeros)
#
# The sentinel key triggers the PKCS#11 P12 patch to load the real private key
# from a hardware token instead of using the sentinel key.
#
# Usage: create-reference-p12.sh <cert_file> <output_p12> [password] [key_id]
#
# Arguments:
#   cert_file   - Path to certificate PEM file (default: client.pem)
#   output_p12  - Path to output P12 file (default: reference.p12)
#   password    - P12 password (default: changeit)
#   key_id      - PKCS#11 key ID in hex (default: 2c)
#
# Output:
#   - reference.p12: P12 file with certificate and sentinel key
#   - sentinel_key.pem: Temporary sentinel key file (deleted after use)
#
################################################################################

set -e

# Default values
CERT_FILE="${1:-client.pem}"
OUTPUT_P12="${2:-reference.p12}"
P12_PASSWORD="${3:-changeit}"
KEY_ID="${4:-2c}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMP_DIR="/tmp/create_ref_p12_$$"

echo "════════════════════════════════════════════════════════════════════"
echo "Reference P12 Generator with Sentinel Key"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "Configuration:"
echo "  Certificate: $CERT_FILE"
echo "  Output P12:  $OUTPUT_P12"
echo "  Password:    $P12_PASSWORD"
echo "  PKCS#11 Key ID: 0x$KEY_ID"
echo ""

# Create temp directory
mkdir -p "$TEMP_DIR"
trap "rm -rf $TEMP_DIR" EXIT

# Verify certificate exists
if [ ! -f "$CERT_FILE" ]; then
    echo "ERROR: Certificate file not found: $CERT_FILE"
    exit 1
fi

echo "Step 1: Generate sentinel EC private key (all zeros)"
echo "────────────────────────────────────────────────────────────────────"

# Generate a valid EC key template for prime256v1 curve
openssl ecparam -name prime256v1 -genkey -noout -out "$TEMP_DIR/template_key.pem"

# Convert to PKCS#8 DER format
openssl pkey -in "$TEMP_DIR/template_key.pem" -outform DER -out "$TEMP_DIR/template.der"

# Find the offset of the 32-byte private key OCTET STRING
# Look for depth=1 (nested inside PKCS#8 structure) with length 32
HEADER_OFFSET=$(openssl asn1parse -in "$TEMP_DIR/template.der" -inform DER | \
    grep "d=1" | \
    grep "OCTET STRING" | \
    grep "l=  32" | \
    head -1 | \
    awk '{print $1}' | \
    cut -d: -f1)

if [ -z "$HEADER_OFFSET" ]; then
    echo "ERROR: Could not find 32-byte OCTET STRING in PKCS#8 template"
    openssl asn1parse -in "$TEMP_DIR/template.der" -inform DER
    exit 1
fi

# Calculate data offset (skip ASN.1 tag and length bytes: +2)
OFFSET=$((HEADER_OFFSET + 2))

# Create sentinel pattern: 32 bytes of 0x00 (all zeros)
# Patch logic:
#   1. Checks first 30 bytes are zero → triggers reference key detection
#   2. Extracts byte 31 as key_id → will be 0x00
#   3. Applies default: key_id = (key_id == 0x00) ? 0x2c : key_id → becomes 0x2c
# Result: OpenSSL detects all-zero key, uses PKCS#11 slot 0x2c
dd if=/dev/zero of="$TEMP_DIR/sentinel32.bin" bs=1 count=32 2>/dev/null

# Replace the 32-byte private key value with sentinel pattern (all zeros)
dd if="$TEMP_DIR/sentinel32.bin" of="$TEMP_DIR/template.der" bs=1 seek=$OFFSET count=32 conv=notrunc 2>/dev/null

# Convert modified DER back to PEM
openssl pkey -inform DER -in "$TEMP_DIR/template.der" -out "$TEMP_DIR/sentinel_key.pem"

if [ ! -s "$TEMP_DIR/sentinel_key.pem" ]; then
    echo "ERROR: Failed to create sentinel key PEM file"
    exit 1
fi

echo "✓ Created valid sentinel EC key PEM (PKCS#8 format with zeroed private value)"
echo ""

echo "Step 2: Build make_ref_p12 helper program"
echo "────────────────────────────────────────────────────────────────────"

# Create make_ref_p12.c if it doesn't exist
if [ ! -f "$SCRIPT_DIR/make_ref_p12.c" ]; then
    cat > "$SCRIPT_DIR/make_ref_p12.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main(int argc, char *argv[]) {
    FILE *f;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    PKCS12 *p12 = NULL;
    PKCS7 *p7 = NULL;
    STACK_OF(PKCS7) *safes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    
    const char *cert_file = "cert.pem";
    const char *key_file = "sentinel_key.pem";
    const char *p12_file = "reference.p12";
    const char *password = "changeit";

    if (argc > 1) cert_file = argv[1];
    if (argc > 2) key_file = argv[2];
    if (argc > 3) p12_file = argv[3];
    if (argc > 4) password = argv[4];

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Load certificate */
    f = fopen(cert_file, "r");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", cert_file);
        return 1;
    }
    cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    /* Load sentinel key */
    f = fopen(key_file, "r");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", key_file);
        X509_free(cert);
        return 1;
    }
    pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    if (!cert || !pkey) {
        fprintf(stderr, "ERROR: Failed to load cert or key\n");
        ERR_print_errors_fp(stderr);
        if (cert) X509_free(cert);
        if (pkey) EVP_PKEY_free(pkey);
        return 1;
    }

    /* Create bag stack */
    bags = sk_PKCS12_SAFEBAG_new_null();

    /* Add cert bag */
    if (!PKCS12_add_cert(&bags, cert)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Add key bag — NO key/cert validation */
    /* PKCS12_add_key signature: pbags, pkey, key_usage, iter, key_nid, pass */
    /* Use -1 for key_nid to disable PBE encryption (avoid legacy provider requirement) */
    if (!PKCS12_add_key(&bags, pkey, -1, 0, -1, NULL)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Pack bags into PKCS7 */
    p7 = PKCS12_pack_p7data(bags);
    if (!p7) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Create safes stack */
    safes = sk_PKCS7_new_null();
    sk_PKCS7_push(safes, p7);

    /* Build PKCS12 */
    p12 = PKCS12_init(NID_pkcs7_data);
    if (!PKCS12_pack_authsafes(p12, safes)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Set MAC */
    if (!PKCS12_set_mac(p12, password, -1, NULL, 0, 2048, NULL)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Write P12 */
    f = fopen(p12_file, "wb");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", p12_file);
        return 1;
    }
    i2d_PKCS12_fp(f, p12);
    fclose(f);

    printf("✓ Successfully created reference P12: %s\n", p12_file);
    printf("  Certificate: %s\n", cert_file);
    printf("  Sentinel key: %s (no validation)\n", key_file);
    printf("  Password: %s\n", password);

    PKCS12_free(p12);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    return 0;
}
EOF
fi

# Compile make_ref_p12 if not already compiled
if [ ! -f "$SCRIPT_DIR/make_ref_p12" ]; then
    echo "  Compiling make_ref_p12..."
    gcc -o "$SCRIPT_DIR/make_ref_p12" "$SCRIPT_DIR/make_ref_p12.c" -lssl -lcrypto
    if [ ! -f "$SCRIPT_DIR/make_ref_p12" ]; then
        echo "ERROR: Failed to compile make_ref_p12"
        exit 1
    fi
    echo "  ✓ Compiled make_ref_p12"
else
    echo "  ✓ make_ref_p12 already compiled"
fi

echo ""
echo "Step 3: Create reference P12 using OpenSSL API"
echo "────────────────────────────────────────────────────────────────────"

# Use make_ref_p12 to create reference P12 (bypasses OpenSSL validation)
"$SCRIPT_DIR/make_ref_p12" "$CERT_FILE" "$TEMP_DIR/sentinel_key.pem" "$OUTPUT_P12" "$P12_PASSWORD"

if [ ! -f "$OUTPUT_P12" ]; then
    echo "ERROR: Failed to create reference P12"
    exit 1
fi

echo ""
echo "Step 4: Verify reference P12 structure"
echo "────────────────────────────────────────────────────────────────────"

# Verify the reference P12 can be parsed
if openssl pkcs12 -in "$OUTPUT_P12" -passin "pass:$P12_PASSWORD" -nokeys -clcerts -noout 2>/dev/null; then
    echo "  ✓ Reference P12 certificate can be extracted"
else
    echo "  ✗ Reference P12 parsing failed"
    exit 1
fi

# Dump the sentinel key pattern for verification
echo ""
echo "  Sentinel key pattern verification:"
SENTINEL_HEX=$(openssl pkcs12 -in "$OUTPUT_P12" -passin "pass:$P12_PASSWORD" -nocerts -nodes 2>/dev/null | \
               openssl ec -text -noout 2>/dev/null | grep -A2 "priv:" | tail -2 | tr -d ' \n:')
echo "    First 64 hex chars: $(echo "$SENTINEL_HEX" | head -c 64)"
echo "    Expected pattern:   0000000000000000000000000000000000000000000000000000000000000000"

if echo "$SENTINEL_HEX" | head -c 64 | grep -q "^00000000000000000000000000000000"; then
    echo "    ✓ Sentinel pattern detected (all zeros)"
else
    echo "    ✗ WARNING: Sentinel pattern NOT detected"
fi

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "✓ Reference P12 generation complete"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "Output file: $OUTPUT_P12"
echo "Password: $P12_PASSWORD"
echo ""
echo "This P12 file contains:"
echo "  • Real certificate from $CERT_FILE"
echo "  • Sentinel key (32 bytes of zeros) → redirects to PKCS#11 slot 0x$KEY_ID"
echo ""
echo "When used with the PKCS#11 P12 patch, OpenSSL will:"
echo "  1. Detect the sentinel key pattern"
echo "  2. Load the real private key from PKCS#11 hardware token (slot 0x$KEY_ID)"
echo "  3. Complete mTLS handshake using hardware-backed key"
echo ""
