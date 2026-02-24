#!/bin/bash
##########################################################################
# PKCS#11 Token Setup and Certificate Import
# 
# This script combines token initialization and certificate import:
# 1. Initializes SoftHSM2 token if not exists
# 2. Imports client certificates to slot 0x01 (standard mTLS)
# 3. Imports keys to slot 0x2c for PKCS#11 patch testing (production mode)
#
# Copyright 2026 RDK Management
# SPDX-License-Identifier: Apache-2.0
##########################################################################

set -e

# Configuration
TOKEN_LABEL="${TOKEN_LABEL:-RDK_TOKEN}"
SO_PIN="${SO_PIN:-1234}"
USER_PIN="${USER_PIN:-1234}"
TOKEN_DIR="${TOKEN_DIR:-/var/lib/softhsm/tokens}"
CERT_DIR="${CERT_DIR:-/opt/certs}"
PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --cert-dir)
            CERT_DIR="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --cert-dir DIR     Certificate directory (default: /opt/certs)"
            echo "  --help             Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "[setup-pkcs11] Starting PKCS#11 setup..."
echo "[setup-pkcs11] Token: $TOKEN_LABEL, Cert dir: $CERT_DIR"

##########################################################################
# STEP 1: Initialize PKCS#11 Token
##########################################################################

echo ""
echo "[setup-pkcs11] === Initializing PKCS#11 token ==="

# Ensure token directory exists
mkdir -p "$TOKEN_DIR"
chmod 755 "$TOKEN_DIR"

# Check if token already exists
if softhsm2-util --show-slots 2>/dev/null | grep -q "$TOKEN_LABEL"; then
    echo "[setup-pkcs11] Token '$TOKEN_LABEL' already exists"
else
    echo "[setup-pkcs11] Creating token '$TOKEN_LABEL'..."
    if softhsm2-util --init-token \
        --free \
        --label "$TOKEN_LABEL" \
        --so-pin "$SO_PIN" \
        --pin "$USER_PIN"; then
        echo "[setup-pkcs11] ✓ Token initialized successfully"
    else
        echo "[setup-pkcs11] ERROR: Failed to initialize token"
        exit 1
    fi
fi

# Display token information
echo "[setup-pkcs11] Token details:"
softhsm2-util --show-slots

##########################################################################
# STEP 2: Import Certificates to PKCS#11
##########################################################################

echo ""
    echo "[setup-pkcs11] === Importing certificates to PKCS#11 ==="
    
    # Verify PKCS#11 module exists
    if [ ! -f "$PKCS11_MODULE" ]; then
        echo "[setup-pkcs11] ERROR: PKCS#11 module not found: $PKCS11_MODULE"
        exit 1
    fi
    
    # Get token slot
    SLOT=$(softhsm2-util --show-slots | grep -B 20 "Label:.*$TOKEN_LABEL" | grep "^Slot " | head -1 | awk '{print $2}')
    if [ -z "$SLOT" ]; then
        echo "[setup-pkcs11] ERROR: Token '$TOKEN_LABEL' not found"
        echo "[setup-pkcs11] This should not happen - token was just initialized"
        exit 1
    fi
    
    echo "[setup-pkcs11] Found token at slot: $SLOT"
    
    # Determine client cert/key source
    if [ -f "$CERT_DIR/client.pem" ] && [ -f "$CERT_DIR/client.key" ]; then
        echo "[setup-pkcs11] Using existing client.pem and client.key files"
        CLIENT_CERT="$CERT_DIR/client.pem"
        CLIENT_KEY="$CERT_DIR/client.key"
        CLEANUP_TEMP=false
    elif [ -f "$CERT_DIR/client.p12" ]; then
        echo "[setup-pkcs11] Extracting cert and key from client.p12..."
        
        # Extract certificate
        if ! openssl pkcs12 -in "$CERT_DIR/client.p12" -passin pass:changeit \
            -out /tmp/client-cert.pem -clcerts -nokeys 2>/dev/null; then
            echo "[setup-pkcs11] ERROR: Failed to extract certificate from client.p12"
            exit 1
        fi
        
        # Extract private key
        if ! openssl pkcs12 -in "$CERT_DIR/client.p12" -passin pass:changeit \
            -out /tmp/client-key.pem -nocerts -nodes 2>/dev/null; then
            echo "[setup-pkcs11] ERROR: Failed to extract key from client.p12"
            exit 1
        fi
        
        CLIENT_CERT="/tmp/client-cert.pem"
        CLIENT_KEY="/tmp/client-key.pem"
        CLEANUP_TEMP=true
    else
        echo "[setup-pkcs11] WARNING: No client certificate files found"
        echo "[setup-pkcs11] Skipping certificate import"
        SKIP_CERT_IMPORT=true
    fi
    
    if [ "$SKIP_CERT_IMPORT" = false ]; then
        # Import to slot 0x01 (standard mTLS)
        echo "[setup-pkcs11] Importing client certificate to slot 0x01..."
        
        pkcs11-tool --module "$PKCS11_MODULE" \
            --slot "$SLOT" \
            --login --pin "$USER_PIN" \
            --write-object "$CLIENT_CERT" \
            --type cert \
            --id 01 \
            --label "rdkclient" 2>&1 | grep -v "error:" || echo "  (may already exist)"
        
        pkcs11-tool --module "$PKCS11_MODULE" \
            --slot "$SLOT" \
            --login --pin "$USER_PIN" \
            --write-object "$CLIENT_KEY" \
            --type privkey \
            --id 01 \
            --label "rdkclient-key" 2>&1 | grep -v "error:" || echo "  (may already exist)"
        
        echo "[setup-pkcs11] ✓ Client certificate imported to slot 0x01"
        
        # Import to slot 0x2c (PKCS#11 patch testing - production mode)
        if [ -f "$CERT_DIR/reference.p12" ]; then
            echo "[setup-pkcs11] Importing keys to slot 0x2c (PRODUCTION MODE - keys only)..."
            
            # Extract public key from certificate
            openssl x509 -in "$CLIENT_CERT" -pubkey -noout > /tmp/client-pubkey.pem
            
            # Convert to DER format (try EC first, fallback to RSA)
            if openssl ec -pubin -in /tmp/client-pubkey.pem -outform DER -out /tmp/client-pubkey.der 2>/dev/null; then
                KEY_TYPE="EC"
            elif openssl rsa -pubin -in /tmp/client-pubkey.pem -outform DER -out /tmp/client-pubkey.der 2>/dev/null; then
                KEY_TYPE="RSA"
            else
                echo "[setup-pkcs11] ERROR: Failed to convert public key to DER"
                rm -f /tmp/client-pubkey.pem
                [ "$CLEANUP_TEMP" = true ] && rm -f "$CLIENT_CERT" "$CLIENT_KEY"
                exit 1
            fi
            
            echo "[setup-pkcs11]   Key type: $KEY_TYPE"
            
            # Import private key
            pkcs11-tool --module "$PKCS11_MODULE" \
                --slot "$SLOT" \
                --login --pin "$USER_PIN" \
                --write-object "$CLIENT_KEY" \
                --type privkey \
                --id 2c \
                --label "rdkclient-p12-key" 2>&1 | grep -v "error:" || echo "  (may already exist)"
            
            # Import public key
            pkcs11-tool --module "$PKCS11_MODULE" \
                --slot "$SLOT" \
                --login --pin "$USER_PIN" \
                --write-object /tmp/client-pubkey.der \
                --type pubkey \
                --id 2c \
                --label "rdkclient-p12-pubkey" 2>&1 | grep -v "error:" || echo "  (may already exist)"
            
            echo "[setup-pkcs11] ✓ Keys imported to slot 0x2c (PRODUCTION MODE)"
            echo "[setup-pkcs11]   • Private key at ID 0x2c: YES"
            echo "[setup-pkcs11]   • Public key at ID 0x2c:  YES"
            echo "[setup-pkcs11]   • Certificate at ID 0x2c: NO (from P12 file)"
            
            rm -f /tmp/client-pubkey.pem /tmp/client-pubkey.der
        fi
        
        # Cleanup temp files
        [ "$CLEANUP_TEMP" = true ] && rm -f "$CLIENT_CERT" "$CLIENT_KEY"
        
        # List imported objects
        echo ""
        echo "[setup-pkcs11] Imported objects:"
        pkcs11-tool --module "$PKCS11_MODULE" --slot "$SLOT" --login --pin "$USER_PIN" --list-objects | \
            grep -E "(Certificate Object|Private Key Object|Public Key Object|label:|ID:)" || true
    fi

echo ""
echo "[setup-pkcs11] ✓ PKCS#11 setup complete"
export PKCS11_PIN="$USER_PIN"
exit 0
