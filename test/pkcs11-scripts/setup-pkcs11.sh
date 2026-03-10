#!/bin/bash
# RDK-CERT-CONFIG-ORIGINAL-WORK
#
# Copyright (c) 2026 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "Apache License");
# this file may be used only in accordance with that License.
# A copy of the License is available at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed in writing,
# the software is provided on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied.
# See the License for permissions and limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -e

# Configuration
TOKEN_LABEL="${TOKEN_LABEL:-RDK_TOKEN}"
SO_PIN="${SO_PIN:-1234}"
USER_PIN="${USER_PIN:-1234}"
TOKEN_DIR="${TOKEN_DIR:-/var/lib/softhsm/tokens}"
CERT_DIR="${CERT_DIR:-/opt/certs}"
PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib/softhsm/libsofthsm2.so}"

echo "[setup-pkcs11] Starting PKCS#11 setup..."
echo "[setup-pkcs11] Token Label: $TOKEN_LABEL, Cert Directory: $CERT_DIR"

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
    fi
    
    if [ -n "$CLIENT_CERT" ] && [ -f "$CLIENT_CERT" ]; then
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
        
        # Import to slot 0x02 (PKCS#11 patch testing - production mode)
        if [ -f "$CERT_DIR/reference.p12" ]; then
            echo "[setup-pkcs11] Importing keys to slot 0x02 (PRODUCTION MODE - keys only)..."
            
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
                --id 02 \
                --label "rdkclient-p12-key" 2>&1 | grep -v "error:" || echo "  (may already exist)"
            
            # Import public key
            pkcs11-tool --module "$PKCS11_MODULE" \
                --slot "$SLOT" \
                --login --pin "$USER_PIN" \
                --write-object /tmp/client-pubkey.der \
                --type pubkey \
                --id 02 \
                --label "rdkclient-p12-pubkey" 2>&1 | grep -v "error:" || echo "  (may already exist)"
            
            echo "[setup-pkcs11] ✓ Keys imported to slot 0x02 (PRODUCTION MODE)"
            echo "[setup-pkcs11]   • Private key at ID 0x02: YES"
            echo "[setup-pkcs11]   • Public key at ID 0x02:  YES"
            echo "[setup-pkcs11]   • Certificate at ID 0x02: NO (from P12 file)"
            
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

##########################################################################
# STEP 3: Create OpenSSL PKCS#11 Configuration
##########################################################################

echo ""
echo "[setup-pkcs11] === Creating OpenSSL PKCS#11 configuration ==="

PKCS11_ENGINE_PATH=""
if [ -f "/usr/local/lib64/engines-3/pkcs11.so" ]; then
    PKCS11_ENGINE_PATH="/usr/local/lib64/engines-3/pkcs11.so"
elif [ -f "/usr/local/lib/engines-3/pkcs11.so" ]; then
    PKCS11_ENGINE_PATH="/usr/local/lib/engines-3/pkcs11.so"
elif [ -f "/usr/lib/aarch64-linux-gnu/engines-3/pkcs11.so" ]; then
    PKCS11_ENGINE_PATH="/usr/lib/aarch64-linux-gnu/engines-3/pkcs11.so"
elif [ -f "/usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so" ]; then
    PKCS11_ENGINE_PATH="/usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so"
fi

if [ -n "$PKCS11_ENGINE_PATH" ]; then
    echo "[setup-pkcs11] Detected PKCS#11 engine: $PKCS11_ENGINE_PATH"
    cat > /etc/ssl/openssl.cnf << EOF
# OpenSSL Configuration for PKCS#11 P12 Patch
openssl_conf = openssl_init

[openssl_init]
engines = engine_section
providers = provider_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = $PKCS11_ENGINE_PATH
MODULE_PATH = /usr/lib/softhsm/libsofthsm2.so
PIN = 1234
init = 1

[provider_section]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
EOF
    echo "[setup-pkcs11] ✓ OpenSSL PKCS#11 configuration created at /etc/ssl/openssl.cnf"
else
    echo "[setup-pkcs11] ⚠ PKCS#11 engine not found, skipping OpenSSL engine config"
    echo "[setup-pkcs11] P12 patch will still work (patch is compiled into OpenSSL)"
fi

##########################################################################
# STEP 4: Create hrot.properties and SSA-daemon hrothardware.cfg
##########################################################################

echo ""
echo "[setup-pkcs11] === Creating hrot configuration ==="

mkdir -p /etc/ssl/certsel/pkcs11

cat > /etc/ssl/certsel/hrot.properties << 'HROTEOF'
deviceclass=rdkv
hrottype=pkcs11
hrotengine=pkcs11
kdftype=ecc
hrotconfig="/etc/ssl/certsel/pkcs11/hrothardware.cfg"
HROTEOF

# Resolve the tltasupportlib stub path; callers may override via env var.
# Default matches the automake install prefix used by rdktrusthal-cpc tests.
TLTA_STUB_LIB="${TLTA_STUB_LIB:-/usr/local/lib/libtrhal_tlta_pin_stub.so}"

# Write the SSA-daemon / rdktrusthal hrothardware.cfg.
# Key naming must exactly match the constants in rdktrHal_common.h:
#   hrotsupportlib  ← HROT_LIB_CFG_KEY
#   tltasupportlib  ← TLTA_LIB_CFG_KEY
#   basekeyhmac     ← BKEY_HMAC_CFG_KEY
#   buildpubkey     ← BUILD_PUB_KEY_CFG_KEY
# Numeric IDs parsed by pkcs11_config_load() – must be decimal.
# slotid is set to 0 here and updated dynamically at the end of STEP 5
# once SoftHSM has assigned the real slot number to TOKEN_LABEL.
cat > /etc/ssl/certsel/pkcs11/hrothardware.cfg << HWEOF
# SSA-daemon / rdktrusthal PKCS#11 configuration (test-only)
# Generated by setup-pkcs11.sh — do not edit by hand.

# --- rdktrusthal / pkcs11_config_load fields ---
slotid=0
AESKEY_ID=12
PRIVATE_KEY_ID=11
CEDM_SHARED=13
CEDM_INTERMEDIATE=14
hrotsupportlib=/usr/lib/softhsm/libsofthsm2.so
tltasupportlib=${TLTA_STUB_LIB}
basekeyhmac=/etc/ssadaemon/cal_tee_bkh.bin
buildpubkey=/etc/ssadaemon/cal_1.bin
HWEOF

echo "[setup-pkcs11] ✓ hrot configuration created (slotid placeholder; updated after token slot is resolved)"

##########################################################################
# STEP 5: Create ECC P-256 Key Pair for rdktrusthal-cpc (PRIVATE_KEY_ID=11)
##########################################################################

echo ""
echo "[setup-pkcs11] === Creating ECC P-256 key pair for rdktrusthal-cpc ==="

# Object ID 0x0b (decimal 11) matches PRIVATE_KEY_ID used by rdktrusthal-cpc
# hrothardware.cfg must have: PRIVATE_KEY_ID=11
ECC_KEY_ID="0b"
ECC_KEY_LABEL="vendor-priv-ecc"
ECC_PRIV_KEY_PEM="/tmp/ssa_ecc_priv_$$.pem"
ECC_PUB_KEY_DER="/tmp/ssa_ecc_pub_$$.der"

# Re-derive SLOT in case STEP 2 was skipped (e.g. no client cert present)
if [ -z "$SLOT" ]; then
    SLOT=$(softhsm2-util --show-slots 2>/dev/null | \
        grep -B 20 "Label:.*$TOKEN_LABEL" | grep "^Slot " | head -1 | awk '{print $2}')
    if [ -z "$SLOT" ]; then
        echo "[setup-pkcs11] ERROR: Cannot locate token slot for '$TOKEN_LABEL'"
        exit 1
    fi
fi

# Generate a test-only ECC P-256 private key (ephemeral; removed after import)
echo "[setup-pkcs11] Generating test-only ECC P-256 private key..."
if ! openssl genpkey -algorithm EC \
        -pkeyopt ec_paramgen_curve:P-256 \
        -out "$ECC_PRIV_KEY_PEM" 2>/dev/null; then
    echo "[setup-pkcs11] ERROR: Failed to generate ECC P-256 key"
    exit 1
fi
echo "[setup-pkcs11] ✓ ECC P-256 private key generated"

# Import the private key into SoftHSM at object ID 0x0b, label vendor-priv-ecc
echo "[setup-pkcs11] Importing ECC private key (ID=0x${ECC_KEY_ID}, label='${ECC_KEY_LABEL}')..."
pkcs11-tool --module "$PKCS11_MODULE" \
    --slot "$SLOT" \
    --login --pin "$USER_PIN" \
    --write-object "$ECC_PRIV_KEY_PEM" \
    --type privkey \
    --id "$ECC_KEY_ID" \
    --label "$ECC_KEY_LABEL" 2>&1 | grep -v "^error:" || true
echo "[setup-pkcs11] ✓ ECC private key object imported"

# Extract and import the corresponding public key (required for ECDH by rdktrusthal)
echo "[setup-pkcs11] Importing ECC public key  (ID=0x${ECC_KEY_ID}, label='${ECC_KEY_LABEL}')..."
if openssl pkey -in "$ECC_PRIV_KEY_PEM" -pubout -outform DER \
        -out "$ECC_PUB_KEY_DER" 2>/dev/null; then
    pkcs11-tool --module "$PKCS11_MODULE" \
        --slot "$SLOT" \
        --login --pin "$USER_PIN" \
        --write-object "$ECC_PUB_KEY_DER" \
        --type pubkey \
        --id "$ECC_KEY_ID" \
        --label "$ECC_KEY_LABEL" 2>&1 | grep -v "^error:" || true
    echo "[setup-pkcs11] ✓ ECC public key object imported"
fi

# Remove temporary key material immediately — do not leave private key on disk
rm -f "$ECC_PRIV_KEY_PEM" "$ECC_PUB_KEY_DER"
echo "[setup-pkcs11] ✓ Temporary ECC key files removed from disk"

# Confirm the objects are visible in the token
echo "[setup-pkcs11] ECC key objects now in token:"
pkcs11-tool --module "$PKCS11_MODULE" --slot "$SLOT" \
    --login --pin "$USER_PIN" --list-objects 2>/dev/null | \
    grep -A3 -E "(Private Key|Public Key)" | grep -E "(ID|label|$ECC_KEY_LABEL)" || true

##########################################################################
# STEP 5b: Generate build-system ECC P-256 peer key → /etc/ssadaemon/cal_1.bin
#
# pkcs11_hal_derive_ecdh() in rdktrusthal-cpc reads BUILD_PUB_KEY_PATH
# (/etc/ssadaemon/cal_1.bin) via d2i_PUBKEY_bio(), which expects a
# SubjectPublicKeyInfo (SPKI) DER-encoded public key.
# This is a separate key pair from the device key above (PRIVATE_KEY_ID=11).
# The private half is discarded; only the public key is needed for ECDH.
##########################################################################

echo ""
echo "[setup-pkcs11] === Generating build-system ECC P-256 peer key (cal_1.bin) ==="

PEER_PRIV_TMP="/tmp/ssa_peer_ecc_priv_$$.pem"
SSA_DAEMON_DIR="/etc/ssadaemon"
CAL1_BIN="${SSA_DAEMON_DIR}/cal_1.bin"

# Ensure the ssadaemon directory exists with appropriate permissions
mkdir -p "$SSA_DAEMON_DIR"
chmod 750 "$SSA_DAEMON_DIR"

# Generate the peer (build-system) ECC P-256 key pair
echo "[setup-pkcs11] Generating test-only build-system ECC P-256 key pair..."
if ! openssl genpkey -algorithm EC \
        -pkeyopt ec_paramgen_curve:P-256 \
        -out "$PEER_PRIV_TMP" 2>/dev/null; then
    echo "[setup-pkcs11] ERROR: Failed to generate peer ECC P-256 key"
    exit 1
fi

# Export the public key in SubjectPublicKeyInfo DER format → cal_1.bin
# d2i_PUBKEY_bio() in pkcs11_api.c requires SPKI DER (not raw EC point, not PEM).
if ! openssl pkey -in "$PEER_PRIV_TMP" \
        -pubout -outform DER \
        -out "$CAL1_BIN" 2>/dev/null; then
    echo "[setup-pkcs11] ERROR: Failed to export peer public key to $CAL1_BIN"
    rm -f "$PEER_PRIV_TMP"
    exit 1
fi

# Discard the private key immediately — only the public key is needed
rm -f "$PEER_PRIV_TMP"

echo "[setup-pkcs11] ✓ cal_1.bin written to $CAL1_BIN ($(wc -c < "$CAL1_BIN") bytes, SPKI DER)"

##########################################################################
# STEP 5c: Update slotid in hrothardware.cfg with the real SoftHSM slot
#
# pkcs11_config_load() reads slotid as a decimal integer.  The SoftHSM
# slot number is dynamic; STEP 4 wrote slotid=0 as a placeholder.
##########################################################################

HROT_CFG="/etc/ssl/certsel/pkcs11/hrothardware.cfg"
if [ -f "$HROT_CFG" ]; then
    sed -i "s/^slotid=.*/slotid=${SLOT}/" "$HROT_CFG"
    echo "[setup-pkcs11] ✓ hrothardware.cfg updated: slotid=${SLOT}"
else
    echo "[setup-pkcs11] WARNING: $HROT_CFG not found; slotid not updated"
fi

echo ""
echo "[setup-pkcs11] ✓ PKCS#11 setup complete"
export PKCS11_PIN="$USER_PIN"
exit 0
