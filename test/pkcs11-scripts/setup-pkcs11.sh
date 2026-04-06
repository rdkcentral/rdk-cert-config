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

# PKCS#11 Object ID Allocation (configurable)
MTLS_CERT_ID="${MTLS_CERT_ID:-01}"        # mTLS client certificate
MTLS_P12_KEY_ID="${MTLS_P12_KEY_ID:-02}"  # mTLS P12 private key (also used by OpenSSL patch for operational cert)
SEED_CERT_ID="${SEED_CERT_ID:-03}"        # xPKI seed certificate
OPC_PRIV_ID="${OPC_PRIV_ID:-02}"          # xPKI operational certificate private key (matches OpenSSL patch)

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
        # Import with object ID 0x${MTLS_CERT_ID} (standard mTLS)
        echo "[setup-pkcs11] Importing client certificate (object ID 0x${MTLS_CERT_ID}) to slot $SLOT..."
        
        if ! pkcs11-tool --module "$PKCS11_MODULE" \
            --slot "$SLOT" \
            --login --pin "$USER_PIN" \
            --write-object "$CLIENT_CERT" \
            --type cert \
            --id $MTLS_CERT_ID \
            --label "rdkclient" 2>&1; then
            if pkcs11-tool --module "$PKCS11_MODULE" --slot "$SLOT" --login --pin "$USER_PIN" --list-objects 2>/dev/null | grep -q "ID: 01"; then
                echo "  (object with ID 01 already exists)"
            else
                echo "[setup-pkcs11] ERROR: Failed to import client certificate"
                exit 1
            fi
        fi
        
        if ! pkcs11-tool --module "$PKCS11_MODULE" \
            --slot "$SLOT" \
            --login --pin "$USER_PIN" \
            --write-object "$CLIENT_KEY" \
            --type privkey \
            --id $MTLS_CERT_ID \
            --label "rdkclient-key" 2>&1; then
            if pkcs11-tool --module "$PKCS11_MODULE" --slot "$SLOT" --login --pin "$USER_PIN" --list-objects 2>/dev/null | grep -q "ID: 01"; then
                echo "  (object with ID 01 already exists)"
            else
                echo "[setup-pkcs11] ERROR: Failed to import client private key"
                exit 1
            fi
        fi
        
        echo "[setup-pkcs11] ✓ Client certificate imported (object ID 0x01 in slot $SLOT)"
        
        # Import with object ID 0x02 (PKCS#11 patch testing - production mode)
        if [ -f "$CERT_DIR/reference.p12" ]; then
            echo "[setup-pkcs11] Importing keys (object ID 0x02) to slot $SLOT (PRODUCTION MODE - keys only)..."
            
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
            
            # Import private key (with --extractable for USE_ACTUAL_KEYS support)
            if ! pkcs11-tool --module "$PKCS11_MODULE" \
                --slot "$SLOT" \
                --login --pin "$USER_PIN" \
                --write-object "$CLIENT_KEY" \
                --type privkey \
                --id $MTLS_P12_KEY_ID \
                --extractable \
                --label "rdkclient-p12-key" 2>&1; then
                if pkcs11-tool --module "$PKCS11_MODULE" --slot "$SLOT" --login --pin "$USER_PIN" --list-objects 2>/dev/null | grep -q "ID: 02"; then
                    echo "  (object with ID 02 already exists)"
                else
                    echo "[setup-pkcs11] ERROR: Failed to import private key to object ID 02"
                    exit 1
                fi
            fi
            
            # Import public key
            if ! pkcs11-tool --module "$PKCS11_MODULE" \
                --slot "$SLOT" \
                --login --pin "$USER_PIN" \
                --write-object /tmp/client-pubkey.der \
                --type pubkey \
                --id $MTLS_P12_KEY_ID \
                --label "rdkclient-p12-pubkey" 2>&1; then
                if pkcs11-tool --module "$PKCS11_MODULE" --slot "$SLOT" --login --pin "$USER_PIN" --list-objects 2>/dev/null | grep -q "ID: $MTLS_P12_KEY_ID"; then
                    echo "  (object with ID $MTLS_P12_KEY_ID already exists)"
                else
                    echo "[setup-pkcs11] ERROR: Failed to import public key to object ID $MTLS_P12_KEY_ID"
                    exit 1
                fi
            fi
            
            echo "[setup-pkcs11] ✓ Keys imported (object ID 0x02 in slot $SLOT - PRODUCTION MODE)"
            echo "[setup-pkcs11]   • Private key at ID 0x02: YES"
            echo "[setup-pkcs11]   • Public key at ID 0x02:  YES"
            echo "[setup-pkcs11]   • Certificate at ID 0x02: NO (from P12 file)"
            
            rm -f /tmp/client-pubkey.pem /tmp/client-pubkey.der
        fi
        
        # Cleanup temp files
        [ "$CLEANUP_TEMP" = true ] && rm -f "$CLIENT_CERT" "$CLIENT_KEY"
        
        # Import xPKI seed certificate with object ID 0x03 (if available)
        SEED_CERT_DIR="/mnt/L2_CONTAINER_SHARED_VOLUME/shared_certs/client"
        if [ -f "$SEED_CERT_DIR/seed-cert.pem" ] && [ -f "$SEED_CERT_DIR/seed-cert.key" ]; then
            echo "[setup-pkcs11] Importing xPKI seed certificate (object ID 0x03) to slot $SLOT..."
            
            if ! pkcs11-tool --module "$PKCS11_MODULE" \
                --slot "$SLOT" \
                --login --pin "$USER_PIN" \
                --write-object "$SEED_CERT_DIR/seed-cert.pem" \
                --type cert \
                --id $SEED_CERT_ID \
                --label "xpki-seed" 2>&1; then
                if pkcs11-tool --module "$PKCS11_MODULE" --slot "$SLOT" --login --pin "$USER_PIN" --list-objects 2>/dev/null | grep -q "ID: $SEED_CERT_ID"; then
                    echo "  (object with ID $SEED_CERT_ID already exists)"
                else
                    echo "[setup-pkcs11] ERROR: Failed to import xPKI seed certificate"
                    exit 1
                fi
            fi
            
            if ! pkcs11-tool --module "$PKCS11_MODULE" \
                --slot "$SLOT" \
                --login --pin "$USER_PIN" \
                --write-object "$SEED_CERT_DIR/seed-cert.key" \
                --type privkey \
                --id $SEED_CERT_ID \
                --extractable \
                --label "xpki-seed-key" 2>&1; then
                if pkcs11-tool --module "$PKCS11_MODULE" --slot "$SLOT" --login --pin "$USER_PIN" --list-objects 2>/dev/null | grep -q "ID: $SEED_CERT_ID"; then
                    echo "  (object with ID $SEED_CERT_ID already exists)"
                else
                    echo "[setup-pkcs11] ERROR: Failed to import xPKI seed private key"
                    exit 1
                fi
            fi
            
            echo "[setup-pkcs11] ✓ xPKI seed certificate imported (object ID 0x03 in slot $SLOT)"
            
            # Create pkcs11seedref.pk12 (production equivalent) for libcertifier
            # This file is what libcertifier expects as input_p12_path parameter
            mkdir -p /opt/certs
            [ -n "$DEBUG_PKCS11" ] && echo "[setup-pkcs11] DEBUG: Creating /opt/certs/pkcs11seedref.pk12 (mimics production)..."
            [ -n "$DEBUG_PKCS11" ] && echo "[setup-pkcs11] DEBUG: Seed cert path: $SEED_CERT_DIR/seed-cert.pem"
            [ -n "$DEBUG_PKCS11" ] && echo "[setup-pkcs11] DEBUG: Seed key path: $SEED_CERT_DIR/seed-cert.key"
            
            # Save current umask and set restrictive umask before creating P12 with private key
            OLD_UMASK=$(umask)
            umask 077
            if openssl pkcs12 -export \
                -in "$SEED_CERT_DIR/seed-cert.pem" \
                -inkey "$SEED_CERT_DIR/seed-cert.key" \
                -out /opt/certs/pkcs11seedref.pk12 \
                -passout pass:changeit \
                -name "pkcs11-seed" 2>/dev/null; then
                
                # Ensure file has restrictive permissions
                chmod 0600 /opt/certs/pkcs11seedref.pk12
                echo "[setup-pkcs11] ✓ /opt/certs/pkcs11seedref.pk12 created (permissions: 0600)"
                
                if [ -n "$DEBUG_PKCS11" ]; then
                    echo "[setup-pkcs11] DEBUG: P12 file details:"
                    ls -lh /opt/certs/pkcs11seedref.pk12
                    echo "[setup-pkcs11] DEBUG: P12 file verification:"
                    openssl pkcs12 -in /opt/certs/pkcs11seedref.pk12 -passin pass:changeit -noout -info 2>&1 || echo "  (verification may fail, but file exists)"
                fi
                echo "[setup-pkcs11]   This file mimics production's pre-provisioned seed P12"
            else
                echo "[setup-pkcs11] ERROR: Failed to create /opt/certs/pkcs11seedref.pk12"
                umask "$OLD_UMASK"  # Restore umask even on failure
                exit 1
            fi
            # Restore original umask
            umask "$OLD_UMASK"
        else
            echo "[setup-pkcs11] ⚠ xPKI seed certificate not found, skipping object ID 0x03"
        fi
        
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
# STEP 4: Create libcertifier Configuration
##########################################################################

echo ""
echo "[setup-pkcs11] === Creating libcertifier configuration ==="

# Get certifier URL from environment or use default
CERTIFIER_URL="${CERTIFIER_URL:-https://mockxconf:50055/v1/certifier}"

mkdir -p /etc/certifier
cat > /etc/certifier/libcertifier.cfg << CERTIFIER_CFG_EOF
{
  "libcertifier.certifier.url": "${CERTIFIER_URL}",
  "libcertifier.ca.info": "/etc/ssl/certs/ca-certificates.crt",
  "libcertifier.profile.name": "RDK_Device_Issuing_ECC_ICA",
  "libcertifier.validity.days": 365,
  "libcertifier.auth.type": "X509",
  "libcertifier.ecc.curve.id": "prime256v1",
  "libcertifier.http.connect.timeout": 15,
  "libcertifier.http.timeout": 15,
  "libcertifier.http.trace": 0,
  "libcertifier.input.p12.path": "seed.p12",
  "libcertifier.input.p12.password": "changeit",
  "libcertifier.log.file": "/opt/logs/libcertifier.log",
  "libcertifier.log.level": 4,
  "libcertifier.log.max.size": 5000000,
  "libcertifier.autorenew.interval": 86400,
  "libcertifier.autorenew.certs.path.list": "~/.libcertifier:~/.libcertifier2",
  "libcertifier.measure.performance": 0,
  "libcertifier.source.id": "RDK-GENERIC-libcertifier",
  "libcertifier.certificate.lite": 0,
  "libcertifier.system.id":"74:06:35:06:DF:6A:ES13SCU2416000C1",
  "libcertifier.fabric.id":"DDDDDDDDDDDDDDDD",
  "libcertifier.product.id":"1101",
  "libcertifier.cn.name":"rdk.device",
  "libcertifier.node.id":"CCCCCCCCCCCCCCCC",
  "libcertifier.ext.key.usage":"critical,clientAuth,serverAuth"
}
CERTIFIER_CFG_EOF

if [ -f /etc/certifier/libcertifier.cfg ]; then
    echo "[setup-pkcs11] ✓ libcertifier configuration created at /etc/certifier/libcertifier.cfg"
    echo "[setup-pkcs11]   • Certifier URL: ${CERTIFIER_URL}"
else
    echo "[setup-pkcs11] ERROR: Failed to create libcertifier configuration"
    exit 1
fi

##########################################################################
# STEP 5: Create hrot.properties for CertSelector
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

cat > /etc/ssl/certsel/pkcs11/hrothardware.cfg << HWEOF
# PKCS#11 Object ID Allocation for CI Environment (in token slot ${SLOT}):
#   Object ID 0x${MTLS_CERT_ID}: mTLS client cert (rdkclient)
#   Object ID 0x${MTLS_P12_KEY_ID}: mTLS P12 keys (rdkclient-p12) + xPKI operational key (OpenSSL patch)
#   Object ID 0x${SEED_CERT_ID}: xPKI seed certificate (xpki-seed)
#   Note: OPC_PRIV_ID=2 matches MTLS_P12_KEY_ID because OpenSSL patch hardcodes ID 02

slotid=${SLOT}
SEED_CERT_ID=${SEED_CERT_ID}
OPC_PRIV_ID=${OPC_PRIV_ID}
HWEOF

echo "[setup-pkcs11] ✓ hrot configuration created:"
echo "[setup-pkcs11]   • Token slot: $SLOT"
echo "[setup-pkcs11]   • Seed cert object ID: 0x$SEED_CERT_ID"
echo "[setup-pkcs11]   • Operational cert object ID: 0x$OPC_PRIV_ID"

echo ""
echo "[setup-pkcs11] ✓ PKCS#11 setup complete"
export PKCS11_PIN="$USER_PIN"
exit 0
