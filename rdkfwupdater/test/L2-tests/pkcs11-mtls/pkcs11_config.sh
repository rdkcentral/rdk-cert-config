#!/bin/bash

# ============================================================================
# PKCS#11 Configuration for rdkfwupdater L2 Tests
# ============================================================================
# This file configures PKCS#11 environment variables for testing rdkfwupdater
# mTLS connections with certificates stored in SoftHSM PKCS#11 token.
#
# Test Infrastructure:
# - SoftHSM2 provides PKCS#11 token (label: RDK_TOKEN, PIN: 1234)
# - Custom OpenSSL 3.0.5 with PKCS#11 patch at /usr/local/bin/openssl
# - Two certificate sets in token:
#   * ID 0x01: rdkclient (normal PKCS#11 test)
#   * ID 0x2c: rdkclient-p12 (reference P12 patch test)
# ============================================================================

# PKCS#11 Token Configuration
export PKCS11_MODULE_PATH="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_TOKEN_LABEL="RDK_TOKEN"
export PKCS11_TOKEN_PIN="1234"

# Custom OpenSSL with PKCS#11 Support
export OPENSSL_BIN="/usr/local/bin/openssl"
export PATH="/usr/local/bin:$PATH"
export LD_LIBRARY_PATH="/usr/local/lib64:/usr/local/lib:$LD_LIBRARY_PATH"

# Certificate Files
export CA_CERT="/opt/certs/ca.pem"
export CLIENT_CERT="/opt/certs/client.pem"
export CLIENT_P12="/opt/certs/client.p12"
export REFERENCE_P12="/opt/certs/reference.p12"
export P12_PASSWORD="changeit"

# rdkfwupdater-specific Test Endpoints
# These match the mockxconf ports used in L2-tests.yml workflow
export MOCKXCONF_HOST="mockxconf"

# Port 50050: T2 DCM Settings (log uploader)
export DCM_SETTINGS_URL="https://${MOCKXCONF_HOST}:50050/loguploader/getT2DCMSettings"

# Port 50051: Data Lake Mock
export DATALAKE_URL="https://${MOCKXCONF_HOST}:50051/datalake/upload"

# Port 50052: XConf Firmware Update (primary rdkfwupdater endpoint)
export XCONF_FIRMWARE_URL="https://${MOCKXCONF_HOST}:50052/firmwareupdate/getfirmwaredata"

# PKCS#11 URIs for Certificate Access
# These URIs allow OpenSSL to access certificates in the PKCS#11 token
# Format: pkcs11:token=<label>;object=<cert_label>;type=cert?pin-value=<pin>

# Normal PKCS#11 certificate (ID 0x01)
export PKCS11_CERT_URI="pkcs11:token=${PKCS11_TOKEN_LABEL};object=rdkclient;type=cert?pin-value=${PKCS11_TOKEN_PIN}"

# P12 patch certificate (ID 0x2c)
export PKCS11_P12_CERT_URI="pkcs11:token=${PKCS11_TOKEN_LABEL};object=rdkclient-p12;type=cert?pin-value=${PKCS11_TOKEN_PIN}"

# Verify PKCS#11 Infrastructure (optional validation)
verify_pkcs11_setup() {
    local errors=0
    
    echo "Verifying PKCS#11 test environment..."
    
    # Check OpenSSL version
    if [ ! -x "$OPENSSL_BIN" ]; then
        echo "✗ ERROR: Custom OpenSSL not found at $OPENSSL_BIN"
        errors=$((errors + 1))
    else
        local version=$($OPENSSL_BIN version)
        if [[ ! "$version" =~ "OpenSSL 3.0.5" ]]; then
            echo "✗ WARNING: Expected OpenSSL 3.0.5, found: $version"
        fi
    fi
    
    # Check PKCS#11 module
    if [ ! -f "$PKCS11_MODULE_PATH" ]; then
        echo "✗ ERROR: PKCS#11 module not found at $PKCS11_MODULE_PATH"
        errors=$((errors + 1))
    fi
    
    # Check CA certificate
    if [ ! -f "$CA_CERT" ]; then
        echo "✗ ERROR: CA certificate not found at $CA_CERT"
        errors=$((errors + 1))
    fi
    
    # Check reference P12
    if [ ! -f "$REFERENCE_P12" ]; then
        echo "✗ ERROR: Reference P12 not found at $REFERENCE_P12"
        errors=$((errors + 1))
    fi
    
    if [ $errors -eq 0 ]; then
        echo "✓ PKCS#11 environment verified"
        return 0
    else
        echo "✗ PKCS#11 environment validation failed ($errors errors)"
        return 1
    fi
}

# Optional: Auto-verify on source (can be disabled if needed)
# Uncomment the line below to enable automatic verification
# verify_pkcs11_setup
