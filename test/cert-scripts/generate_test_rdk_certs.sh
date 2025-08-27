#!/bin/bash
# Certificate generation script for PKI infrastructure with support for various failure scenarios
# Usage: generate_test_rdk_certs.sh [OPTION]
#  Options:
#    --expired-cert          Generate a leaf certificate that is already expired
#    --expired-intermediate  Generate an expired intermediate CA
#    --expired-root          Generate an expired root CA
#    --corrupted-cert        Generate a corrupted leaf certificate
#    --corrupted-intermediate Generate a corrupted intermediate CA
#    --corrupted-root        Generate a corrupted root CA
#    --revoked-cert          Generate a revoked leaf certificate
#    --revoked-intermediate  Generate a revoked intermediate CA
#    --revoked-root          Generate a revoked root CA
#    --untrusted-root        Generate a root CA that won't be in the trust store
#    --missing-cert          Simulate a missing certificate file
#    --cert-key-mismatch     Generate a certificate with mismatched private key
#    --missing-passcode      Generate a P12 file with no password
#    --wrong-passcode        Generate a P12 file with a different password than expected
#    --ecc-p384             Use ECC curve P-384 (default is P-256)
#    --ecc-p521             Use ECC curve P-521 (default is P-256)
#    --help                  Display this help message

# Import utility functions
source "$(dirname "$0")/cert_utils.sh"

# Default values
FAILURE_MODE=""
CERT_PASSWORD="changeit"
ECC_CURVE="prime256v1" # Default is P-256

# Function to show help message
show_help() {
  cat << EOF
Usage: $0 [OPTIONS]

This script generates RDK test certificates by creating a complete chain:
- Root CA
- Server Intermediate CA
- Client Intermediate CA 
- Server Certificate
- Client Certificate

It uses the create_ca.sh and create_leaf_cert.sh scripts to do this.

Options:
  --expired-cert          Generate a leaf certificate that is already expired
  --expired-intermediate  Generate an expired intermediate CA
  --expired-root          Generate an expired root CA
  --corrupted-cert        Generate a corrupted leaf certificate
  --corrupted-intermediate Generate a corrupted intermediate CA
  --corrupted-root        Generate a corrupted root CA
  --revoked-cert          Generate a revoked leaf certificate
  --revoked-intermediate  Generate a revoked intermediate CA
  --revoked-root          Generate a revoked root CA
  --untrusted-root        Generate a root CA that won't be in the trust store
  --missing-cert          Simulate a missing certificate file
  --cert-key-mismatch     Generate a certificate with mismatched private key
  --missing-passcode      Generate a P12 file with no password
  --wrong-passcode        Generate a P12 file with a different password than expected
  --ecc-p384             Use ECC curve P-384 (default is P-256)
  --ecc-p521             Use ECC curve P-521 (default is P-256)
  --help                  Display this help message
EOF
}

# Parse command line arguments
parse_args() {
  if [ $# -eq 0 ]; then
    echo "Generating standard certificates..."
    return
  fi

  case "$1" in
    --expired-cert)
      FAILURE_MODE="expired-cert"
      echo "Generating expired leaf certificate..."
      ;;
    --expired-intermediate)
      FAILURE_MODE="expired-intermediate"
      echo "Generating expired intermediate CA..."
      ;;
    --expired-root)
      FAILURE_MODE="expired-root"
      echo "Generating expired root CA..."
      ;;
    --corrupted-cert)
      FAILURE_MODE="corrupted-cert"
      echo "Generating corrupted leaf certificate..."
      ;;
    --corrupted-intermediate)
      FAILURE_MODE="corrupted-intermediate"
      echo "Generating corrupted intermediate CA..."
      ;;
    --corrupted-root)
      FAILURE_MODE="corrupted-root"
      echo "Generating corrupted root CA..."
      ;;
    --revoked-cert)
      FAILURE_MODE="revoked-cert"
      echo "Generating revoked leaf certificate..."
      ;;
    --revoked-intermediate)
      FAILURE_MODE="revoked-intermediate"
      echo "Generating revoked intermediate CA..."
      ;;
    --revoked-root)
      FAILURE_MODE="revoked-root"
      echo "Generating revoked root CA..."
      ;;
    --untrusted-root)
      FAILURE_MODE="untrusted-root"
      echo "Generating untrusted root CA..."
      ;;
    --missing-cert)
      FAILURE_MODE="missing-cert"
      echo "Simulating missing certificate file..."
      ;;
    --cert-key-mismatch)
      FAILURE_MODE="cert-key-mismatch"
      echo "Generating certificate with mismatched private key..."
      ;;
    --missing-passcode)
      FAILURE_MODE="missing-passcode"
      CERT_PASSWORD=""
      echo "Generating P12 file with no password..."
      ;;
    --wrong-passcode)
      FAILURE_MODE="wrong-passcode"
      CERT_PASSWORD="incorrect-password"
      echo "Generating P12 file with incorrect password..."
      ;;
    --ecc-p384)
      ECC_CURVE="secp384r1"
      echo "Using ECC curve P-384..."
      ;;
    --ecc-p521)
      ECC_CURVE="secp521r1"
      echo "Using ECC curve P-521..."
      ;;
    --help)
      show_help
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
}

# Setup basic directory structure
setup_dirs() {
  echo "Setting up certificate directories..."
  mkdir -p "${CERT_DIR}/certs"
  mkdir -p "${CERT_DIR}/private"
  mkdir -p "${CERT_DIR}/crl"

  # Create directory for test scenarios
  if [ ! -z "$FAILURE_MODE" ]; then
    mkdir -p "${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}"
  fi
}

# Generate all certificates
generate_certificates() {
  # Check if required scripts exist
  if [ ! -f "$(dirname "$0")/create_ca.sh" ] || [ ! -f "$(dirname "$0")/create_leaf_cert.sh" ]; then
    echo "ERROR: Required scripts create_ca.sh or create_leaf_cert.sh not found."
    echo "Make sure you're running this script from the same directory as those scripts."
    exit 1
  fi

  # Make scripts executable
  chmod +x "$(dirname "$0")/create_ca.sh" "$(dirname "$0")/create_leaf_cert.sh"

  # Generate Root CA
  if [ "$FAILURE_MODE" = "expired-root" ]; then
    "$(dirname "$0")/create_ca.sh" --ca-name "Test-RDK-root" --parent-ca "Test-RDK-root" --ecc-curve "$ECC_CURVE" --expired
  elif [ "$FAILURE_MODE" = "corrupted-root" ]; then
    "$(dirname "$0")/create_ca.sh" --ca-name "Test-RDK-root" --parent-ca "Test-RDK-root" --ecc-curve "$ECC_CURVE" --corrupted
  elif [ "$FAILURE_MODE" = "untrusted-root" ]; then
    # Create an untrusted root with a different name
    "$(dirname "$0")/create_ca.sh" --ca-name "Test-RDK-root-untrusted" --parent-ca "Test-RDK-root-untrusted" --ecc-curve "$ECC_CURVE"
    # Also create the standard root for other certificates
    "$(dirname "$0")/create_ca.sh" --ca-name "Test-RDK-root" --parent-ca "Test-RDK-root" --ecc-curve "$ECC_CURVE"
  else
    "$(dirname "$0")/create_ca.sh" --ca-name "Test-RDK-root" --parent-ca "Test-RDK-root" --ecc-curve "$ECC_CURVE"
  fi

  # Generate Server Intermediate CA
  "$(dirname "$0")/create_ca.sh" --ca-name "Test-RDK-server-ICA" --parent-ca "Test-RDK-root" --ecc-curve "$ECC_CURVE"

  # Generate Client Intermediate CA
  if [ "$FAILURE_MODE" = "expired-intermediate" ]; then
    "$(dirname "$0")/create_ca.sh" --ca-name "Test-RDK-client-ICA" --parent-ca "Test-RDK-root" --ecc-curve "$ECC_CURVE" --expired
  elif [ "$FAILURE_MODE" = "corrupted-intermediate" ]; then
    "$(dirname "$0")/create_ca.sh" --ca-name "Test-RDK-client-ICA" --parent-ca "Test-RDK-root" --ecc-curve "$ECC_CURVE" --corrupted
  elif [ "$FAILURE_MODE" = "revoked-intermediate" ]; then
    "$(dirname "$0")/create_ca.sh" --ca-name "Test-RDK-client-ICA" --parent-ca "Test-RDK-root" --ecc-curve "$ECC_CURVE"
    # TODO: Implement revocation for CAs
  else
    "$(dirname "$0")/create_ca.sh" --ca-name "Test-RDK-client-ICA" --parent-ca "Test-RDK-root" --ecc-curve "$ECC_CURVE"
  fi

  # Generate Server Certificate
  "$(dirname "$0")/create_leaf_cert.sh" --cert-name "test-rdk-server-cert" --ca-name "Test-RDK-server-ICA" --type server --ecc-curve "$ECC_CURVE"

  # Generate Client Certificate
  if [ "$FAILURE_MODE" = "expired-cert" ]; then
    "$(dirname "$0")/create_leaf_cert.sh" --cert-name "test-rdk-client-cert" --ca-name "Test-RDK-client-ICA" --type client --expired --ecc-curve "$ECC_CURVE"
  elif [ "$FAILURE_MODE" = "corrupted-cert" ]; then
    "$(dirname "$0")/create_leaf_cert.sh" --cert-name "test-rdk-client-cert" --ca-name "Test-RDK-client-ICA" --type client --corrupted --ecc-curve "$ECC_CURVE"
  elif [ "$FAILURE_MODE" = "revoked-cert" ]; then
    "$(dirname "$0")/create_leaf_cert.sh" --cert-name "test-rdk-client-cert" --ca-name "Test-RDK-client-ICA" --type client --revoked --ecc-curve "$ECC_CURVE"
  elif [ "$FAILURE_MODE" = "cert-key-mismatch" ]; then
    "$(dirname "$0")/create_leaf_cert.sh" --cert-name "test-rdk-client-cert" --ca-name "Test-RDK-client-ICA" --type client --key-mismatch --ecc-curve "$ECC_CURVE"
  elif [ "$FAILURE_MODE" = "missing-cert" ]; then
    "$(dirname "$0")/create_leaf_cert.sh" --cert-name "test-rdk-client-cert" --ca-name "Test-RDK-client-ICA" --type client --missing-cert --ecc-curve "$ECC_CURVE"
  elif [ "$FAILURE_MODE" = "missing-passcode" ]; then
    "$(dirname "$0")/create_leaf_cert.sh" --cert-name "test-rdk-client-cert" --ca-name "Test-RDK-client-ICA" --type client --no-password --ecc-curve "$ECC_CURVE"
  elif [ "$FAILURE_MODE" = "wrong-passcode" ]; then
    "$(dirname "$0")/create_leaf_cert.sh" --cert-name "test-rdk-client-cert" --ca-name "Test-RDK-client-ICA" --type client --wrong-password --ecc-curve "$ECC_CURVE"
  else
    "$(dirname "$0")/create_leaf_cert.sh" --cert-name "test-rdk-client-cert" --ca-name "Test-RDK-client-ICA" --type client --ecc-curve "$ECC_CURVE"
  fi
}

# Copy files to test scenarios directory if needed
setup_test_scenarios() {
  if [ -z "$FAILURE_MODE" ]; then
    return
  fi

  echo "Setting up test scenarios directory for ${FAILURE_MODE}..."
  mkdir -p "${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}"

  case "$FAILURE_MODE" in
    expired-cert|revoked-cert|corrupted-cert|cert-key-mismatch|missing-cert|missing-passcode|wrong-passcode)
      # Copy client certificate files
      cp ${CERT_DIR}/Test-RDK-client-ICA/certs/test-rdk-client-cert/* ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/ 2>/dev/null || true
      ;;
    expired-intermediate|revoked-intermediate|corrupted-intermediate)
      # Copy intermediate CA and chain
      cp ${CERT_DIR}/Test-RDK-client-ICA/certs/Test-RDK-client-ICA.pem ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/ 2>/dev/null || true
      cp ${CERT_DIR}/Test-RDK-client-ICA/certs/chain.pem ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/ 2>/dev/null || true
      ;;
    expired-root|revoked-root|corrupted-root)
      # Copy root CA
      cp ${CERT_DIR}/Test-RDK-root/certs/Test-RDK-root.pem ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/ 2>/dev/null || true
      # Copy chain if it exists
      if [ -f "${CERT_DIR}/Test-RDK-client-ICA/certs/test-rdk-client-cert/fullchain.pem" ]; then
        cp ${CERT_DIR}/Test-RDK-client-ICA/certs/test-rdk-client-cert/fullchain.pem ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/client-chain.pem 2>/dev/null || true
      fi
      ;;
    untrusted-root)
      # Copy untrusted root
      cp ${CERT_DIR}/Test-RDK-root-untrusted/certs/Test-RDK-root-untrusted.pem ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/Test-RDK-root.pem 2>/dev/null || true
      ;;
  esac

  echo "Test scenario certificates for ${FAILURE_MODE} available at ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/"
}

# Create a README file with certificate information
create_main_readme() {
  cat > "${CERT_DIR}/README.txt" << EOF
RDK Test Certificate Environment
===============================

This directory contains certificates for testing various PKI scenarios.

Key Type: ECC with ${ECC_CURVE} curve

Certificate Structure:
--------------------
- Root CA: Test-RDK-root
- Server Intermediate CA: Test-RDK-server-ICA (signed by Root CA)
  └── Server Certificate: test-rdk-server-cert
- Client Intermediate CA: Test-RDK-client-ICA (signed by Root CA)
  └── Client Certificate: test-rdk-client-cert

Certificates are organized hierarchically with each CA containing its issued certificates:
- Root CA directory contains its own certificates and configuration
- Intermediate CAs directories each contain:
  - Their own certificates and private keys
  - Certificates they've issued (in the certs/ subdirectory)
- Each leaf certificate is stored under its issuing CA's directory

For details on specific certificates, see the README.txt in each directory.

ECC Curve Information:
--------------------
- Current curve: ${ECC_CURVE}
- P-256 (prime256v1): 256-bit elliptic curve
- P-384 (secp384r1): 384-bit elliptic curve
- P-521 (secp521r1): 521-bit elliptic curve
EOF

  if [ ! -z "$FAILURE_MODE" ]; then
    echo -e "\nCurrent test scenario: ${FAILURE_MODE}" >> "${CERT_DIR}/README.txt"
    echo "Test scenario files are available at: ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/" >> "${CERT_DIR}/README.txt"
  fi
}

# Main function
main() {
  # Parse arguments
  parse_args "$@"

  # Setup directories
  setup_dirs

  # Generate certificates
  generate_certificates

  # Setup test scenarios if needed
  setup_test_scenarios

  # Create main README
  create_main_readme

  # Set appropriate permissions
  chmod -R 644 ${CERT_DIR}/certs/*.pem ${CERT_DIR}/certs/*.p12 2>/dev/null || true
  chmod -R 640 ${CERT_DIR}/certs/*.key 2>/dev/null || true

  echo "Certificate generation complete. See ${CERT_DIR}/README.txt for details."
}

# Run the script
main "$@"
