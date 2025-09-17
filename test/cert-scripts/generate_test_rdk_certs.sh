#!/bin/bash
# Certificate generation script for PKI infrastructure with support for various failure scenarios
# Usage: generate_test_rdk_certs.sh --type <TYPE> [OPTION]
#  Required:
#    --type <TYPE>          Certificate type: must be "server" or "client"
#
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

# Get the directory where this script is located
SCRIPT_DIR="$(dirname "$0")"

# Import utility functions
source "${SCRIPT_DIR}/cert_utils.sh"

# Default values
FAILURE_MODE=""
CERT_PASSWORD="changeit"
ECC_CURVE="prime256v1" # Default is P-256
CERT_TYPE=""           # Must be specified as "server" or "client"
ROOT_CA_OPTIONS=""     # Options for root CA creation
ICA_OPTIONS=""         # Options for intermediate CA creation
LEAF_CERT_OPTIONS=""   # Options for leaf certificate creation

# Function to show help message
show_help() {
  cat << EOF
Usage: $0 --type <TYPE> [OPTIONS]

This script generates RDK test certificates by creating a complete chain:
- Root CA
- Intermediate CA (based on specified type)
- Leaf Certificate (based on specified type)

It uses the create_ca.sh and create_leaf_cert.sh scripts to do this.

Required:
  --type <TYPE>           Certificate type: must be "server" or "client"

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
    echo "Error: Missing required arguments"
    show_help
    exit 1
  fi

  # Check for help flag first
  for arg in "$@"; do
    if [ "$arg" == "--help" ]; then
      show_help
      exit 0
    fi
  done

  # Process all arguments to find the type parameter
  for arg in "$@"; do
    if [ "$arg" == "--type" ]; then
      TYPE_ARG=true
      break
    fi
  done

  if [ -z "$TYPE_ARG" ]; then
    echo "Error: Missing required --type argument"
    show_help
    exit 1
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --type)
        if [[ "$2" == "server" || "$2" == "client" ]]; then
          CERT_TYPE="$2"
          shift 2
        else
          echo "Error: Invalid certificate type. Must be 'server' or 'client'."
          show_help
          exit 1
        fi
        ;;
      --expired-cert)
      FAILURE_MODE="expired-cert"
      LEAF_CERT_OPTIONS="--expired"
      echo "Generating expired leaf certificate..."
      ;;
    --expired-intermediate)
      FAILURE_MODE="expired-intermediate"
      ICA_OPTIONS="--expired"
      echo "Generating expired intermediate CA..."
      ;;
    --expired-root)
      FAILURE_MODE="expired-root"
      ROOT_CA_OPTIONS="--expired"
      echo "Generating expired root CA..."
      ;;
    --corrupted-cert)
      FAILURE_MODE="corrupted-cert"
      LEAF_CERT_OPTIONS="--corrupted"
      echo "Generating corrupted leaf certificate..."
      ;;
    --corrupted-intermediate)
      FAILURE_MODE="corrupted-intermediate"
      ICA_OPTIONS="--corrupted"
      echo "Generating corrupted intermediate CA..."
      ;;
    --corrupted-root)
      FAILURE_MODE="corrupted-root"
      ROOT_CA_OPTIONS="--corrupted"
      echo "Generating corrupted root CA..."
      ;;
    --revoked-cert)
      FAILURE_MODE="revoked-cert"
      LEAF_CERT_OPTIONS="--revoked"
      echo "Generating revoked leaf certificate..."
      ;;
    --revoked-intermediate)
      FAILURE_MODE="revoked-intermediate"
      ICA_OPTIONS="--revoked"
      echo "Generating revoked intermediate CA..."
      ;;
    --revoked-root)
      FAILURE_MODE="revoked-root"
      # We don't set ROOT_CA_OPTIONS because root CA revocation is not implemented
      echo "Generating revoked root CA..."
      ;;
    --untrusted-root)
      FAILURE_MODE="untrusted-root"
      echo "Generating untrusted root CA..."
      ;;
    --missing-cert)
      FAILURE_MODE="missing-cert"
      LEAF_CERT_OPTIONS="--missing-cert"
      echo "Simulating missing certificate file..."
      ;;
    --cert-key-mismatch)
      FAILURE_MODE="cert-key-mismatch"
      LEAF_CERT_OPTIONS="--key-mismatch"
      echo "Generating certificate with mismatched private key..."
      ;;
    --missing-passcode)
      FAILURE_MODE="missing-passcode"
      CERT_PASSWORD=""
      LEAF_CERT_OPTIONS="--no-password"
      echo "Generating P12 file with no password..."
      ;;
    --wrong-passcode)
      FAILURE_MODE="wrong-passcode"
      CERT_PASSWORD="incorrect-password"
      LEAF_CERT_OPTIONS="--wrong-password"
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
  done

  # After parsing all arguments, check if type was provided
  if [ -z "$CERT_TYPE" ]; then
    echo "Error: Certificate type must be specified with --type option"
    show_help
    exit 1
  fi
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
  if [ ! -f "${SCRIPT_DIR}/create_ca.sh" ] || [ ! -f "${SCRIPT_DIR}/create_leaf_cert.sh" ]; then
    echo "ERROR: Required scripts create_ca.sh or create_leaf_cert.sh not found."
    echo "Make sure you're running this script from the same directory as those scripts."
    exit 1
  fi

  # Make scripts executable
  chmod +x "${SCRIPT_DIR}/create_ca.sh" "${SCRIPT_DIR}/create_leaf_cert.sh"

  # Generate Root CA
  if [ "$FAILURE_MODE" = "untrusted-root" ]; then
    # Create an untrusted root with a different name
    "${SCRIPT_DIR}/create_ca.sh" --ca-name "Test-RDK-root-untrusted" --parent-ca "Test-RDK-root-untrusted" --ecc-curve "$ECC_CURVE"
    # Also create the standard root for other certificates
    "${SCRIPT_DIR}/create_ca.sh" --ca-name "Test-RDK-root" --parent-ca "Test-RDK-root" --ecc-curve "$ECC_CURVE"
  else
    "${SCRIPT_DIR}/create_ca.sh" --ca-name "Test-RDK-root" --parent-ca "Test-RDK-root" --ecc-curve "$ECC_CURVE" $ROOT_CA_OPTIONS
  fi

  # Generate Intermediate CA based on type
  ICA_NAME="Test-RDK-${CERT_TYPE}-ICA"
  echo "Generating ${CERT_TYPE} Intermediate CA..."

  "${SCRIPT_DIR}/create_ca.sh" --ca-name "${ICA_NAME}" --parent-ca "Test-RDK-root" --ecc-curve "$ECC_CURVE" $ICA_OPTIONS

  if [ "$FAILURE_MODE" = "revoked-intermediate" ]; then
    echo "Note: Intermediate CA revocation implemented - CRL files can be found in the parent CA's crl directory"
  elif [ "$FAILURE_MODE" = "revoked-root" ]; then
    echo "Warning: Root CA revocation is not implemented as it requires removing from trust stores"
    echo "The --revoked-root option has no effect on certificate generation"
  fi

  # Generate Leaf Certificate based on type
  CERT_NAME="test-rdk-${CERT_TYPE}-cert"
  echo "Generating ${CERT_TYPE} certificate..."

  # Single call to create_leaf_cert.sh with the appropriate options
  "${SCRIPT_DIR}/create_leaf_cert.sh" --cert-name "${CERT_NAME}" --ca-name "${ICA_NAME}" --type "${CERT_TYPE}" --ecc-curve "$ECC_CURVE" $LEAF_CERT_OPTIONS
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
      # Copy certificate files
      cp ${CERT_DIR}/${ICA_NAME}/certs/${CERT_NAME}/* ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/ 2>/dev/null || true
      ;;
    expired-intermediate|revoked-intermediate|corrupted-intermediate)
      # Copy intermediate CA and chain
      cp ${CERT_DIR}/${ICA_NAME}/certs/${ICA_NAME}.pem ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/ 2>/dev/null || true
      cp ${CERT_DIR}/${ICA_NAME}/${ICA_NAME}_chain.pem ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/ 2>/dev/null || true
      ;;
    expired-root|revoked-root|corrupted-root)
      # Copy root CA
      cp ${CERT_DIR}/Test-RDK-root/certs/Test-RDK-root.pem ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/ 2>/dev/null || true
      # Copy chain if it exists
      if [ -f "${CERT_DIR}/${ICA_NAME}/certs/${CERT_NAME}/fullchain.pem" ]; then
        cp ${CERT_DIR}/${ICA_NAME}/certs/${CERT_NAME}/fullchain.pem ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/${CERT_TYPE}-chain.pem 2>/dev/null || true
      fi
      ;;
    untrusted-root)
      # Copy untrusted root
      cp ${CERT_DIR}/Test-RDK-root-untrusted/certs/Test-RDK-root-untrusted.pem ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/Test-RDK-root.pem 2>/dev/null || true
      ;;
  esac

  echo "Test scenario certificates for ${FAILURE_MODE} available at ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/"
}

# Print certificate information (replacing README file creation)
print_certificate_info() {
  echo ""
  echo "Certificate Information:"
  echo "========================"
  echo "Key Type: ECC with ${ECC_CURVE} curve"
  echo ""
  echo "Certificate Structure:"
  echo "- Root CA: Test-RDK-root"
  echo "- ${CERT_TYPE^} Intermediate CA: ${ICA_NAME} (signed by Root CA)"
  echo "  └── ${CERT_TYPE^} Certificate: ${CERT_NAME}"
  echo ""

  if [ ! -z "$FAILURE_MODE" ]; then
    echo "Test scenario: ${FAILURE_MODE}"
    echo "Test scenario files are available at: ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}/"
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

  # Print certificate information
  #print_certificate_info

  # Set appropriate permissions
  chmod -R 644 ${CERT_DIR}/certs/*.pem ${CERT_DIR}/certs/*.p12 2>/dev/null || true
  chmod -R 640 ${CERT_DIR}/certs/*.key 2>/dev/null || true

  # Print a summary
  echo ""
  echo_t "Certificate generation complete."
  echo_t "Root CA: ${CERT_DIR}/Test-RDK-root/certs/Test-RDK-root.pem"
  echo_t "${CERT_TYPE^} Intermediate CA: ${CERT_DIR}/${ICA_NAME}/certs/${ICA_NAME}.pem"
  echo_t "${CERT_TYPE^} Certificate: ${CERT_DIR}/${ICA_NAME}/certs/${CERT_NAME}.pem"
  echo_t "${CERT_TYPE^} Key: ${CERT_DIR}/${ICA_NAME}/private/${CERT_NAME}.key"

  if [ ! -z "$FAILURE_MODE" ]; then
    echo_t ""
    echo_t "Test scenario: ${FAILURE_MODE}"
    echo_t "Test certificates copied to: ${CERT_DIR}/certs/test-scenarios/${FAILURE_MODE}"
  fi

  echo_t "For more information, see the README.md file at: ${SCRIPT_DIR}/README.md"
}

# Run the script
main "$@"
