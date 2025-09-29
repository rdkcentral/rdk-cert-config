#!/bin/bash
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2025 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
# Certificate generation script for PKI infrastructure with support for various failure scenarios
# Usage: generate_test_rdk_certs.sh --type <TYPE> [OPTION]
#  Required:
#    --type <TYPE>          Certificate type: must be "server" or "client"
#    --cn <COMMON_NAME>     Common Name (CN) for the leaf certificate
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
#    --help                  Display this help message

# Get the directory where this script is located
SCRIPT_DIR="$(dirname "$0")"

# Import utility functions
source "${SCRIPT_DIR}/cert_utils.sh"

# Default values
FAILURE_MODE=""
CERT_PASSWORD="changeit"
CERT_TYPE=""           # Must be specified as "server" or "client"
COMMON_NAME=""         # Must be specified for the leaf certificate
KEY_TYPE=""            # Will be auto-selected based on cert type if not specified
KEY_SIZE=""            # Will be auto-selected based on key type if not specified
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
  --cn <COMMON_NAME>      Common Name (CN) for the leaf certificate

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
  --key-type <TYPE>       Key type: 'rsa' or 'ecc' (auto-selected based on cert type if not specified)
  --key-size <SIZE>       RSA key size in bits (default: 2048) or ECC curve name (default: prime256v1)
  --help                  Display this help message

Note: Server certificates default to RSA 2048-bit, client certificates default to ECC P-256
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

  # Process all arguments to find the required parameters
  TYPE_ARG=false
  CN_ARG=false

  for arg in "$@"; do
    if [ "$arg" == "--type" ]; then
      TYPE_ARG=true
    fi
    if [ "$arg" == "--cn" ]; then
      CN_ARG=true
    fi
  done

  if [ "$TYPE_ARG" != "true" ]; then
    echo "Error: Missing required --type argument"
    show_help
    exit 1
  fi

  if [ "$CN_ARG" != "true" ]; then
    echo "Error: Missing required --cn argument"
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
      --cn)
        if [ -n "$2" ]; then
          COMMON_NAME="$2"
          shift 2
        else
          echo "Error: Common Name (CN) value is required."
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
    --key-type)
      if [[ "$2" == "rsa" || "$2" == "ecc" ]]; then
        KEY_TYPE="$2"
        echo "Using key type: ${KEY_TYPE}"
        shift 2
      else
        echo "Error: Invalid key type. Must be 'rsa' or 'ecc'."
        exit 1
      fi
      ;;
    --key-size)
      KEY_SIZE="$2"
      echo "Using key size/curve: ${KEY_SIZE}"
      shift 2
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

  # Auto-select key type and size based on certificate type if not specified
  if [ -z "$KEY_TYPE" ]; then
    if [ "$CERT_TYPE" = "server" ]; then
      KEY_TYPE="rsa"
      echo "Auto-selected RSA key type for server certificate"
    else
      KEY_TYPE="ecc"
      echo "Auto-selected ECC key type for client certificate"
    fi
  fi

  if [ -z "$KEY_SIZE" ]; then
    if [ "$KEY_TYPE" = "rsa" ]; then
      KEY_SIZE="2048"
      echo "Auto-selected RSA key size: 2048 bits"
    else
      KEY_SIZE="prime256v1"
      echo "Auto-selected ECC curve: prime256v1"
    fi
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
  echo "DEBUG: KEY_TYPE='$KEY_TYPE', KEY_SIZE='$KEY_SIZE'"
  if [ "$FAILURE_MODE" = "untrusted-root" ]; then
    # Create an untrusted root with a different name
    "${SCRIPT_DIR}/create_ca.sh" --ca-name "Test-RDK-root-untrusted" --parent-ca "Test-RDK-root-untrusted" --key-type "$KEY_TYPE" --key-size "$KEY_SIZE"
    # Also create the standard root for other certificates
    "${SCRIPT_DIR}/create_ca.sh" --ca-name "Test-RDK-root" --parent-ca "Test-RDK-root" --key-type "$KEY_TYPE" --key-size "$KEY_SIZE"
  else
    "${SCRIPT_DIR}/create_ca.sh" --ca-name "Test-RDK-root" --parent-ca "Test-RDK-root" --key-type "$KEY_TYPE" --key-size "$KEY_SIZE" $ROOT_CA_OPTIONS
  fi

  # Generate Intermediate CA based on type
  ICA_NAME="Test-RDK-${CERT_TYPE}-ICA"
  echo "Generating ${CERT_TYPE} Intermediate CA..."

  "${SCRIPT_DIR}/create_ca.sh" --ca-name "${ICA_NAME}" --parent-ca "Test-RDK-root" --key-type "$KEY_TYPE" --key-size "$KEY_SIZE" $ICA_OPTIONS

  if [ "$FAILURE_MODE" = "revoked-intermediate" ]; then
    echo "Note: Intermediate CA revocation implemented - CRL files can be found in the parent CA's crl directory"
  elif [ "$FAILURE_MODE" = "revoked-root" ]; then
    echo "Warning: Root CA revocation is not implemented as it requires removing from trust stores"
    echo "The --revoked-root option has no effect on certificate generation"
  fi

  # Generate Leaf Certificate based on type - use CN as the certificate name
  CERT_NAME="${COMMON_NAME}"
  echo "Generating ${CERT_TYPE} certificate with name '${CERT_NAME}'..."

  # Single call to create_leaf_cert.sh with the appropriate options
  "${SCRIPT_DIR}/create_leaf_cert.sh" --cert-name "${CERT_NAME}" --ca-name "${ICA_NAME}" --type "${CERT_TYPE}" --key-type "${KEY_TYPE}" --key-size "${KEY_SIZE}" --cn "${COMMON_NAME}" $LEAF_CERT_OPTIONS
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
  if [ "$KEY_TYPE" = "rsa" ]; then
    echo "Key Type: RSA ${KEY_SIZE}-bit"
  else
    echo "Key Type: ECC with ${KEY_SIZE} curve"
  fi
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

  # Certificate generation completed
}

# Run the script
main "$@"
