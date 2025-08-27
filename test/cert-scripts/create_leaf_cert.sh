#!/bin/bash
# Leaf Certificate creation script for PKI infrastructure
# Usage: create_leaf_cert.sh --cert-name <CERT_NAME> --ca-name <CA_NAME> [OPTIONS]
#
# This script creates a leaf certificate signed by a Certificate Authority (CA).
#
# Options:
#   --cert-name <n>      Name of the certificate to create (required)
#   --ca-name <n>        Name of the CA to sign with (required)
#   --type <TYPE>           Certificate type: 'server' or 'client' (default: client)
#   --validity <DAYS>       Validity period in days (default: 365)
#   --ecc-curve <CURVE>     ECC curve to use (default: prime256v1)
#                           Options: prime256v1 (P-256), secp384r1 (P-384), secp521r1 (P-521)
#   --expired               Generate an expired certificate
#   --corrupted             Generate a corrupted certificate
#   --revoked               Generate a revoked certificate
#   --key-mismatch          Generate a certificate with mismatched private key
#   --no-password           Generate a P12 file with no password
#   --wrong-password        Generate a P12 file with incorrect password
#   --missing-cert          Simulate a missing certificate file
#   --help                  Display this help message

# Import utility functions
source "$(dirname "$0")/cert_utils.sh"

# Helper function to get the correct path for a CA
get_ca_path() {
  local name=$1
  local path=""

  # Check if this is a root CA or exists directly under CERT_DIR
  if [ -d "${CERT_DIR}/${name}" ]; then
    # Validate that this is actually a CA directory
    if [ -f "${CERT_DIR}/${name}/certs/${name}.pem" ]; then
      path="${CERT_DIR}/${name}"
    fi
  else
    # Try to find CA by checking for cert file
    local found=false
    for dir in $(find "${CERT_DIR}" -type d -name "${name}" 2>/dev/null); do
      if [ -f "${dir}/certs/${name}.pem" ]; then
        path="${dir}"
        found=true
        break
      fi
    done

    # No valid path found, but directory exists at root level, try that as a fallback
    if [ "${found}" != "true" ] && [ -d "${CERT_DIR}/${name}" ]; then
      path="${CERT_DIR}/${name}"
    fi
  fi

  # Check if we found a valid CA path
  if [ -z "${path}" ] || [ ! -d "${path}" ] || [ ! -f "${path}/certs/${name}.pem" ] || [ ! -f "${path}/private/${name}.key" ]; then
    echo "Error: Could not find a valid CA directory for ${name}" >&2
    echo "Make sure the CA exists and has a valid certificate at \${CERT_DIR}/[path]/${name}/certs/${name}.pem" >&2
    echo "and a valid private key at \${CERT_DIR}/[path]/${name}/private/${name}.key" >&2
    return 1
  fi

  echo "${path}"
  return 0
}

# Default values
CERT_NAME=""
CA_NAME=""
PARENT_CA=""  # Will be determined later if needed
CERT_TYPE="client"
ECC_CURVE="prime256v1"
VALIDITY=365
FAILURE_MODE=""
CERT_PASSWORD="changeit"

# Parse command line arguments
parse_args() {
  if [ $# -eq 0 ]; then
    echo "Error: Missing required arguments"
    show_help
    exit 1
  fi

  while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
      --cert-name)
        CERT_NAME="$2"
        shift 2
        ;;
      --ca-name)
        CA_NAME="$2"
        shift 2
        ;;
      --type)
        if [ "$2" = "server" ] || [ "$2" = "client" ]; then
          CERT_TYPE="$2"
        else
          echo "Error: Invalid certificate type. Use 'server' or 'client'"
          exit 1
        fi
        shift 2
        ;;
      --validity)
        VALIDITY="$2"
        shift 2
        ;;
      --ecc-curve)
        case "$2" in
          p256|prime256v1)
            ECC_CURVE="prime256v1"
            ;;
          p384|secp384r1)
            ECC_CURVE="secp384r1"
            ;;
          p521|secp521r1)
            ECC_CURVE="secp521r1"
            ;;
          *)
            echo "Error: Invalid ECC curve specified"
            echo "Valid options: prime256v1, secp384r1, secp521r1"
            exit 1
            ;;
        esac
        shift 2
        ;;
      --expired)
        VALIDITY="-365"
        FAILURE_MODE="expired"
        echo "Setting certificate to be expired..."
        shift
        ;;
      --corrupted)
        FAILURE_MODE="corrupted"
        echo "Certificate will be corrupted after creation..."
        shift
        ;;
      --revoked)
        FAILURE_MODE="revoked"
        echo "Certificate will be revoked after creation..."
        shift
        ;;
      --key-mismatch)
        FAILURE_MODE="key-mismatch"
        echo "Certificate will have mismatched key..."
        shift
        ;;
      --no-password)
        FAILURE_MODE="no-password"
        CERT_PASSWORD=""
        echo "P12 file will have no password..."
        shift
        ;;
      --wrong-password)
        FAILURE_MODE="wrong-password"
        CERT_PASSWORD="incorrect-password"
        echo "P12 file will have incorrect password..."
        shift
        ;;
      --missing-cert)
        FAILURE_MODE="missing-cert"
        echo "Will simulate missing certificate file..."
        shift
        ;;
      --help)
        show_help
        exit 0
        ;;
      *)
        echo "Unknown option: $1"
        show_help
        exit 1
        ;;
    esac
  done

  # Validate required parameters
  if [ -z "$CERT_NAME" ]; then
    echo "Error: Certificate name is required (--cert-name)"
    exit 1
  fi

  if [ -z "$CA_NAME" ]; then
    echo "Error: CA name is required (--ca-name)"
    exit 1
  fi
}

show_help() {
  cat << EOF
Usage: $0 --cert-name <CERT_NAME> --ca-name <CA_NAME> [OPTIONS]

This script creates a leaf certificate signed by a Certificate Authority (CA).

Options:
  --cert-name <n>      Name of the certificate to create (required)
  --ca-name <n>        Name of the CA to sign with (required)
  --type <TYPE>           Certificate type: 'server' or 'client' (default: client)
  --validity <DAYS>       Validity period in days (default: 365)
  --ecc-curve <CURVE>     ECC curve to use (default: prime256v1)
                          Options: prime256v1 (P-256), secp384r1 (P-384), secp521r1 (P-521)
  --expired               Generate an expired certificate
  --corrupted             Generate a corrupted certificate
  --revoked               Generate a revoked certificate
  --key-mismatch          Generate a certificate with mismatched private key
  --no-password           Generate a P12 file with no password
  --wrong-password        Generate a P12 file with incorrect password
  --missing-cert          Simulate a missing certificate file
  --help                  Display this help message

Examples:
  # Create a standard client certificate
  $0 --cert-name "client-cert" --ca-name "Intermediate-CA"

  # Create a server certificate
  $0 --cert-name "server-cert" --ca-name "Intermediate-CA" --type server

  # Create an expired client certificate
  $0 --cert-name "expired-client-cert" --ca-name "Intermediate-CA" --expired
EOF
}

# Setup certificate directories
setup_cert_dirs() {
  local ca_path=$1

  echo "Using existing CA directories for ${CERT_NAME} under ${CA_NAME} at ${ca_path}..."

  # Create csr directory if it doesn't exist
  if [ ! -d "${ca_path}/csr" ]; then
    echo "Creating CSR directory at ${ca_path}/csr"
    mkdir -p "${ca_path}/csr"

    # Check if directory creation was successful
    if [ ! -d "${ca_path}/csr" ]; then
      echo "Error: Failed to create CSR directory at ${ca_path}/csr"
      echo "Please check filesystem permissions and try again."
      exit 1
    fi
  fi
}

# Main function to generate leaf certificate
generate_leaf_cert() {
  local ca_path=$1

  # Create OpenSSL config file if it doesn't exist
  create_openssl_config

  # Determine which extensions section to use (server or client)
  local cert_extensions="${CERT_TYPE}_cert"

  # Generate certificate key
  if [ "${FAILURE_MODE}" = "key-mismatch" ]; then
    # Generate a mismatched key (different curve)
    local mismatch_curve="secp521r1"
    if [ "${ECC_CURVE}" = "secp521r1" ]; then
      mismatch_curve="prime256v1"
    fi
    generate_private_key "${CERT_NAME}" "${ca_path}/private" "${mismatch_curve}"
  else
    generate_private_key "${CERT_NAME}" "${ca_path}/private" "${ECC_CURVE}"
  fi

  # Create CSR
  create_csr "${CERT_NAME}" \
    "${CERT_DIR}/openssl.cnf" \
    "${ca_path}/private/${CERT_NAME}.key" \
    "${ca_path}/csr/${CERT_NAME}.csr" \
    "${CERT_NAME}"

  # Check if CSR creation was successful
  if [ $? -ne 0 ]; then
    echo "Error: Failed to create CSR for ${CERT_NAME}."
    echo "Please check that the private key exists and is valid at ${ca_path}/private/${CERT_NAME}.key"
    exit 1
  fi

  # Sign the CSR with the CA
  sign_certificate "${CERT_TYPE}" \
    "${ca_path}/csr/${CERT_NAME}.csr" \
    "${ca_path}/certs/${CA_NAME}.pem" \
    "${ca_path}/private/${CA_NAME}.key" \
    "${CERT_DIR}/openssl.cnf" \
    "${ca_path}/certs/${CERT_NAME}.pem" \
    "${VALIDITY}" \
    "${cert_extensions}"

    # Check if certificate signing was successful
    if [ $? -ne 0 ]; then
      echo "Error: Certificate signing failed for ${CERT_NAME}."
      echo "Please check the CA certificate and private key at ${ca_path}."
      exit 1
    fi

  # Check for CA chain file or create a simple chain
  local chain_file="${ca_path}/${CA_NAME}_chain.pem"

  if [ ! -f "${chain_file}" ]; then
    echo "CA chain file not found at ${chain_file}"
    echo "Creating a simple chain with the CA certificate"
    chain_file="${ca_path}/certs/${CA_NAME}.pem"
  fi

  # Create PKCS#12 keystore
  create_pkcs12 \
    "${ca_path}/certs/${CERT_NAME}.pem" \
    "${ca_path}/private/${CERT_NAME}.key" \
    "${chain_file}" \
    "${ca_path}/certs/${CERT_NAME}.p12" \
    "${CERT_PASSWORD}" \
    "${CERT_NAME}"

  # Check if PKCS#12 creation was successful
  if [ $? -ne 0 ]; then
    echo "Error: Failed to create PKCS#12 file for ${CERT_NAME}."
    echo "Please check that all required files exist and are valid."
    exit 1
  fi

  echo "Leaf certificate created at ${ca_path}/certs/${CERT_NAME}.pem"
  echo "Private key created at ${ca_path}/private/${CERT_NAME}.key"
  echo "PKCS#12 file created at ${ca_path}/certs/${CERT_NAME}.p12"

  # Handle failure modes if specified
  if [ "${FAILURE_MODE}" = "corrupted" ]; then
    corrupt_certificate "${ca_path}/certs/${CERT_NAME}.pem"
  elif [ "${FAILURE_MODE}" = "revoked" ]; then
    # Make sure the CRL directory exists
    if [ ! -d "${ca_path}/crl" ]; then
      echo "Creating CRL directory at ${ca_path}/crl"
      mkdir -p "${ca_path}/crl"
    fi

    revoke_certificate \
      "${ca_path}/certs/${CERT_NAME}.pem" \
      "${ca_path}/certs/${CA_NAME}.pem" \
      "${ca_path}/private/${CA_NAME}.key" \
      "${CERT_DIR}/openssl.cnf" \
      "${ca_path}/crl/${CERT_NAME}.crl"
  elif [ "${FAILURE_MODE}" = "missing-cert" ]; then
    # Create a backup then remove
    cp "${ca_path}/certs/${CERT_NAME}.pem" "${ca_path}/certs/${CERT_NAME}.pem.bak"
    rm -f "${ca_path}/certs/${CERT_NAME}.pem"
    echo "Certificate deliberately removed (backup saved as ${CERT_NAME}.pem.bak)"
  fi

  # Create a README for the certificate
  create_leaf_readme "${ca_path}"
}

# Create a README file for the certificate
create_leaf_readme() {
  local ca_path=$1

  # Create README file
  cat > "${ca_path}/certs/README_${CERT_NAME}.txt" << EOF
${CERT_NAME} - ${CERT_TYPE} Certificate
===============================

Certificate type: ${CERT_TYPE}
Signed by: ${CA_NAME}
Key type: ECC (${ECC_CURVE})
Validity: ${VALIDITY} days

Files:
-----
- certs/${CERT_NAME}.pem: The certificate
- private/${CERT_NAME}.key: The private key (sensitive!)
- csr/${CERT_NAME}.csr: The Certificate Signing Request
- certs/${CERT_NAME}.p12: PKCS#12 file containing certificate and private key with CA chain

Certificate Path:
---------------
${ca_path}/certs/${CERT_NAME}.pem

Private Key Path:
--------------
${ca_path}/private/${CERT_NAME}.key

PKCS#12 File:
-----------
${ca_path}/certs/${CERT_NAME}.p12
EOF

  if [ ! -z "${FAILURE_MODE}" ]; then
    cat >> "${ca_path}/certs/README_${CERT_NAME}.txt" << EOF

ATTENTION: This certificate has been deliberately ${FAILURE_MODE} for testing purposes.
EOF
  fi

  if [ ! -z "${CERT_PASSWORD}" ]; then
    cat >> "${ca_path}/certs/README_${CERT_NAME}.txt" << EOF

PKCS#12 Password: ${CERT_PASSWORD}
EOF
  else
    cat >> "${ca_path}/certs/README_${CERT_NAME}.txt" << EOF

PKCS#12 Password: [Empty password]
EOF
  fi
}

# Main function
main() {
  # Parse arguments
  parse_args "$@"

  # Determine the CA path once
  local ca_path=$(get_ca_path "${CA_NAME}")

  # Check if get_ca_path succeeded
  if [ $? -ne 0 ] || [ -z "${ca_path}" ]; then
    echo "Error: Failed to determine a valid path for CA '${CA_NAME}'"
    echo "Please make sure the CA exists and has the expected directory structure."
    exit 1
  fi

  echo "Using CA path: ${ca_path}"

  # Create certificate directory structure
  setup_cert_dirs "${ca_path}"

  # Generate leaf certificate
  generate_leaf_cert "${ca_path}"

  echo "Certificate generation complete."

  # Display certificate details if OpenSSL is available
  if command -v openssl &>/dev/null; then
    echo "------------------------------"
    echo "Certificate details:"
    echo "------------------------------"
    openssl x509 -in "${ca_path}/certs/${CERT_NAME}.pem" -text -noout | grep -E "Subject:|Issuer:|Validity|Public Key"
    echo "------------------------------"
  fi

  echo "Certificate available at ${ca_path}/certs/${CERT_NAME}.pem"
}

# Run the script
main "$@"
