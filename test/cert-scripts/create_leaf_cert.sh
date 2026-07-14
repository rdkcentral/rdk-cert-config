#!/bin/bash
##########################################################################
# Copyright 2025 Comcast Cable Communications Management, LLC
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
#
# SPDX-License-Identifier: Apache-2.0
##########################################################################
# Leaf Certificate creation script for PKI infrastructure
# Usage: create_leaf_cert.sh --cert-name <CERT_NAME> --ca-name <CA_NAME> [OPTIONS]
#
# This script creates a leaf certificate signed by a Certificate Authority (CA).
# Options:
#   --cert-name <n>      Name of the certificate to create (required)
#   --ca-name <n>        Name of the CA to sign with (required)
#   --cn <COMMON_NAME>      Common Name for certificates
#   --type <TYPE>           Certificate type: 'server' or 'client' (default: client)
#   --validity <DAYS>       Validity period in days (default: 1)
#   --key-type <TYPE>       Key type: 'rsa' or 'ecc' (auto-selected based on cert type if not specified)
#   --key-size <SIZE>       RSA key size in bits or ECC curve name (default depends on key type: RSA: 2048, ECC: prime256v1)
#                           Options: prime256v1 (P-256), secp384r1 (P-384), secp521r1 (P-521)
#   --expired               Generate an expired certificate
#   --corrupted             Generate a corrupted certificate
#   --revoked               Generate a revoked certificate
#   --key-mismatch          Generate a certificate with mismatched private key
#   --no-password           Generate a P12 file with no password
#   --wrong-password        Generate a P12 file with incorrect password
#   --missing-cert          Simulate a missing certificate file
#   --ca-track              Sign via 'openssl ca' (tracked in CA DB for revocation)
#   --san <SAN>             Subject Alternative Name (e.g. DNS:mockxconf)
#   --eku <EKU>             Extended Key Usage (serverAuth|clientAuth|OCSPSigning)
#   --aia <URI>             Authority Information Access OCSP responder URI
#   --no-p12                Skip PKCS#12 (.p12) bundle generation
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
    while IFS= read -r -d '' dir; do
      if [ -f "${dir}/certs/${name}.pem" ]; then
        path="${dir}"
        found=true
        break
      fi
    done < <(find "${CERT_DIR}" -type d -name "${name}" -print0 2>/dev/null)

    # No valid path found, but directory exists at root level, try that as a fallback
    if [ "${found}" != "true" ] && [ -d "${CERT_DIR}/${name}" ]; then
      path="${CERT_DIR}/${name}"
    fi
  fi

  # Check if we found a valid CA path
  if [ -z "${path}" ] || [ ! -d "${path}" ] || [ ! -f "${path}/certs/${name}.pem" ] || [ ! -f "${path}/private/${name}.key" ]; then
    echo_a "Error: Could not find a valid CA directory for ${name}" >&2
    echo_t "Make sure the CA exists and has a valid certificate at \${CERT_DIR}/[path]/${name}/certs/${name}.pem" >&2
    echo_t "and a valid private key at \${CERT_DIR}/[path]/${name}/private/${name}.key" >&2
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
KEY_TYPE=""     # Auto-selected based on --type when not specified (server→RSA, client→ECC)
VALIDITY=1
FAILURE_MODE=""
CERT_PASSWORD="changeit"
COMMON_NAME=""  # CN parameter for certificate
CA_TRACK=""     # When set, sign via openssl ca (tracked in CA DB for revocation)
SAN_VALUE=""    # Custom SAN (e.g., DNS:mockxconf)
EKU_VALUE=""    # Custom EKU (serverAuth|clientAuth|OCSPSigning)
AIA_VALUE=""    # Authority Information Access OCSP URI
NO_P12=""       # Skip P12 generation

# Parse command line arguments
parse_args() {
  if [ $# -eq 0 ]; then
    echo_a "Error: Missing required arguments"
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
      --cn)
        COMMON_NAME="$2"
        shift 2
        ;;
      --type)
        if [ "$2" = "server" ] || [ "$2" = "client" ]; then
          CERT_TYPE="$2"
        else
          echo_a "Error: Invalid certificate type. Use 'server' or 'client'"
          exit 1
        fi
        shift 2
        ;;
      --validity)
        VALIDITY="$2"
        shift 2
        ;;
      --key-type)
        if [[ "$2" == "rsa" || "$2" == "ecc" ]]; then
          KEY_TYPE="$2"
        else
          echo_a "Error: Invalid key type. Must be 'rsa' or 'ecc'"
          exit 1
        fi
        shift 2
        ;;
      --key-size)
        KEY_SIZE="$2"
        shift 2
        ;;
      --expired)
        VALIDITY="-1"  # -1 is the minimum value OpenSSL accepts
        FAILURE_MODE="expired"
        echo_t "Setting certificate to be expired (backdated by 1 day)..."
        shift
        ;;
      --corrupted)
        FAILURE_MODE="corrupted"
        echo_t "Certificate will be corrupted after creation..."
        shift
        ;;
      --revoked)
        FAILURE_MODE="revoked"
        echo_t "Certificate will be revoked after creation..."
        shift
        ;;
      --key-mismatch)
        FAILURE_MODE="key-mismatch"
        echo_t "Certificate will have mismatched key..."
        shift
        ;;
      --no-password)
        FAILURE_MODE="no-password"
        CERT_PASSWORD=""
        echo_t "P12 file will have no password..."
        shift
        ;;
      --wrong-password)
        FAILURE_MODE="wrong-password"
        CERT_PASSWORD="incorrect-password"
        echo_t "P12 file will have incorrect password..."
        shift
        ;;
      --missing-cert)
        FAILURE_MODE="missing-cert"
        echo_t "Will simulate missing certificate file..."
        shift
        ;;
      --ca-track)
        CA_TRACK="true"
        echo_t "Certificate will be tracked in CA database..."
        shift
        ;;
      --san)
        SAN_VALUE="$2"
        shift 2
        ;;
      --eku)
        EKU_VALUE="$2"
        shift 2
        ;;
      --aia)
        AIA_VALUE="$2"
        shift 2
        ;;
      --no-p12)
        NO_P12="true"
        shift
        ;;
      --help)
        show_help
        exit 0
        ;;
      *)
        echo_t "Unknown option: $1"
        show_help
        exit 1
        ;;
    esac
  done

  # Validate required parameters
  if [ -z "$CERT_NAME" ]; then
    echo_a "Error: Certificate name is required (--cert-name)"
    exit 1
  fi

  if [ -z "$CA_NAME" ]; then
    echo_a "Error: CA name is required (--ca-name)"
    exit 1
  fi

  if [ -z "$COMMON_NAME" ]; then
    echo_a "Error: Common Name is required (--cn)"
    exit 1
  fi

  # Auto-select key type based on cert type if not explicitly specified
  if [ -z "$KEY_TYPE" ]; then
    if [ "$CERT_TYPE" = "server" ]; then
      KEY_TYPE="rsa"
    else
      KEY_TYPE="ecc"
    fi
    echo_t "Auto-selected key type: ${KEY_TYPE} (based on --type ${CERT_TYPE})"
  fi

  if [ -z "$KEY_SIZE" ]; then
      if [ "$KEY_TYPE" == "ecc" ]; then
          KEY_SIZE="prime256v1"   # Default ECC curve
      elif [ "$KEY_TYPE" == "rsa" ]; then
          KEY_SIZE="2048"         # Default RSA key size
      else
          echo_a "Error: Invalid key type"
          exit 1
      fi
  fi
}

show_help() {
  cat << EOF
Usage: $0 --cert-name <CERT_NAME> --ca-name <CA_NAME> [OPTIONS]

This script creates a leaf certificate signed by a Certificate Authority (CA).

Options:
  --cert-name <n>      Name of the certificate to create (required)
  --ca-name <n>        Name of the CA to sign with (required)
  --cn <COMMON_NAME>      Common Name for certificate (required for server certificates)
  --type <TYPE>           Certificate type: 'server' or 'client' (default: client)
  --validity <DAYS>       Validity period in days (default: 1)
  --key-type <TYPE>       Key type: 'rsa' or 'ecc' (auto-selected: server→RSA, client→ECC)
  --key-size <SIZE>       RSA key size in bits or ECC curve name (default depends on key type: RSA: 2048, ECC: prime256v1)
  --expired               Generate an expired certificate
  --corrupted             Generate a corrupted certificate
  --revoked               Generate a revoked certificate
  --key-mismatch          Generate a certificate with mismatched private key
  --no-password           Generate a P12 file with no password
  --wrong-password        Generate a P12 file with incorrect password
  --missing-cert          Simulate a missing certificate file
  --ca-track              Sign via 'openssl ca' so the cert is tracked in the CA
                          database (enables later revocation)
  --san <SAN>             Subject Alternative Name (e.g. DNS:mockxconf)
  --eku <EKU>             Extended Key Usage (serverAuth|clientAuth|OCSPSigning)
  --aia <URI>             Authority Information Access OCSP responder URI
  --no-p12                Skip PKCS#12 (.p12) bundle generation
  --help                  Display this help message

Examples:
  # Create a standard client certificate
  $0 --cert-name "client-cert" --ca-name "Intermediate-CA"

  # Create a server certificate
  $0 --cert-name "server-cert" --ca-name "Intermediate-CA" --type server --cn "example.com"

  # Create an expired client certificate
  $0 --cert-name "expired-client-cert" --ca-name "Intermediate-CA" --expired
EOF
}

# Setup certificate directories
setup_cert_dirs() {
  local ca_path=$1

  echo_t "Using existing CA directories for ${CERT_NAME} under ${CA_NAME} at ${ca_path}..."

  # Create csr directory if it doesn't exist
  if [ ! -d "${ca_path}/csr" ]; then
    echo_t "Creating CSR directory at ${ca_path}/csr"
    mkdir -p "${ca_path}/csr"

    # Check if directory creation was successful
    if [ ! -d "${ca_path}/csr" ]; then
      echo_a "Error: Failed to create CSR directory at ${ca_path}/csr"
      echo_t "Please check filesystem permissions and try again."
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

  # Generate certificate key using specified parameters
  if [ "${FAILURE_MODE}" = "key-mismatch" ]; then
    # Generate a mismatched key (opposite type)
    if [ "${KEY_TYPE}" = "rsa" ]; then
      # Should use RSA, so mismatch with ECC
      generate_private_key "${CERT_NAME}" "${ca_path}/private" "prime256v1" "ecc"
    else
      # Should use ECC, so mismatch with RSA
      generate_private_key "${CERT_NAME}" "${ca_path}/private" "2048" "rsa"
    fi
  else
    # Normal key generation using specified parameters
    generate_private_key "${CERT_NAME}" "${ca_path}/private" "${KEY_SIZE}" "${KEY_TYPE}"
  fi

  # Create CSR
  create_csr "${CERT_NAME}" \
    "${CERT_DIR}/openssl.cnf" \
    "${ca_path}/private/${CERT_NAME}.key" \
    "${ca_path}/csr/${CERT_NAME}.csr" \
    "${COMMON_NAME}" \
    "${CERT_TYPE}"

  # Check if CSR creation was successful
  if [ $? -ne 0 ]; then
    echo_a "Error: Failed to create CSR for ${CERT_NAME}."
    echo_t "Please check that the private key exists and is valid at ${ca_path}/private/${CERT_NAME}.key"
    exit 1
  fi

  # Sign the CSR with the CA
  if [ "${CA_TRACK}" = "true" ]; then
    # Sign via openssl ca — cert tracked in CA database for live revocation
    sign_certificate_tracked "${ca_path}" "${CA_NAME}" \
      "${ca_path}/csr/${CERT_NAME}.csr" \
      "${ca_path}/certs/${CERT_NAME}.pem" \
      "${VALIDITY}" "${CERT_TYPE}" "${SAN_VALUE}" "${EKU_VALUE}" "${AIA_VALUE}"
  else
    sign_certificate "${CERT_TYPE}" \
      "${ca_path}/csr/${CERT_NAME}.csr" \
      "${ca_path}/certs/${CA_NAME}.pem" \
      "${ca_path}/private/${CA_NAME}.key" \
      "${CERT_DIR}/openssl.cnf" \
      "${ca_path}/certs/${CERT_NAME}.pem" \
      "${VALIDITY}" \
      "${cert_extensions}"
  fi

    # Check if certificate signing was successful
    if [ $? -ne 0 ]; then
      echo_a "Error: Certificate signing failed for ${CERT_NAME}."
      echo_t "Please check the CA certificate and private key at ${ca_path}."
      exit 1
    fi

  # Check for CA chain file or create a simple chain
  local chain_file="${ca_path}/${CA_NAME}_chain.pem"

  if [ ! -f "${chain_file}" ]; then
    echo_t "CA chain file not found at ${chain_file}"
    echo_t "Creating a simple chain with the CA certificate"
    chain_file="${ca_path}/certs/${CA_NAME}.pem"
  fi

  # Create PKCS#12 keystore (skip if --no-p12)
  if [ "${NO_P12}" != "true" ]; then
    create_pkcs12 \
      "${ca_path}/certs/${CERT_NAME}.pem" \
      "${ca_path}/private/${CERT_NAME}.key" \
      "${chain_file}" \
      "${ca_path}/certs/${CERT_NAME}.p12" \
      "${CERT_PASSWORD}" \
      "${CERT_NAME}"

    # Check if PKCS#12 creation was successful
    if [ $? -ne 0 ]; then
      echo_a "Error: Failed to create PKCS#12 file for ${CERT_NAME}."
      echo_t "Please check that all required files exist and are valid."
      exit 1
    fi
  fi

  echo_t "Leaf certificate created at ${ca_path}/certs/${CERT_NAME}.pem"
  echo_t "Private key created at ${ca_path}/private/${CERT_NAME}.key"

  # Handle failure modes if specified
  if [ "${FAILURE_MODE}" = "corrupted" ]; then
    corrupt_certificate "${ca_path}/certs/${CERT_NAME}.pem"
  elif [ "${FAILURE_MODE}" = "revoked" ]; then
    # Make sure the CRL directory exists
    if [ ! -d "${ca_path}/crl" ]; then
      echo_t "Creating CRL directory at ${ca_path}/crl"
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
    echo_t "Certificate deliberately removed (backup saved as ${CERT_NAME}.pem.bak)"
  fi

  # Certificate generation completed
}



# Main function
main() {
  # Parse arguments
  parse_args "$@"

  # Determine the CA path once
  local ca_path=$(get_ca_path "${CA_NAME}")

  # Check if get_ca_path succeeded
  if [ $? -ne 0 ] || [ -z "${ca_path}" ]; then
    echo_a "Error: Failed to determine a valid path for CA '${CA_NAME}'"
    echo_t "Please make sure the CA exists and has the expected directory structure."
    exit 1
  fi

  echo_t "Using CA path: ${ca_path}"

  # Create certificate directory structure
  setup_cert_dirs "${ca_path}"

  # Generate leaf certificate
  generate_leaf_cert "${ca_path}"

  echo_t "Certificate generation complete."

  # Display certificate details
  echo_t "------------------------------"
  echo_t "Certificate details:"
  echo_t "------------------------------"
  local cert_details=$(openssl x509 -in "${ca_path}/certs/${CERT_NAME}.pem" -text -noout | grep -E "Subject:|Issuer:|Validity|Public Key")
  echo_t "${cert_details}"
  echo_t "------------------------------"
  echo_t "Certificate available at ${ca_path}/certs/${CERT_NAME}.pem"
}

# Run the script
main "$@"
