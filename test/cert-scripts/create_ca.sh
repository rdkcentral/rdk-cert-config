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
# CA Certificate creation script for PKI infrastructure
# Usage: create_ca.sh --ca-name <CA_NAME> [--parent-ca <PARENT_CA>] [OPTIONS]
#
# This script creates a Certificate Authority certificate.
# If --ca-name and --parent-ca are the same, it creates a root CA (self-signed)
# If different, it creates an intermediate CA signed by the parent CA
#
# Options:
#   --ca-name <n>        Name of the CA to create (required)
#   --parent-ca <n>      Name of the parent CA to sign with (required)
#                           If same as --ca-name, creates a root CA
#   --pathlen <NUM>         Path length constraint (default: 5 for root, auto-calculated for intermediate)
#   --validity <DAYS>       Validity period in days (default: 3650)
#   --key-type <TYPE>       Key type: 'rsa' or 'ecc' (default: ecc)
#   --key-size <SIZE>       RSA key size in bits (default: 2048) or ECC curve name (default: prime256v1)
#   --expired               Generate an expired CA certificate
#   --corrupted             Generate a corrupted CA certificate
#   --revoked               Generate a revoked CA certificate
#   --help                  Display this help message

# Import utility functions
source "$(dirname "$0")/cert_utils.sh"

# Default values
CA_NAME=""
PARENT_CA=""
KEY_TYPE="ecc"           # Default to ECC for CAs
KEY_SIZE="prime256v1"   # Default ECC curve
VALIDITY=1
PATHLEN=""
FAILURE_MODE=""

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
      --ca-name)
        CA_NAME="$2"
        shift 2
        ;;
      --parent-ca)
        PARENT_CA="$2"
        shift 2
        ;;
      --pathlen)
        PATHLEN="$2"
        shift 2
        ;;
      --validity)
        VALIDITY="$2"
        shift 2
        ;;
      --key-type)
        if [[ "$2" == "rsa" || "$2" == "ecc" ]]; then
          KEY_TYPE="$2"
          shift 2
        else
          echo_a "Error: Invalid key type. Must be 'rsa' or 'ecc'."
          exit 1
        fi
        ;;
      --key-size)
        KEY_SIZE="$2"
        shift 2
        ;;
      --expired)
        VALIDITY="-1"  # -1 is the minimum value OpenSSL accepts
        echo_t "Setting CA to be expired (backdated by 1 day)..."
        FAILURE_MODE="expired"
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
  if [ -z "$CA_NAME" ]; then
    echo_a "Error: CA name is required (--ca-name)"
    exit 1
  fi

  if [ -z "$PARENT_CA" ]; then
    echo_a "Error: Parent CA name is required (--parent-ca)"
    exit 1
  fi
}

show_help() {
  cat << EOF
Usage: $0 --ca-name <CA_NAME> --parent-ca <PARENT_CA> [OPTIONS]

This script creates a Certificate Authority (CA) certificate.
If --ca-name and --parent-ca are the same, it creates a root CA (self-signed)
If different, it creates an intermediate CA signed by the parent CA

Options:
  --ca-name <n>        Name of the CA to create (required)
  --parent-ca <n>      Name of the parent CA to sign with (required)
                          If same as --ca-name, creates a root CA
  --pathlen <NUM>         Path length constraint (default: 5 for root, auto-calculated for intermediate)
  --validity <DAYS>       Validity period in days (default: 3650)
  --key-type <TYPE>       Key type: 'rsa' or 'ecc' (default: ecc)
  --key-size <SIZE>       RSA key size in bits (default: 2048) or ECC curve name (default: prime256v1)
  --expired               Generate an expired CA certificate
  --corrupted             Generate a corrupted CA certificate
  --revoked               Generate a revoked CA certificate
  --help                  Display this help message

Examples:
  # Create a root CA
  $0 --ca-name "Root-CA" --parent-ca "Root-CA"

  # Create an intermediate CA signed by Root-CA
  $0 --ca-name "Intermediate-CA" --parent-ca "Root-CA"
EOF
}

# Setup certificate directories
setup_cert_dirs() {
  # Determine the proper path for the CA directory
  local ca_path="${CERT_DIR}/${CA_NAME}"

  # If this is an intermediate CA, place it under its parent
  if [ "${CA_NAME}" != "${PARENT_CA}" ]; then
    ca_path="${CERT_DIR}/${PARENT_CA}/${CA_NAME}"
    echo_t "Setting up intermediate CA directory for ${CA_NAME} under ${PARENT_CA}..."
  else
    echo_t "Setting up root CA directory for ${CA_NAME}..."
  fi

  # Create CA directories with their subdirectories
  mkdir -p "${ca_path}/certs"
  mkdir -p "${ca_path}/private"
  mkdir -p "${ca_path}/csr"
  mkdir -p "${ca_path}/crl"

  # Create necessary database files for certificate management
  touch "${ca_path}/index.txt"
  echo "01" > "${ca_path}/serial"
  echo "01" > "${ca_path}/crlnumber"

  # Set proper permissions
  chmod -R 700 "${ca_path}/private"
}

# Helper function to get the correct path for a CA
get_ca_path() {
  local name=$1
  local parent=$2

  if [ "${name}" = "${parent}" ]; then
    # Root CA
    echo "${CERT_DIR}/${name}"
  else
    # Intermediate CA
    echo "${CERT_DIR}/${parent}/${name}"
  fi
}

# Note: We no longer need CA-specific config files as we use the common openssl.cnf file

# Main function to generate CA certificate
generate_ca_cert() {
  # Determine if this is a root or intermediate CA
  local is_root=false
  local ca_extensions="v3_intermediate_ca"

  if [ "${CA_NAME}" = "${PARENT_CA}" ]; then
    is_root=true
    ca_extensions="v3_ca"

    # Set default pathlen for root CA if not specified
    if [ -z "${PATHLEN}" ]; then
      PATHLEN=5
    fi
  else
    # Set default pathlen for intermediate CA if not specified
    if [ -z "${PATHLEN}" ]; then
      # For intermediate CAs, default pathlen is one less than parent's pathlen
      # Get parent CA's pathlen by inspecting its certificate
      local parent_path=$(get_ca_path "${PARENT_CA}" "${PARENT_CA}")
      local parent_cert="${parent_path}/certs/${PARENT_CA}.pem"

      if [ -f "${parent_cert}" ]; then
        # Extract pathlen from parent certificate
        local parent_pathlen=$(openssl x509 -in "${parent_cert}" -text -noout | grep "CA:TRUE" | grep -o "pathlen:[0-9]*" | cut -d: -f2)

        if [ ! -z "${parent_pathlen}" ] && [ "${parent_pathlen}" -gt 0 ]; then
          # Set pathlen to one less than parent's
          PATHLEN=$((parent_pathlen - 1))
          echo_t "Using pathlen ${PATHLEN} based on parent CA's constraint"
        else
          # Default if we couldn't determine parent's pathlen
          PATHLEN=1
          echo_t "Using default pathlen ${PATHLEN} for intermediate CA"
        fi
      else
        # Default if parent certificate doesn't exist
        PATHLEN=1
        echo_t "Using default pathlen ${PATHLEN} (parent certificate not found)"
      fi
    fi
  fi

  # Create OpenSSL config file if it doesn't exist
  create_openssl_config

  # Create CA directory structure
  setup_cert_dirs

  # Get the proper path for this CA
  local ca_path=$(get_ca_path "${CA_NAME}" "${PARENT_CA}")

  # Generate CA key
  generate_private_key "${CA_NAME}" "${ca_path}/private" "${KEY_SIZE}" "${KEY_TYPE}"

  # Check if key generation was successful
  if [ ! -f "${ca_path}/private/${CA_NAME}.key" ]; then
    echo_a "Error: Failed to generate private key for ${CA_NAME}."
    echo_t "Please check filesystem permissions and try again."
    exit 1
  fi

  if [ "${is_root}" = "true" ]; then
    # Root CA: Generate self-signed certificate
    create_self_signed_cert "${CA_NAME}" \
      "${CERT_DIR}/openssl.cnf" \
      "${ca_path}/private/${CA_NAME}.key" \
      "${ca_path}/certs/${CA_NAME}.pem" \
      "${VALIDITY}" \
      "${CA_NAME}"

    # Check if certificate creation was successful
    if [ ! -f "${ca_path}/certs/${CA_NAME}.pem" ]; then
      echo_a "Error: Failed to create self-signed certificate for ${CA_NAME}."
      exit 1
    fi

    echo_t "Root CA certificate created at ${ca_path}/certs/${CA_NAME}.pem"

    # Create a symbolic link to the certificate as chain.pem for consistency
    ln -sf "${ca_path}/certs/${CA_NAME}.pem" "${ca_path}/${CA_NAME}_chain.pem"
    echo_t "Created chain link at ${ca_path}/${CA_NAME}_chain.pem"
  else
    # Intermediate CA: Generate CSR and get it signed by parent CA
    local parent_path=$(get_ca_path "${PARENT_CA}" "${PARENT_CA}")  # Parent CA path

    # Create CSR
    create_csr "${CA_NAME}" \
      "${CERT_DIR}/openssl.cnf" \
      "${ca_path}/private/${CA_NAME}.key" \
      "${ca_path}/csr/${CA_NAME}.csr" \
      "${CA_NAME}"

    # Sign the CSR with the parent CA
    sign_certificate "ca" \
      "${ca_path}/csr/${CA_NAME}.csr" \
      "${parent_path}/certs/${PARENT_CA}.pem" \
      "${parent_path}/private/${PARENT_CA}.key" \
      "${CERT_DIR}/openssl.cnf" \
      "${ca_path}/certs/${CA_NAME}.pem" \
      "${VALIDITY}" \
      "${ca_extensions}" \
      "${PATHLEN}"

    # Check if signing was successful
    if [ ! -f "${ca_path}/certs/${CA_NAME}.pem" ]; then
      echo_a "Error: Failed to sign certificate for ${CA_NAME} with ${PARENT_CA}."
      echo_t "Please check that the parent CA certificate and private key exist and are valid."
      exit 1
    fi

    # Create certificate chain (intermediate + parent)
    create_cert_chain \
      "${ca_path}/certs/${CA_NAME}.pem" \
      "${parent_path}/${PARENT_CA}_chain.pem" \
      "${ca_path}/${CA_NAME}_chain.pem"

    echo_t "Intermediate CA certificate created at ${ca_path}/certs/${CA_NAME}.pem"
    echo_t "Certificate chain created at ${ca_path}/${CA_NAME}_chain.pem"
  fi

  # Handle failure modes if specified
  if [ "${FAILURE_MODE}" = "corrupted" ]; then
    corrupt_certificate "${ca_path}/certs/${CA_NAME}.pem"
  elif [ "${FAILURE_MODE}" = "revoked" ]; then
    # We only revoke intermediate CAs, not root CAs
    if [ "${CA_NAME}" != "${PARENT_CA}" ]; then
      # This is an intermediate CA, revoke it using its parent
      local parent_path=$(get_ca_path "${PARENT_CA}" "${PARENT_CA}")

      # Make sure the CRL directory exists
      if [ ! -d "${parent_path}/crl" ]; then
        echo_t "Creating CRL directory at ${parent_path}/crl"
        mkdir -p "${parent_path}/crl"
      fi

      # Revoke the intermediate CA using its parent
      revoke_certificate \
        "${ca_path}/certs/${CA_NAME}.pem" \
        "${parent_path}/certs/${PARENT_CA}.pem" \
        "${parent_path}/private/${PARENT_CA}.key" \
        "${CERT_DIR}/openssl.cnf" \
        "${parent_path}/crl/${CA_NAME}.crl"

      echo_t "Intermediate CA revoked by parent CA. CRL available at: ${parent_path}/crl/${CA_NAME}.crl"
    else
      echo_t "Note: Root CA revocation is not implemented as it requires removing from trust stores."
      echo_t "The --revoked option is only effective for intermediate CAs."
    fi
  fi

  # CA certificate generation completed
}



# Main function
main() {
  # Parse arguments
  parse_args "$@"

  # Generate CA certificate
  generate_ca_cert

  local ca_path=$(get_ca_path "${CA_NAME}" "${PARENT_CA}")
  echo_t "CA certificate generation complete."

  # Display certificate details
  echo_t "------------------------------"
  echo_t "Certificate details:"
  echo_t "------------------------------"
  # Capture the output and print using echo_t to respect debug settings
  local cert_details=$(openssl x509 -in "${ca_path}/certs/${CA_NAME}.pem" -text -noout | grep -E "Subject:|Issuer:|Validity|Basic Constraints|Key Usage")
  echo_t "${cert_details}"
  echo_t "------------------------------"
  echo_t "Certificate available at ${ca_path}/certs/${CA_NAME}.pem"
}

# Run the script
main "$@"
