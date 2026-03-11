#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
##########################################################################
# Copyright 2025 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file in the project root or
# https://www.apache.org/licenses/LICENSE-2.0
##########################################################################
# Cross-signing script for Root CA certificates
# Usage: cross_sign_roots.sh --source-root <SOURCE_ROOT> --signing-root <SIGNING_ROOT> [OPTIONS]
#
# This script creates a cross-signed certificate where one root CA signs another root CA's
# public key, creating a bridge of trust between two separate PKI hierarchies.
#
# Options:
#   --source-root <NAME>      Name of the root CA to be cross-signed (required unless --source-cert provided)
#   --source-cert <PATH>      Path to source certificate file (alternative to --source-root, implies cert-only mode)
#   --signing-root <NAME>     Name of the root CA that will sign (required)
#   --output-name <NAME>      Name for the cross-signed certificate (default: auto-generated)
#   --validity <DAYS>         Validity period in days (default: auto-calculated as minimum of source and signing root validity periods)
#   --help                    Display this help message

# Import utility functions
source "$(dirname "$0")/cert_utils.sh"

# Default values
SOURCE_ROOT=""
SOURCE_CERT=""
SIGNING_ROOT=""
OUTPUT_NAME=""
VALIDITY=""  # Will be auto-calculated if not specified
SOURCE_CERT_ONLY=false  # Flag for cert-only mode (no private key)

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
      --source-root)
        SOURCE_ROOT="$2"
        shift 2
        ;;
      --source-cert)
        SOURCE_CERT="$2"
        shift 2
        ;;
      --signing-root)
        SIGNING_ROOT="$2"
        shift 2
        ;;
      --output-name)
        OUTPUT_NAME="$2"
        shift 2
        ;;
      --validity)
        VALIDITY="$2"
        shift 2
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

  # Validate mutually exclusive options
  if [ -n "$SOURCE_ROOT" ] && [ -n "$SOURCE_CERT" ]; then
    echo_a "Error: --source-root and --source-cert are mutually exclusive; provide only one"
    exit 1
  fi

  # Auto-enable cert-only mode if --source-cert is provided
  if [ -n "$SOURCE_CERT" ]; then
    SOURCE_CERT_ONLY=true
  fi

  # Validate required parameters
  if [ -z "$SOURCE_ROOT" ] && [ -z "$SOURCE_CERT" ]; then
    echo_a "Error: Either --source-root or --source-cert is required"
    exit 1
  fi

  if [ -z "$SIGNING_ROOT" ]; then
    echo_a "Error: Signing root CA name is required (--signing-root)"
    exit 1
  fi

  # Set default output name if not provided
  if [ -z "$OUTPUT_NAME" ]; then
    if [ -n "$SOURCE_ROOT" ]; then
      OUTPUT_NAME="${SOURCE_ROOT}-cross-signed-by-${SIGNING_ROOT}"
    else
      # Extract basename from certificate file
      local cert_basename=$(basename "${SOURCE_CERT}" .pem)
      OUTPUT_NAME="${cert_basename}-cross-signed-by-${SIGNING_ROOT}"
    fi
  fi
}

show_help() {
  cat << EOF
Usage: $0 --source-root <SOURCE_ROOT> --signing-root <SIGNING_ROOT> [OPTIONS]
   or: $0 --source-cert <CERT_FILE> --signing-root <SIGNING_ROOT> [OPTIONS]

This script creates a cross-signed certificate where one root CA signs another root CA's
public key, creating a bridge of trust between two separate PKI hierarchies.

Options:
  --source-root <NAME>      Name of the root CA to be cross-signed (mutually exclusive with --source-cert)
  --source-cert <PATH>      Path to source certificate file (alternative to --source-root, implies cert-only mode)
  --signing-root <NAME>     Name of the root CA that will sign (required)
  --output-name <NAME>      Name for the cross-signed certificate (default: auto-generated)
  --validity <DAYS>         Validity period in days (default: auto-calculated as minimum of source and signing root validity periods)
  --help                    Display this help message

Notes:
  - Both root CAs must already exist in ${CERT_DIR}
  - The cross-signed certificate will be placed in the signing root's cross-signed/ directory
  - Creates unidirectional trust: certificates under Source Root trusted by systems trusting Signing Root
  - For bidirectional trust, run the command twice (swapping source and signing roots)
  - Standard mode (--source-root): Requires source root private key, preserves subject DN (via CSR); extensions applied from openssl.cnf
  - Certificate-only mode (--source-cert): No source private key needed, works with any OpenSSL version; extensions preserved and applied from config
    * OpenSSL 3.x: Uses direct certificate creation (x509 -new)
    * OpenSSL 1.x: Uses dummy CSR approach with -force_pubkey
    Automatically enabled when using --source-cert option
EOF
}

# Helper function to get the path for a root CA
get_root_ca_path() {
  local name=$1
  local path="${CERT_DIR}/${name}"

  # Validate that this is a root CA directory
  if [ ! -d "${path}" ]; then
    echo_a "Error: Root CA directory not found at ${path}" >&2
    return 1
  fi

  if [ ! -f "${path}/certs/${name}.pem" ]; then
    echo_a "Error: Root CA certificate not found at ${path}/certs/${name}.pem" >&2
    return 1
  fi

  # Always require the private key (both source and signing root need it in their respective modes)
  if [ ! -f "${path}/private/${name}.key" ]; then
    echo_a "Error: Root CA private key not found at ${path}/private/${name}.key" >&2
    echo_t "Hint: Use --source-cert if you only have the certificate file" >&2
    return 1
  fi

  echo "${path}"
  return 0
}

# Calculate remaining validity days for a certificate
get_cert_remaining_days() {
  local cert_file=$1

  # Get the expiry date in seconds since epoch
  local expiry_date=$(openssl x509 -in "${cert_file}" -noout -enddate | cut -d= -f2)
  local expiry_epoch=$(date -d "${expiry_date}" +%s 2>/dev/null)

  if [ -z "${expiry_epoch}" ]; then
    echo_a "Error: Failed to parse expiry date from ${cert_file}" >&2
    return 1
  fi

  # Get current date in seconds since epoch
  local current_epoch=$(date +%s)

  # Calculate remaining days (round up partial days)
  local remaining_seconds=$((expiry_epoch - current_epoch))
  local remaining_days=$(( (remaining_seconds + 86399) / 86400 ))

  # Return 0 if certificate is already expired
  if [ ${remaining_days} -lt 0 ]; then
    remaining_days=0
  fi

  echo "${remaining_days}"
  return 0
}

# Get OpenSSL major version
get_openssl_version() {
  openssl version | awk '{print $2}' | cut -d. -f1
}

# Main function to perform cross-signing
cross_sign_roots() {
  local source_root_path=$1
  local signing_root_path=$2

  echo_t "Starting cross-signing process..."
  if [ -n "$SOURCE_ROOT" ]; then
    echo_t "Source Root CA: ${SOURCE_ROOT} at ${source_root_path}"
  else
    echo_t "Source Certificate: ${SOURCE_CERT}"
  fi
  echo_t "Signing Root CA: ${SIGNING_ROOT} at ${signing_root_path}"

  # Calculate validity if not specified
  if [ -z "${VALIDITY}" ]; then
    echo_t "Calculating optimal validity period..."

    # Determine source certificate path
    local source_cert
    if [ -n "$SOURCE_ROOT" ]; then
      source_cert="${source_root_path}/certs/${SOURCE_ROOT}.pem"
    else
      source_cert="${SOURCE_CERT}"
    fi
    local signing_cert="${signing_root_path}/certs/${SIGNING_ROOT}.pem"

    local source_days=$(get_cert_remaining_days "${source_cert}")
    if [ $? -ne 0 ]; then
      echo_a "Error: Failed to calculate remaining days for source root certificate"
      exit 1
    fi

    local signing_days=$(get_cert_remaining_days "${signing_cert}")
    if [ $? -ne 0 ]; then
      echo_a "Error: Failed to calculate remaining days for signing root certificate"
      exit 1
    fi

    local source_label="${SOURCE_ROOT:-$(basename "${SOURCE_CERT}")}"
    echo_t "Source root ${source_label} has ${source_days} days remaining"
    echo_t "Signing root ${SIGNING_ROOT} has ${signing_days} days remaining"

    # Use the minimum of the two
    if [ ${source_days} -le ${signing_days} ]; then
      VALIDITY=${source_days}
      echo_t "Using source root validity (shorter): ${VALIDITY} days"
    else
      VALIDITY=${signing_days}
      echo_t "Using signing root validity (shorter): ${VALIDITY} days"
    fi

    # Sanity check - ensure validity is at least 1 day
    if [ ${VALIDITY} -lt 1 ]; then
      echo_a "Error: One or both root certificates have expired or expire within 1 day"
      echo_t "Source root (${source_label}) expires in: ${source_days} days"
      echo_t "Signing root (${SIGNING_ROOT}) expires in: ${signing_days} days"
      exit 1
    fi
  else
    echo_t "Using specified validity period: ${VALIDITY} days"
  fi

  # Create OpenSSL config file if it doesn't exist
  create_openssl_config

  # Set paths for source root certificate and key
  local source_cert
  local source_key
  if [ -n "$SOURCE_ROOT" ]; then
    source_cert="${source_root_path}/certs/${SOURCE_ROOT}.pem"
    source_key="${source_root_path}/private/${SOURCE_ROOT}.key"
  else
    source_cert="${SOURCE_CERT}"
    source_key=""  # Not used in cert-only mode
  fi

  echo_t "Source certificate: ${source_cert}"
  if [ "${SOURCE_CERT_ONLY}" = "false" ]; then
    echo_t "Source private key: ${source_key}"
  else
    echo_t "Mode: Certificate-only (no private key required)"
  fi

  # Create cross-signed certs directory if it doesn't exist
  local cross_sign_dir="${signing_root_path}/cross-signed"
  if [ ! -d "${cross_sign_dir}" ]; then
    echo_t "Creating cross-signed directory at ${cross_sign_dir}"
    mkdir -p "${cross_sign_dir}"
  fi

  # Output certificate path
  local output_cert="${cross_sign_dir}/${OUTPUT_NAME}.pem"
  local signing_cert="${signing_root_path}/certs/${SIGNING_ROOT}.pem"
  local signing_key="${signing_root_path}/private/${SIGNING_ROOT}.key"

  if [ "${SOURCE_CERT_ONLY}" = "true" ]; then
    # Certificate-only mode: Use appropriate method based on OpenSSL version
    local openssl_major_version=$(get_openssl_version)
    echo_t "Detected OpenSSL version: ${openssl_major_version}.x"

    # Extract subject from source certificate in OpenSSL format (preserve exact field order)
    # Using -nameopt compat preserves the original order and outputs in /type=value format
    local source_subject=$(openssl x509 -in "${source_cert}" -noout -subject -nameopt compat | sed 's/^subject=//')
    echo_t "Source certificate subject: ${source_subject}"

    # Build extensions config for the cross-signed certificate.
    # For cross-signing, authorityKeyIdentifier must reference the signing CA's key
    # and subjectKeyIdentifier is computed from the (copied) public key via hash.
    # What we do preserve from the source: pathlen constraint and critical flags.
    local ext_file="${cross_sign_dir}/${OUTPUT_NAME}.ext.cnf"
    echo_t "Building extensions configuration from source certificate..."

    local cert_text
    cert_text=$(openssl x509 -in "${source_cert}" -text -noout)

    # --- basicConstraints: preserve critical flag and pathlen ---
    local bc_critical=""
    echo "${cert_text}" | grep "X509v3 Basic Constraints" | grep -q "critical" && bc_critical="critical, "
    local pathlen
    pathlen=$(echo "${cert_text}" | sed -n 's/.*CA:TRUE, pathlen:\([0-9][0-9]*\).*/\1/p')
    local bc_value="CA:TRUE"
    [ -n "${pathlen}" ] && bc_value="CA:TRUE, pathlen:${pathlen}"

    # --- keyUsage: map text token names back to OpenSSL config names ---
    local ku_critical=""
    echo "${cert_text}" | grep "X509v3 Key Usage" | grep -q "critical" && ku_critical="critical, "
    # The value line immediately follows the "X509v3 Key Usage" header line
    local ku_text
    ku_text=$(echo "${cert_text}" | awk '/X509v3 Key Usage/{found=1; next} found{gsub(/^[[:space:]]+/,"",$0); print; exit}')
    local ku_value=""
    echo "${ku_text}" | grep -q "Digital Signature"                          && ku_value="${ku_value}digitalSignature, "
    echo "${ku_text}" | grep -qE "Non Repudiation|Content Commitment"        && ku_value="${ku_value}nonRepudiation, "
    echo "${ku_text}" | grep -q "Key Encipherment"                           && ku_value="${ku_value}keyEncipherment, "
    echo "${ku_text}" | grep -q "Data Encipherment"                          && ku_value="${ku_value}dataEncipherment, "
    echo "${ku_text}" | grep -q "Key Agreement"                              && ku_value="${ku_value}keyAgreement, "
    echo "${ku_text}" | grep -qE "Certificate Sign|Key Cert Sign"            && ku_value="${ku_value}keyCertSign, "
    echo "${ku_text}" | grep -q "CRL Sign"                                   && ku_value="${ku_value}cRLSign, "
    echo "${ku_text}" | grep -q "Encipher Only"                              && ku_value="${ku_value}encipherOnly, "
    echo "${ku_text}" | grep -q "Decipher Only"                              && ku_value="${ku_value}decipherOnly, "
    ku_value="${ku_value%, }"
    # Fall back to minimal CA key usage if source had none parseable
    [ -z "${ku_value}" ] && ku_value="keyCertSign, cRLSign"

    # --- extendedKeyUsage: map text token names if the extension is present ---
    local eku_line=""
    if echo "${cert_text}" | grep -q "X509v3 Extended Key Usage"; then
      local eku_critical=""
      echo "${cert_text}" | grep "X509v3 Extended Key Usage" | grep -q "critical" && eku_critical="critical, "
      local eku_text
      eku_text=$(echo "${cert_text}" | awk '/X509v3 Extended Key Usage/{found=1; next} found{gsub(/^[[:space:]]+/,"",$0); print; exit}')
      local eku_value=""
      echo "${eku_text}" | grep -qE "TLS Web Server Authentication|serverAuth" && eku_value="${eku_value}serverAuth, "
      echo "${eku_text}" | grep -qE "TLS Web Client Authentication|clientAuth" && eku_value="${eku_value}clientAuth, "
      echo "${eku_text}" | grep -qE "Code Signing|codeSigning"                 && eku_value="${eku_value}codeSigning, "
      echo "${eku_text}" | grep -qE "E-mail Protection|emailProtection"        && eku_value="${eku_value}emailProtection, "
      echo "${eku_text}" | grep -qE "Time Stamping|timeStamping"               && eku_value="${eku_value}timeStamping, "
      echo "${eku_text}" | grep -qE "OCSP Signing|OCSPSigning"                 && eku_value="${eku_value}OCSPSigning, "
      eku_value="${eku_value%, }"
      [ -n "${eku_value}" ] && eku_line="extendedKeyUsage = ${eku_critical}${eku_value}"
    fi

    # SKI is always recomputed as hash — the public key is identical so the hash matches the source.
    # AKI always references the signing CA's key; this is required for a valid cross-signed cert
    # and must NOT be copied from the source (which points to the original issuer).
    {
      echo "[ v3_ca ]"
      echo "basicConstraints = ${bc_critical}${bc_value}"
      echo "keyUsage = ${ku_critical}${ku_value}"
      echo "subjectKeyIdentifier = hash"
      echo "authorityKeyIdentifier = keyid:always,issuer"
      [ -n "${eku_line}" ] && echo "${eku_line}"
    } > "${ext_file}"

    [ -n "${pathlen}" ] && echo_t "Preserving pathlen constraint: ${pathlen}"
    echo_t "Extensions configuration built from source certificate"

    if [ "${openssl_major_version}" -ge 3 ]; then
      # OpenSSL 3.0+: Use x509 -new with -force_pubkey (direct method, no CSR)
      echo_t "Cross-signing using OpenSSL 3.x direct method (x509 -new)..."

      # Extract public key from source certificate
      local pubkey_file="${cross_sign_dir}/${OUTPUT_NAME}.pubkey.pem"
      echo_t "Extracting public key from source certificate..."
      openssl x509 -in "${source_cert}" -pubkey -noout > "${pubkey_file}"

      if [ $? -ne 0 ]; then
        echo_a "Error: Failed to extract public key from source certificate"
        exit 1
      fi

      # Subject is already in OpenSSL format (/C=.../O=.../CN=...)
      echo_t "Using subject (already in OpenSSL format): ${source_subject}"

      # Use x509 -new to create certificate directly (OpenSSL 3.0+ feature)
      echo_t "Creating cross-signed certificate with ${SIGNING_ROOT}..."
      openssl x509 -new \
        -force_pubkey "${pubkey_file}" \
        -subj "${source_subject}" \
        -CA "${signing_cert}" \
        -CAkey "${signing_key}" \
        -CAcreateserial \
        -out "${output_cert}" \
        -days "${VALIDITY}" \
        -sha256 \
        -copy_extensions none \
        -extfile "${ext_file}" \
        -extensions v3_ca

      if [ $? -ne 0 ]; then
        echo_a "Error: Failed to create cross-signed certificate using x509 -new"
        exit 1
      fi

      # Clean up temporary public key file
      rm -f "${pubkey_file}"
      echo_t "Cleaned up temporary files"

    else
      # OpenSSL 1.x: Use dummy key pair approach with CSR + -force_pubkey
      echo_t "Cross-signing using OpenSSL 1.x method (dummy CSR with -force_pubkey)..."

      # Extract public key from source certificate
      local pubkey_file="${cross_sign_dir}/${OUTPUT_NAME}.pubkey.pem"
      echo_t "Extracting public key from source certificate..."
      openssl x509 -in "${source_cert}" -pubkey -noout > "${pubkey_file}"

      if [ $? -ne 0 ]; then
        echo_a "Error: Failed to extract public key from source certificate"
        exit 1
      fi

      # Create a dummy CSR with temporary key
      local dummy_key="${cross_sign_dir}/${OUTPUT_NAME}.dummy.key"
      local dummy_csr="${cross_sign_dir}/${OUTPUT_NAME}.dummy.csr"

      echo_t "Creating temporary CSR with dummy key..."
      echo_t "Using subject (already in OpenSSL format): ${source_subject}"
      openssl genrsa -out "${dummy_key}" 2048 > /dev/null 2>&1
      openssl req -new -key "${dummy_key}" -out "${dummy_csr}" -subj "${source_subject}" > /dev/null 2>&1

      # Sign with forced public key
      echo_t "Signing certificate with ${SIGNING_ROOT} (forcing source public key)..."
      openssl x509 -req \
        -in "${dummy_csr}" \
        -force_pubkey "${pubkey_file}" \
        -CA "${signing_cert}" \
        -CAkey "${signing_key}" \
        -CAcreateserial \
        -out "${output_cert}" \
        -days "${VALIDITY}" \
        -sha256 \
        -extfile "${ext_file}" \
        -extensions v3_ca

      if [ $? -ne 0 ]; then
        echo_a "Error: Failed to create cross-signed certificate"
        exit 1
      fi

      # Clean up temporary files
      rm -f "${dummy_key}" "${dummy_csr}" "${pubkey_file}"
      echo_t "Cleaned up temporary files"
    fi

  else
    # Standard mode: Use private key to create proper CSR
    # Create a CSR directory in the signing root if it doesn't exist
    if [ ! -d "${signing_root_path}/csr" ]; then
      echo_t "Creating CSR directory at ${signing_root_path}/csr"
      mkdir -p "${signing_root_path}/csr"
    fi

    # Generate a CSR from the source root CA certificate
    # Use x509toreq to preserve the exact subject field order from the original certificate
    local csr_file="${signing_root_path}/csr/${OUTPUT_NAME}.csr"
    echo_t "Creating CSR for cross-signing (preserving subject field order)..."

    openssl x509 \
      -x509toreq \
      -in "${source_cert}" \
      -signkey "${source_key}" \
      -out "${csr_file}"

    if [ $? -ne 0 ]; then
      echo_a "Error: Failed to create CSR for cross-signing"
      exit 1
    fi

    echo_t "CSR created at ${csr_file}"

    # Sign the CSR with the signing root CA
    echo_t "Cross-signing certificate with ${SIGNING_ROOT}..."

    # Use v3_ca extensions for root CA cross-signing
    openssl x509 -req \
      -in "${csr_file}" \
      -CA "${signing_cert}" \
      -CAkey "${signing_key}" \
      -CAcreateserial \
      -out "${output_cert}" \
      -days "${VALIDITY}" \
      -sha256 \
      -extensions v3_ca \
      -extfile "${CERT_DIR}/openssl.cnf"

    if [ $? -ne 0 ]; then
      echo_a "Error: Failed to sign certificate with ${SIGNING_ROOT}"
      exit 1
    fi
  fi

  echo_t "Cross-signed certificate created at ${output_cert}"

  # Create a certificate chain file
  local chain_file="${cross_sign_dir}/${OUTPUT_NAME}_chain.pem"
  echo_t "Creating certificate chain file..."

  cat "${output_cert}" "${signing_cert}" > "${chain_file}"

  if [ $? -ne 0 ]; then
    echo_a "Error: Failed to create certificate chain file"
    exit 1
  fi

  echo_t "Certificate chain created at ${chain_file}"

  # Verify the cross-signed certificate
  echo_t "Verifying cross-signed certificate..."
  openssl verify -CAfile "${signing_cert}" "${output_cert}" > /dev/null 2>&1

  if [ $? -eq 0 ]; then
    echo_t "✓ Cross-signed certificate verification successful"
  else
    echo_a "⚠ Warning: Cross-signed certificate verification failed"
    echo_t "This may be expected if the signing root is not in the system trust store"
  fi

  # Display certificate details
  echo_t "------------------------------"
  echo_t "Cross-signed Certificate Details:"
  echo_t "------------------------------"
  openssl x509 -in "${output_cert}" -text -noout | grep -E "Subject:|Issuer:|Validity"
  echo_t "------------------------------"

  echo_t ""
  echo_t "Cross-signing complete!"
  echo_t ""
  echo_t "Files created:"
  echo_t "  - Cross-signed certificate: ${output_cert}"
  echo_t "  - Certificate chain: ${chain_file}"
  if [ "${SOURCE_CERT_ONLY}" = "true" ]; then
    echo_t "  - Extensions config: ${cross_sign_dir}/${OUTPUT_NAME}.ext.cnf"
  else
    echo_t "  - CSR (for reference): ${csr_file}"
  fi
  echo_t ""
  if [ "${SOURCE_CERT_ONLY}" = "true" ]; then
    echo_t "⚠ Note: Certificate created in cert-only mode (without source private key)"
    echo_t "   This is a synthetic cross-signed certificate. Verify compatibility with your use case."
    echo_t ""
  fi
  if [ "${SOURCE_CERT_ONLY}" = "false" ]; then
    echo_t "To establish bidirectional trust, run:"
    echo_t "  $0 --source-root \"${SIGNING_ROOT}\" --signing-root \"${SOURCE_ROOT}\""
  fi
}

# Main function
main() {
  # Parse arguments
  parse_args "$@"

  # Get paths for both root CAs
  echo_t "Validating root CA directories..."

  local source_root_path=""
  if [ -n "$SOURCE_ROOT" ]; then
    source_root_path=$(get_root_ca_path "${SOURCE_ROOT}")
    if [ $? -ne 0 ] || [ -z "${source_root_path}" ]; then
      echo_a "Error: Failed to find valid path for source root CA '${SOURCE_ROOT}'"
      exit 1
    fi
  elif [ -n "$SOURCE_CERT" ]; then
    # Validate source certificate file exists
    if [ ! -f "${SOURCE_CERT}" ]; then
      echo_a "Error: Source certificate file not found: ${SOURCE_CERT}"
      exit 1
    fi
    # Verify it's a valid certificate
    if ! openssl x509 -in "${SOURCE_CERT}" -noout 2>/dev/null; then
      echo_a "Error: Invalid certificate file: ${SOURCE_CERT}"
      exit 1
    fi
    echo_t "Source certificate validated: ${SOURCE_CERT}"
  fi

  local signing_root_path=$(get_root_ca_path "${SIGNING_ROOT}")
  if [ $? -ne 0 ] || [ -z "${signing_root_path}" ]; then
    echo_a "Error: Failed to find valid path for signing root CA '${SIGNING_ROOT}'"
    exit 1
  fi

  # Perform cross-signing
  cross_sign_roots "${source_root_path}" "${signing_root_path}"
}

# Run the script
main "$@"
