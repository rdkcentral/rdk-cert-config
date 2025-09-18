#!/bin/bash
# Utility functions for certificate generation
# This file contains common functions used by create_ca.sh and create_leaf_cert.sh

# Default directory for certificates
CERT_DIR="/etc/pki"

# Echo function that prints only when DEBUG_ENABLED is set
echo_t() {
    if [ "${DEBUG_ENABLED:-false}" = "true" ]; then
        echo "[CERT-DEBUG] $*"
    fi
}

# Always echo function - for critical messages that should always be displayed
echo_a() {
    echo "$*"
}

# Generate private key using ECC
generate_private_key() {
  local name=$1
  local key_dir=$2
  local curve=$3

  echo_t "Generating ECC key with curve ${curve} for ${name}"
  if [ ! -d "${key_dir}" ]; then
    mkdir -p "${key_dir}"
  fi

  openssl ecparam -name "${curve}" -genkey -noout -out "${key_dir}/${name}.key"

  # Set appropriate permissions
  chmod 600 "${key_dir}/${name}.key"

  echo_t "Key generated at ${key_dir}/${name}.key"
}

# Create Certificate Signing Request (CSR)
create_csr() {
  local name=$1
  local config_path=$2
  local key_path=$3
  local csr_path=$4
  local cn=$5

  echo_t "Creating CSR for ${name}..."

  # Create a temporary config with the correct CN and SAN fields
  local temp_config="${config_path}.tmp"
  sed "s/@COMMON_NAME@/${cn}/g" "${config_path}" > "${temp_config}"

  # Generate the CSR
  openssl req -new -key "${key_path}" -out "${csr_path}" -config "${temp_config}"

  # Remove the temporary config
  rm -f "${temp_config}"

  echo_t "CSR generated at ${csr_path}"
}

# Sign a certificate with a CA
sign_certificate() {
  local cert_type=$1     # Type of cert: ca, server, client
  local csr_path=$2      # Path to the CSR
  local ca_cert=$3       # Path to the CA certificate
  local ca_key=$4        # Path to the CA key
  local ca_config=$5     # Path to the OpenSSL config
  local output_cert=$6   # Where to write the certificate
  local validity=$7      # Validity period in days
  local extensions=$8    # Extensions section name in config
  local pathlen=$9       # Optional pathlen constraint for intermediate CAs

  echo_t "Signing certificate using ${cert_type} extensions..."

  # Default to v3_ca extensions if not specified
  if [ -z "${extensions}" ]; then
    extensions="v3_ca"
  fi

  # Create a temporary config file
  local temp_config="${ca_config}.tmp"
  cp "${ca_config}" "${temp_config}"

  # Extract CN from the CSR to use in the SAN field if needed
  local cn=$(openssl req -in "${csr_path}" -noout -subject | sed -n 's/.*CN\s*=\s*\([^,]*\).*/\1/p')

  # Apply pathlen constraint if specified and using intermediate CA extensions
  if [ "${extensions}" = "v3_intermediate_ca" ] && [ ! -z "${pathlen}" ]; then
    sed -i "s/@PATHLEN@/${pathlen}/g" "${temp_config}"
  else
    # Default pathlen for intermediate CAs
    sed -i "s/@PATHLEN@/1/g" "${temp_config}"
  fi

  # Apply common name to SAN field if this is a server certificate
  if [ "${cert_type}" = "server" ] && [ ! -z "${cn}" ]; then
    sed -i "s/@COMMON_NAME@/${cn}/g" "${temp_config}"
  fi

  # Sign the certificate
  openssl x509 -req -in "${csr_path}" \
    -CA "${ca_cert}" \
    -CAkey "${ca_key}" \
    -CAcreateserial \
    -out "${output_cert}" \
    -days "${validity}" \
    -extfile "${temp_config}" \
    -extensions "${extensions}"

  # Remove the temporary config
  rm -f "${temp_config}"

  echo_t "Certificate signed and saved to ${output_cert}"
}

# Create a self-signed certificate
create_self_signed_cert() {
  local name=$1
  local config_path=$2
  local key_path=$3
  local cert_path=$4
  local validity=$5
  local cn=$6

  echo_t "Creating self-signed certificate for ${name}..."

  # Create a temporary config with the correct CN
  local temp_config="${config_path}.tmp"
  sed "s/@COMMON_NAME@/${cn}/g" "${config_path}" > "${temp_config}"

  # Generate the self-signed certificate
  openssl req -new -x509 -key "${key_path}" \
    -out "${cert_path}" \
    -days "${validity}" \
    -config "${temp_config}" \
    -extensions v3_ca

  # Remove the temporary config
  rm -f "${temp_config}"

  echo_t "Self-signed certificate generated at ${cert_path}"
}

# Create certificate chain
create_cert_chain() {
  local cert=$1
  local parent_chain=$2
  local output_chain=$3

  echo_t "Creating certificate chain..."

  # Check if all required certificates exist
  if [ -z "${cert}" ] || [ ! -f "${cert}" ]; then
    echo_a "Error: Certificate file not found at ${cert}"
    return 1
  fi

  if [ -z "${parent_chain}" ] || [ ! -f "${parent_chain}" ]; then
    echo_a "Error: Parent chain file not found at ${parent_chain}"
    return 1
  fi

  # Create the chain by concatenating the certificate with the parent chain
  cat "${cert}" "${parent_chain}" > "${output_chain}"

  # Check if chain creation was successful
  if [ ! -f "${output_chain}" ]; then
    echo_a "Error: Failed to create certificate chain at ${output_chain}"
    return 1
  fi

  echo_t "Certificate chain created at ${output_chain}"
  return 0
}

# Create PKCS#12 keystore
create_pkcs12() {
  local cert=$1
  local key=$2
  local chain=$3
  local output_p12=$4
  local password=$5
  local name=$6

  echo_t "Creating PKCS#12 keystore for ${name}..."

  # Check if all required files exist
  if [ ! -f "${cert}" ]; then
    echo_a "Error: Certificate file not found at ${cert}"
    return 1
  fi

  if [ ! -f "${key}" ]; then
    echo_a "Error: Private key file not found at ${key}"
    return 1
  fi

  # For chain file, use a fallback if it doesn't exist
  local chain_file="${chain}"
  if [ ! -f "${chain_file}" ]; then
    echo_a "Warning: Certificate chain file not found at ${chain}. Using certificate itself as chain."
    chain_file="${cert}"
  fi

  # Create output directory if it doesn't exist
  local output_dir=$(dirname "${output_p12}")
  if [ ! -d "${output_dir}" ]; then
    mkdir -p "${output_dir}"
  fi

  # Use -passout to specify empty password if no password
  if [ -z "${password}" ]; then
    openssl pkcs12 -export -out "${output_p12}" \
      -inkey "${key}" \
      -in "${cert}" \
      -certfile "${chain_file}" \
      -name "${name}" \
      -passout pass:
  else
    openssl pkcs12 -export -out "${output_p12}" \
      -inkey "${key}" \
      -in "${cert}" \
      -certfile "${chain_file}" \
      -name "${name}" \
      -passout pass:"${password}"
  fi

  # Verify that the file was created
  if [ ! -f "${output_p12}" ]; then
    echo_a "Error: Failed to create PKCS#12 file at ${output_p12}"
    return 1
  fi

  echo_t "PKCS#12 keystore created at ${output_p12}"
  return 0
}

# Corrupt a certificate file (for testing)
corrupt_certificate() {
  local cert_path=$1

  echo_t "Corrupting certificate at ${cert_path}..."

  # Make a backup first
  cp "${cert_path}" "${cert_path}.bak"

  # Corrupt the certificate by replacing some bytes
  dd if=/dev/urandom bs=1 count=10 seek=100 conv=notrunc of="${cert_path}" 2>/dev/null

  echo_t "Certificate corrupted. Original backed up at ${cert_path}.bak"
}

# Revoke a certificate (create CRL)
revoke_certificate() {
  local cert_to_revoke=$1
  local ca_cert=$2
  local ca_key=$3
  local ca_config=$4
  local output_crl=$5

  echo_t "Revoking certificate..."

  # Create a temporary database if it doesn't exist
  local ca_dir=$(dirname "${ca_cert}")
  if [ ! -f "${ca_dir}/index.txt" ]; then
    touch "${ca_dir}/index.txt"
  fi

  if [ ! -f "${ca_dir}/crlnumber" ]; then
    echo "01" > "${ca_dir}/crlnumber"
  fi

  # Add certificate to revocation list
  openssl ca -config "${ca_config}" \
    -cert "${ca_cert}" \
    -keyfile "${ca_key}" \
    -revoke "${cert_to_revoke}" \
    -crl_reason keyCompromise

  # Generate CRL
  openssl ca -config "${ca_config}" \
    -cert "${ca_cert}" \
    -keyfile "${ca_key}" \
    -gencrl \
    -out "${output_crl}"

  echo_t "Certificate revoked. CRL saved to ${output_crl}"
}

# Create base OpenSSL config file
create_openssl_config() {
  local output_path="${CERT_DIR}/openssl.cnf"

  if [ -f "${output_path}" ]; then
    echo_t "OpenSSL config file already exists at ${output_path}"
    return 0
  fi

  echo_t "Creating OpenSSL config file..."

  cat > "${output_path}" << EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
req_extensions = v3_req

[ v3_req ]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = @COMMON_NAME@
IP.1 = 127.0.0.1

[ req_distinguished_name ]
C = US
ST = PA
L = Philadelphia
O = RDK Test Environment
OU = RDK PKI Testing
CN = @COMMON_NAME@

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
nsCertType = sslCA

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:@PATHLEN@
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
nsCertType = sslCA

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "RDK Test Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ client_cert ]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "RDK Test Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

  echo_t "OpenSSL config file created at ${output_path}"
}
