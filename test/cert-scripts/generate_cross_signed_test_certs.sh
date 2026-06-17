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
# Cross-signed PKI topology generator for L2/L3 tests
#
# Creates the full Root A / Root B / Root C cross-signed topology:
#   Root A  — unrelated trusted root (present on native platform)
#   Root B  — issuing root for client certificates
#   Root C  — cross-signing root (signs Root B's public key)
#
# Generates:
#   - 3 root CAs (A, B, C) with ECC P-256
#   - 3 intermediate CAs (ICA-B, ICA-C, RevokedICA under Root B)
#   - 10 leaf client certs as P12 bundles
#   - 3 cross-signed bridge artefacts (valid, expired, revoked)
#   - CRL files for revocation scenarios
#
# Usage: generate_cross_signed_test_certs.sh [--help]
#
# Environment Variables:
#   CERT_DIR       Root dir for CA material (default: /etc/pki/test-xs)
#   OUT_DIR        Target dir for final P12 bundles (default: ./l2/xs)
#   BASE_VALIDITY  Base certificate validity in days (default: 365)
#   XS_EXPIRY      Validity for expired-bridge cert in days (default: -1, already expired)
#   DEBUG_ENABLED  Enable verbose trace (default: false)

set -euo pipefail

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Environment defaults
export CERT_DIR="${CERT_DIR:-/etc/pki/test-xs}"
OUT_DIR="${OUT_DIR:-./l2/xs}"
BASE_VALIDITY="${BASE_VALIDITY:-365}"
XS_EXPIRY="${XS_EXPIRY:--1}"
export DEBUG_ENABLED="${DEBUG_ENABLED:-false}"

# Import utility functions
source "${SCRIPT_DIR}/cert_utils.sh"

show_help() {
  cat << EOF
Usage: $0 [--help]

Generates the full cross-signed PKI topology for L2/L3 tests.

Environment Variables:
  CERT_DIR       Root dir for CA material (default: /etc/pki/test-xs)
  OUT_DIR        Target dir for final P12 bundles (default: ./l2/xs)
  BASE_VALIDITY  Base certificate validity in days (default: 365)
  XS_EXPIRY      Validity for expired-bridge cert in days (default: -1)
  DEBUG_ENABLED  Enable verbose trace (default: false)
EOF
  exit 0
}

if [ "${1:-}" = "--help" ]; then
  show_help
fi

echo_a "=== Cross-Signed PKI Generator ==="
echo_a "CERT_DIR=${CERT_DIR}"
echo_a "OUT_DIR=${OUT_DIR}"

# Clean previous run
rm -rf "${CERT_DIR}"
mkdir -p "${CERT_DIR}" "${OUT_DIR}"

# ─── Step 1: Create Root CAs ───────────────────────────────────────────

echo_a "Creating Root CAs..."

"${SCRIPT_DIR}/create_ca.sh" --ca-name "RootA" --parent-ca "RootA" \
  --key-type ecc --key-size prime256v1 --validity "${BASE_VALIDITY}"

"${SCRIPT_DIR}/create_ca.sh" --ca-name "RootB" --parent-ca "RootB" \
  --key-type ecc --key-size prime256v1 --validity "${BASE_VALIDITY}"

"${SCRIPT_DIR}/create_ca.sh" --ca-name "RootC" --parent-ca "RootC" \
  --key-type ecc --key-size prime256v1 --validity "${BASE_VALIDITY}"

# ─── Step 2: Create Intermediate CAs ───────────────────────────────────

echo_a "Creating Intermediate CAs..."

# ICA-B under Root B
"${SCRIPT_DIR}/create_ca.sh" --ca-name "ICA-B" --parent-ca "RootB" \
  --key-type ecc --key-size prime256v1 --validity "${BASE_VALIDITY}" --pathlen 0

# ICA-C under Root C
"${SCRIPT_DIR}/create_ca.sh" --ca-name "ICA-C" --parent-ca "RootC" \
  --key-type ecc --key-size prime256v1 --validity "${BASE_VALIDITY}" --pathlen 0

# RevokedICA under Root B (will be revoked for seq 15)
"${SCRIPT_DIR}/create_ca.sh" --ca-name "RevokedICA" --parent-ca "RootB" \
  --key-type ecc --key-size prime256v1 --validity "${BASE_VALIDITY}" --pathlen 0 --revoked

# ─── Step 3: Create Leaf Certificates ──────────────────────────────────

echo_a "Creating leaf certificates..."

# Cross-sign test certs (under ICA-B)
"${SCRIPT_DIR}/create_leaf_cert.sh" --cert-name "client-nobridge" --ca-name "ICA-B" \
  --cn "client-nobridge.test" --type client --validity "${BASE_VALIDITY}"

"${SCRIPT_DIR}/create_leaf_cert.sh" --cert-name "client-xsign" --ca-name "ICA-B" \
  --cn "client-xsign.test" --type client --validity "${BASE_VALIDITY}"

"${SCRIPT_DIR}/create_leaf_cert.sh" --cert-name "client-expxs" --ca-name "ICA-B" \
  --cn "client-expxs.test" --type client --validity "${BASE_VALIDITY}"

"${SCRIPT_DIR}/create_leaf_cert.sh" --cert-name "client-revxs" --ca-name "ICA-B" \
  --cn "client-revxs.test" --type client --validity "${BASE_VALIDITY}"

# CRL test certs (under ICA-B)
"${SCRIPT_DIR}/create_leaf_cert.sh" --cert-name "crl-revoked" --ca-name "ICA-B" \
  --cn "crl-revoked.test" --type client --validity "${BASE_VALIDITY}" --revoked

"${SCRIPT_DIR}/create_leaf_cert.sh" --cert-name "crl-valid" --ca-name "ICA-B" \
  --cn "crl-valid.test" --type client --validity "${BASE_VALIDITY}"

# ICA revocation test certs
"${SCRIPT_DIR}/create_leaf_cert.sh" --cert-name "ica-valid-leaf" --ca-name "ICA-B" \
  --cn "ica-valid-leaf.test" --type client --validity "${BASE_VALIDITY}"

"${SCRIPT_DIR}/create_leaf_cert.sh" --cert-name "ica-revoked-leaf" --ca-name "RevokedICA" \
  --cn "ica-revoked-leaf.test" --type client --validity "${BASE_VALIDITY}"

# OCSP test certs (under ICA-C)
"${SCRIPT_DIR}/create_leaf_cert.sh" --cert-name "ocsp-valid" --ca-name "ICA-C" \
  --cn "ocsp-valid.test" --type client --validity "${BASE_VALIDITY}"

"${SCRIPT_DIR}/create_leaf_cert.sh" --cert-name "ocsp-revoked" --ca-name "ICA-C" \
  --cn "ocsp-revoked.test" --type client --validity "${BASE_VALIDITY}"

# ─── Step 4: Cross-Signed Bridge Artefacts ─────────────────────────────

echo_a "Creating cross-signed bridge artefacts..."

# Valid bridge: Root B cross-signed by Root C (full validity)
"${SCRIPT_DIR}/cross_sign_roots.sh" --source-root "RootB" --signing-root "RootC" \
  --output-name "RootB-xsign" --validity "${BASE_VALIDITY}"

# Expired bridge: Root B cross-signed by Root C (already expired)
"${SCRIPT_DIR}/cross_sign_roots.sh" --source-root "RootB" --signing-root "RootC" \
  --output-name "RootB-expxs" --validity "${XS_EXPIRY}"

# Revoked bridge: Root B cross-signed by Root C, then revoked
"${SCRIPT_DIR}/cross_sign_roots.sh" --source-root "RootB" --signing-root "RootC" \
  --output-name "RootB-revxs" --validity "${BASE_VALIDITY}"

# Revoke the revoked bridge cert via Root C's CRL
REVXS_CERT="${CERT_DIR}/RootC/cross-signed/RootB-revxs.pem"
ROOTC_CERT="${CERT_DIR}/RootC/certs/RootC.pem"
ROOTC_KEY="${CERT_DIR}/RootC/private/RootC.key"
ROOTC_CNF="${CERT_DIR}/openssl.cnf"

# Initialize Root C's CA database if not present
if [ ! -f "${CERT_DIR}/RootC/index.txt" ]; then
  touch "${CERT_DIR}/RootC/index.txt"
fi
if [ ! -f "${CERT_DIR}/RootC/crlnumber" ]; then
  echo 1000 > "${CERT_DIR}/RootC/crlnumber"
fi
mkdir -p "${CERT_DIR}/RootC/crl"

revoke_certificate "${REVXS_CERT}" "${ROOTC_CERT}" "${ROOTC_KEY}" \
  "${ROOTC_CNF}" "${CERT_DIR}/RootC/crl/RootB-revxs.crl"

# ─── Step 5: Copy P12 Bundles to Output Directory ─────────────────────

echo_a "Copying P12 bundles to ${OUT_DIR}..."

# Find and copy P12 files from the CA directory tree
find_and_copy_p12() {
  local cert_name="$1"
  local p12_path
  p12_path=$(find "${CERT_DIR}" -name "${cert_name}.p12" -print -quit 2>/dev/null)
  if [ -n "${p12_path}" ]; then
    cp "${p12_path}" "${OUT_DIR}/${cert_name}.p12"
    echo_t "Copied ${cert_name}.p12 to ${OUT_DIR}/"
  else
    echo_a "WARNING: ${cert_name}.p12 not found in ${CERT_DIR}"
  fi
}

find_and_copy_p12 "client-nobridge"
find_and_copy_p12 "client-xsign"
find_and_copy_p12 "client-expxs"
find_and_copy_p12 "client-revxs"
find_and_copy_p12 "crl-revoked"
find_and_copy_p12 "crl-valid"
find_and_copy_p12 "ica-revoked-leaf"
find_and_copy_p12 "ica-valid-leaf"
find_and_copy_p12 "ocsp-valid"
find_and_copy_p12 "ocsp-revoked"

# Copy bridge artefacts
mkdir -p "${OUT_DIR}/bridge"
cp "${CERT_DIR}/RootC/cross-signed/RootB-xsign.pem" "${OUT_DIR}/bridge/" 2>/dev/null || true
cp "${CERT_DIR}/RootC/cross-signed/RootB-expxs.pem" "${OUT_DIR}/bridge/" 2>/dev/null || true
cp "${CERT_DIR}/RootC/cross-signed/RootB-revxs.pem" "${OUT_DIR}/bridge/" 2>/dev/null || true

# Copy root certs for trust store population
mkdir -p "${OUT_DIR}/roots"
cp "${CERT_DIR}/RootA/certs/RootA.pem" "${OUT_DIR}/roots/" 2>/dev/null || true
cp "${CERT_DIR}/RootB/certs/RootB.pem" "${OUT_DIR}/roots/" 2>/dev/null || true
cp "${CERT_DIR}/RootC/certs/RootC.pem" "${OUT_DIR}/roots/" 2>/dev/null || true

# Copy CRL files
mkdir -p "${OUT_DIR}/crl"
find "${CERT_DIR}" -name "*.crl" -exec cp {} "${OUT_DIR}/crl/" \; 2>/dev/null || true


# ─── Step 6: Generate leaf-level CRLs for L3 revocation tests ─────────
#
# Generates a PEM CRL from a CA that marks one cert as revoked.
# Uses a self-contained minimal openssl.cnf so the CA database is
# isolated inside ${CERT_DIR}/<ca_name>/ and does not pollute the
# system CA database.
#
# Usage: generate_leaf_crl <ca_name> <revoked_cert_pem> <output_crl_pem>
generate_leaf_crl() {
  local ca_name="$1"
  local revoked_cert="$2"
  local out_crl="$3"

  local ca_cert="${CERT_DIR}/${ca_name}/certs/${ca_name}.pem"
  local ca_key="${CERT_DIR}/${ca_name}/private/${ca_name}.key"
  local db_dir="${CERT_DIR}/${ca_name}"

  if [ ! -f "${ca_cert}" ] || [ ! -f "${ca_key}" ]; then
    echo_a "WARNING: CA ${ca_name} not found; skipping CRL generation"
    return 1
  fi

  mkdir -p "${db_dir}/crl" "${db_dir}/newcerts"
  [ -f "${db_dir}/index.txt" ]  || touch "${db_dir}/index.txt"
  [ -f "${db_dir}/serial" ]     || echo "1000" > "${db_dir}/serial"
  [ -f "${db_dir}/crlnumber" ]  || echo "1000" > "${db_dir}/crlnumber"

  # Write a minimal CA config that references this CA's database
  local tmp_cnf
  tmp_cnf=$(mktemp "${db_dir}/ca_XXXXXX.cnf")
  cat > "${tmp_cnf}" << CAEOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = ${db_dir}
database         = \$dir/index.txt
new_certs_dir    = \$dir/newcerts
serial           = \$dir/serial
crlnumber        = \$dir/crlnumber
certificate      = ${ca_cert}
private_key      = ${ca_key}
default_md       = sha256
default_crl_days = 365
preserve         = no
policy           = policy_anything

[ policy_anything ]
commonName = optional
organizationName = optional

[ crl_ext ]
authorityKeyIdentifier = keyid:always
CAEOF

  # Revoke the cert in this CA's database (add to index.txt)
  if [ -f "${revoked_cert}" ]; then
    openssl ca -config "${tmp_cnf}" \
      -revoke "${revoked_cert}" \
      -crl_reason keyCompromise 2>/dev/null || true
  fi

  # Generate the CRL in PEM format
  openssl ca -config "${tmp_cnf}" \
    -gencrl \
    -crlexts crl_ext \
    -out "${out_crl}" 2>/dev/null || \
  openssl ca -config "${tmp_cnf}" \
    -gencrl \
    -out "${out_crl}" 2>/dev/null || true

  rm -f "${tmp_cnf}"

  if [ -f "${out_crl}" ]; then
    echo_a "  CRL: ${out_crl}"
  else
    echo_a "WARNING: CRL generation failed for CA ${ca_name}"
  fi
}

echo_a "Generating leaf-level CRLs for L3 revocation tests..."

# ICA-B CRL: marks crl-revoked leaf as revoked
generate_leaf_crl "ICA-B" \
  "${CERT_DIR}/ICA-B/certs/crl-revoked.pem" \
  "${CERT_DIR}/ICA-B/crl/ICA-B-leaf.crl"

# ICA-C CRL: marks ocsp-revoked leaf as revoked
generate_leaf_crl "ICA-C" \
  "${CERT_DIR}/ICA-C/certs/ocsp-revoked.pem" \
  "${CERT_DIR}/ICA-C/crl/ICA-C-leaf.crl"

# ─── Step 7: Export L3 material ────────────────────────────────────────

echo_a "Exporting L3 test material..."

L3_DIR="${OUT_DIR}/l3"
mkdir -p "${L3_DIR}"

# Trust-store bundles consumed by mtls-xs-server.js
cp "${CERT_DIR}/RootB/certs/RootB.pem"  "${L3_DIR}/trust-rootb.pem" 2>/dev/null || true
cp "${CERT_DIR}/RootC/certs/RootC.pem"  "${L3_DIR}/trust-rootc.pem" 2>/dev/null || true

# CRL files for revocation-enforcing servers
cp "${CERT_DIR}/ICA-B/crl/ICA-B-leaf.crl" "${L3_DIR}/crl-icab.pem"  2>/dev/null || true
cp "${CERT_DIR}/ICA-C/crl/ICA-C-leaf.crl" "${L3_DIR}/crl-icac.pem"  2>/dev/null || true

# ── Bridge-embedded P12 for cross-sign success test ──────────────────
# Bundles: client-xsign.pem + ICA-B.pem (chain) + RootB-xsign.pem (bridge)
# When presented in the TLS handshake this chain resolves to RootC (trust anchor).
_XS_CERT="${CERT_DIR}/ICA-B/certs/client-xsign.pem"
_XS_KEY="${CERT_DIR}/ICA-B/private/client-xsign.key"
_BRIDGE_PEM="${CERT_DIR}/RootC/cross-signed/RootB-xsign.pem"
_ICAB_PEM="${CERT_DIR}/ICA-B/certs/ICA-B.pem"

if [ -f "${_XS_CERT}" ] && [ -f "${_XS_KEY}" ] && \
   [ -f "${_BRIDGE_PEM}" ] && [ -f "${_ICAB_PEM}" ]; then
  _CHAIN_TMP=$(mktemp /tmp/l3chain_XXXXXX.pem)
  cat "${_ICAB_PEM}" "${_BRIDGE_PEM}" > "${_CHAIN_TMP}"
  openssl pkcs12 -export \
    -in  "${_XS_CERT}" \
    -inkey "${_XS_KEY}" \
    -certfile "${_CHAIN_TMP}" \
    -out "${L3_DIR}/client-xsign-withbridge.p12" \
    -passout pass:changeit \
    -name "client-xsign-withbridge" 2>/dev/null
  rm -f "${_CHAIN_TMP}"
  echo_t "Created client-xsign-withbridge.p12"
else
  echo_a "WARNING: Could not create client-xsign-withbridge.p12 — source PEMs missing"
fi

# Copy client cert P12s used by L3 test cases
for _p12 in client-nobridge crl-valid crl-revoked ocsp-valid ocsp-revoked; do
  [ -f "${OUT_DIR}/${_p12}.p12" ] && \
    cp "${OUT_DIR}/${_p12}.p12" "${L3_DIR}/${_p12}.p12" 2>/dev/null || true
done

# Sentinel: tells mock-xconf that L3 PKI material is ready
touch "${OUT_DIR}/xs-pki-ready"
echo_a "Sentinel written: ${OUT_DIR}/xs-pki-ready"

echo_a "=== PKI Generation Complete ==="
echo_a "P12 bundles:  ${OUT_DIR}/*.p12"
echo_a "Bridge certs: ${OUT_DIR}/bridge/"
echo_a "Root certs:   ${OUT_DIR}/roots/"
echo_a "CRL files:    ${OUT_DIR}/crl/"
