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
# generate_cross_signed_test_certs.sh
#
# Generates the cross-signed PKI topology used by L3 mTLS tests.
#
# PKI hierarchy produced:
#
#   OldRoot (ECC P-256, self-signed)
#     └── OldICA
#           ├── client-old.p12         L3 cross-sign negative test
#           ├── client-xsign.p12       L3 cross-sign bridge test
#           └── client-expxs.p12       L3 expired bridge test
#
#   NewRoot (ECC P-256, self-signed)   (signs the cross-signed bridges)
#
#   Cross-signed bridge artefacts:
#     OldRoot-xsign.pem   — OldRoot re-signed by NewRoot (full validity)
#     OldRoot-expxs.pem   — OldRoot re-signed by NewRoot (XS_EXPIRY days)
#
#   Post-processing (folded in from the former generate_xs_crl_and_expired_bridge.sh):
#     - empty XS CRLs (*.crl.pem) for every XS CA, required by OpenSSL 3
#       CRL_CHECK_ALL when the mTLS server verifies the full xsign chain
#     - a truly-expired OldRoot-expxs bridge, re-bundled into client-expxs.p12
#     - NewRoot.pem exported as the xsign trust anchor (written LAST)
#
# Environment variables:
#   CERT_DIR      Root for CA/cert material     (default: /etc/pki/test-xs)
#   OUT_DIR       Target for final P12 bundles  (default: ./l2/xs)
#   BASE_VALIDITY Base cert validity in days    (default: 365)
#   XS_EXPIRY     Expiry-bridge validity days   (default: 1)
#   DEBUG_ENABLED Verbose trace (true/false)    (default: false)
##########################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Save caller-supplied CERT_DIR before sourcing cert_utils.sh.
# cert_utils.sh unconditionally sets CERT_DIR="/etc/pki" which would
# override any value the caller passed via environment variable.
_CALLER_CERT_DIR="${CERT_DIR:-}"

# Import utility functions and sub-scripts
source "${SCRIPT_DIR}/cert_utils.sh"

# ── Environment variable defaults ────────────────────────────────────────────
# Restore the caller's CERT_DIR (cert_utils.sh would have overwritten it).
CERT_DIR="${_CALLER_CERT_DIR:-/etc/pki/test-xs}"
OUT_DIR="${OUT_DIR:-./l2/xs}"
BASE_VALIDITY="${BASE_VALIDITY:-365}"
XS_EXPIRY="${XS_EXPIRY:-1}"
DEBUG_ENABLED="${DEBUG_ENABLED:-false}"
CERT_PASSWORD="changeit"

# Detect OpenSSL major version (1 or 3)
OPENSSL_MAJOR="$(openssl version | awk '{print $2}' | cut -d. -f1)"
echo_t "Detected OpenSSL major version: ${OPENSSL_MAJOR}"

# ── Helpers ──────────────────────────────────────────────────────────────────

# Locate a PEM cert file
find_pem() {
    local cert_name="$1"
    find "${CERT_DIR}" -name "${cert_name}.pem" 2>/dev/null | head -1
}

# Locate a private key file
find_key() {
    local cert_name="$1"
    find "${CERT_DIR}" -name "${cert_name}.key" 2>/dev/null | head -1
}



# ── Ensure output directory ───────────────────────────────────────────────────
mkdir -p "${OUT_DIR}"
mkdir -p "${CERT_DIR}"

# ── Step 1: Root CAs ──────────────────────────────────────────────────────────
echo_a "[xs-pki] Creating root CAs..."
CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/create_ca.sh" \
    --ca-name "Test-XS-OldRoot" --parent-ca "Test-XS-OldRoot" \
    --validity "${BASE_VALIDITY}" --key-type ecc
CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/create_ca.sh" \
    --ca-name "Test-XS-NewRoot" --parent-ca "Test-XS-NewRoot" \
    --validity "${BASE_VALIDITY}" --key-type ecc

# ── Step 2: Intermediate CAs ─────────────────────────────────────────────────
echo_a "[xs-pki] Creating intermediate CAs..."
CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/create_ca.sh" \
    --ca-name "Test-XS-OldICA" --parent-ca "Test-XS-OldRoot" \
    --validity "${BASE_VALIDITY}" --key-type ecc

# ── Step 3: Leaf certificates ─────────────────────────────────────────────────
echo_a "[xs-pki] Creating leaf certificates..."

# Under OldICA — only the 3 certs used by L3 cross-sign tests
for leaf in client-old client-xsign client-expxs; do
    CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/create_leaf_cert.sh" \
        --cert-name "${leaf}" --ca-name "Test-XS-OldICA" \
        --cn "${leaf}" --validity "${BASE_VALIDITY}" --type client
done

OLD_ICA_DIR="${CERT_DIR}/Test-XS-OldRoot/Test-XS-OldICA"
OLD_ROOT_DIR="${CERT_DIR}/Test-XS-OldRoot"

# ── Step 4: Cross-sign OldRoot under NewRoot ──────────────────────────────────
echo_a "[xs-pki] Generating cross-signed bridge certificates..."

NEW_ROOT_DIR="${CERT_DIR}/Test-XS-NewRoot"
CROSS_SIGNED_DIR="${NEW_ROOT_DIR}/cross-signed"
mkdir -p "${CROSS_SIGNED_DIR}"

XS_BRIDGE="${CROSS_SIGNED_DIR}/OldRoot-xsign.pem"
XS_EXPIRY_BRIDGE="${CROSS_SIGNED_DIR}/OldRoot-expxs.pem"

echo_a "[xs-pki] Cross-signing OldRoot under NewRoot (full validity)..."
CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/cross_sign_roots.sh" \
    --source-root "Test-XS-OldRoot" \
    --signing-root "Test-XS-NewRoot" \
    --output-name "OldRoot-xsign" \
    --validity "${BASE_VALIDITY}"

echo_a "[xs-pki] Cross-signing OldRoot under NewRoot (expiry bridge, ${XS_EXPIRY} day(s))..."
CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/cross_sign_roots.sh" \
    --source-root "Test-XS-OldRoot" \
    --signing-root "Test-XS-NewRoot" \
    --output-name "OldRoot-expxs" \
    --validity "${XS_EXPIRY}"

# ── Step 5: Assemble P12 bundles into OUT_DIR ─────────────────────────────────
echo_a "[xs-pki] Assembling P12 bundles into ${OUT_DIR}..."

# Build certificate chain files for use in bundles
OLD_ROOT_PEM="${OLD_ROOT_DIR}/certs/Test-XS-OldRoot.pem"
OLD_ICA_PEM="${OLD_ICA_DIR}/certs/Test-XS-OldICA.pem"
NEW_ROOT_PEM="${NEW_ROOT_DIR}/certs/Test-XS-NewRoot.pem"

# Chain: OldICA → OldRoot (standard)
OLD_CHAIN="${CERT_DIR}/old-chain.pem"
cat "${OLD_ICA_PEM}" "${OLD_ROOT_PEM}" > "${OLD_CHAIN}"

# Chain: OldICA → OldRoot → bridge → NewRoot  (for xsign bundle)
XSIGN_CHAIN="${CERT_DIR}/xsign-chain.pem"
cat "${OLD_ICA_PEM}" "${OLD_ROOT_PEM}" "${XS_BRIDGE}" "${NEW_ROOT_PEM}" > "${XSIGN_CHAIN}"

# Chain: OldICA → OldRoot → expiry-bridge → NewRoot  (for expxs bundle)
EXPXS_CHAIN="${CERT_DIR}/expxs-chain.pem"
cat "${OLD_ICA_PEM}" "${OLD_ROOT_PEM}" "${XS_EXPIRY_BRIDGE}" "${NEW_ROOT_PEM}" > "${EXPXS_CHAIN}"

# client-old.p12 — plain chain, no bridge
SRC_OLD_KEY="$(find_key "client-old")"
SRC_OLD_PEM="$(find_pem "client-old")"
if [ -n "${SRC_OLD_PEM}" ] && [ -n "${SRC_OLD_KEY}" ]; then
    create_pkcs12 "${SRC_OLD_PEM}" "${SRC_OLD_KEY}" "${OLD_CHAIN}" \
                  "${OUT_DIR}/client-old.p12" "${CERT_PASSWORD}" "client-old"
else
    echo_a "ERROR: client-old cert/key not found"; exit 1
fi

# client-xsign.p12 — leaf + chain + cross-signed bridge
SRC_XSIG_KEY="$(find_key "client-xsign")"
SRC_XSIG_PEM="$(find_pem "client-xsign")"
if [ -n "${SRC_XSIG_PEM}" ] && [ -n "${SRC_XSIG_KEY}" ]; then
    create_pkcs12 "${SRC_XSIG_PEM}" "${SRC_XSIG_KEY}" "${XSIGN_CHAIN}" \
                  "${OUT_DIR}/client-xsign.p12" "${CERT_PASSWORD}" "client-xsign"
else
    echo_a "ERROR: client-xsign cert/key not found"; exit 1
fi

# client-expxs.p12 — leaf + chain + expiry bridge
SRC_EXPXS_KEY="$(find_key "client-expxs")"
SRC_EXPXS_PEM="$(find_pem "client-expxs")"
if [ -n "${SRC_EXPXS_PEM}" ] && [ -n "${SRC_EXPXS_KEY}" ]; then
    create_pkcs12 "${SRC_EXPXS_PEM}" "${SRC_EXPXS_KEY}" "${EXPXS_CHAIN}" \
                  "${OUT_DIR}/client-expxs.p12" "${CERT_PASSWORD}" "client-expxs"
else
    echo_a "ERROR: client-expxs cert/key not found"; exit 1
fi

# ── Step 6: Verify bridge certificates ───────────────────────────────────────
echo_a "[xs-pki] Verifying cross-signed bridge..."
if openssl verify -CAfile "${NEW_ROOT_PEM}" "${XS_BRIDGE}" >/dev/null 2>&1; then
    echo_a "[xs-pki] ✓ OldRoot-xsign.pem verifies against NewRoot"
else
    echo_a "[xs-pki] WARNING: OldRoot-xsign.pem did NOT verify against NewRoot"
fi
# At this stage OldRoot-expxs.pem is still the short-validity (but currently
# valid) bridge; the truly-expired replacement is applied by the post-processing
# section at the end of this script. So it should verify successfully here.
if openssl verify -CAfile "${NEW_ROOT_PEM}" "${XS_EXPIRY_BRIDGE}" >/dev/null 2>&1; then
    echo_a "[xs-pki] ✓ OldRoot-expxs.pem verifies against NewRoot (short validity: ${XS_EXPIRY} day(s))"
else
    echo_a "[xs-pki] WARNING: OldRoot-expxs.pem did NOT verify against NewRoot"
fi

echo_a "[xs-pki] Done. P12 bundles written to: ${OUT_DIR}"

# ═════════════════════════════════════════════════════════════════════════════════
# Post-processing: XS CRLs + truly-expired bridge
# (previously the separate generate_xs_crl_and_expired_bridge.sh, folded in here
#  so the cross-signed PKI is produced by a single script.)
# ═════════════════════════════════════════════════════════════════════════════════
echo_a "[xs-pki] Post-processing: generating XS CRLs and expired bridge..."

# ── Generate empty CRLs for all XS CAs ──────────────────────────────────
for _CA_DIR in \
    "${CERT_DIR}/Test-XS-OldRoot" \
    "${CERT_DIR}/Test-XS-OldRoot/Test-XS-OldICA" \
    "${CERT_DIR}/Test-XS-NewRoot"; do
    _CA_NAME=$(basename "${_CA_DIR}")
    _CA_CERT="${_CA_DIR}/certs/${_CA_NAME}.pem"
    _CA_KEY="${_CA_DIR}/private/${_CA_NAME}.key"
    [ -f "${_CA_CERT}" ] && [ -f "${_CA_KEY}" ] || continue

    generate_empty_crl "${_CA_DIR}" "${_CA_NAME}" \
        "${_CA_DIR}/crl/${_CA_NAME}.crl.pem" 365
    cp "${_CA_DIR}/crl/${_CA_NAME}.crl.pem" "${OUT_DIR}/${_CA_NAME}.crl.pem"
done
echo_a "[xs-pki] XS PKI CRLs generated"

# ── Create truly-expired bridge cert ────────────────────────────────────
_NEWROOT_CERT="${CERT_DIR}/Test-XS-NewRoot/certs/Test-XS-NewRoot.pem"
_NEWROOT_KEY="${CERT_DIR}/Test-XS-NewRoot/private/Test-XS-NewRoot.key"
_OLDROOT_CERT="${CERT_DIR}/Test-XS-OldRoot/certs/Test-XS-OldRoot.pem"
_OLDROOT_KEY="${CERT_DIR}/Test-XS-OldRoot/private/Test-XS-OldRoot.key"
_EXPXS_BRIDGE="${CERT_DIR}/Test-XS-NewRoot/cross-signed/OldRoot-expxs.pem"
_NR_DIR="${CERT_DIR}/Test-XS-NewRoot"

_OLD_SUBJ=$(openssl x509 -in "${_OLDROOT_CERT}" -noout -subject -nameopt compat 2>/dev/null | sed 's/^subject=//')

# Ensure NewRoot has a CA DB config for signing
create_ca_db_config "${_NR_DIR}" "Test-XS-NewRoot"

# Append v3_ca extensions to the existing config (idempotent — the config may
# already exist and carry the section from a previous run).
if ! grep -q '^\[ v3_ca \]' "${_NR_DIR}/openssl.cnf"; then
    cat >> "${_NR_DIR}/openssl.cnf" << 'EXTEOF'

[ v3_ca ]
basicConstraints       = critical,CA:TRUE
keyUsage               = critical,digitalSignature,cRLSign,keyCertSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
EXTEOF
fi

_OLDROOT_EXPIRED_CSR="$(mktemp)"
openssl req -new \
    -key "${_OLDROOT_KEY}" \
    -out "${_OLDROOT_EXPIRED_CSR}" \
    -subj "${_OLD_SUBJ}" 2>/dev/null

openssl ca \
    -config "${_NR_DIR}/openssl.cnf" \
    -in "${_OLDROOT_EXPIRED_CSR}" \
    -out "${_EXPXS_BRIDGE}" \
    -startdate 20240101000000Z \
    -enddate   20240102000000Z \
    -extensions v3_ca \
    -batch \
    -notext 2>/dev/null
rm -f "${_OLDROOT_EXPIRED_CSR}"

# Re-bundle client-expxs.p12 with the expired bridge
_EXPXS_KEY=$(find "${CERT_DIR}" -name "client-expxs.key" 2>/dev/null | head -1)
_EXPXS_PEM=$(find "${CERT_DIR}" -name "client-expxs.pem" 2>/dev/null | head -1)
_OLD_ICA="${CERT_DIR}/Test-XS-OldRoot/Test-XS-OldICA/certs/Test-XS-OldICA.pem"
_CHAIN_TMP="$(mktemp)"
cat "${_OLD_ICA}" "${_OLDROOT_CERT}" "${_EXPXS_BRIDGE}" "${_NEWROOT_CERT}" > "${_CHAIN_TMP}"

PKCS12_PASS="${CERT_PASSWORD}" openssl pkcs12 -export \
    -in "${_EXPXS_PEM}" \
    -inkey "${_EXPXS_KEY}" \
    -certfile "${_CHAIN_TMP}" \
    -out "${OUT_DIR}/client-expxs.p12" \
    -name "client-expxs" \
    -passout env:PKCS12_PASS 2>/dev/null
chmod 600 "${OUT_DIR}/client-expxs.p12"
rm -f "${_CHAIN_TMP}"
echo_a "[xs-pki] Replaced expired bridge with truly-expired cert (2024-01-01/02)"

# Copy NewRoot for trust anchor. Written LAST and ONLY here, so the docker
# native-platform certs.sh gates its xsign copy on this file as the readiness
# sentinel (avoids racing the client-expxs.p12 double-write above).
[ -f "${_NEWROOT_CERT}" ] && cp "${_NEWROOT_CERT}" "${OUT_DIR}/NewRoot.pem"

echo_a "[xs-pki] Post-processing complete."
