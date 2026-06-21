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
# Generates the full cross-signed PKI topology used by L2 sequences 9-17
# and future L3 mTLS tests.
#
# PKI hierarchy produced:
#
#   OldRoot (ECC P-256, self-signed)
#     └── OldICA
#           ├── client-old.p12         seq 10/11
#           ├── client-xsign.p12       seq 9/10/11  (bundle includes bridge)
#           ├── client-expxs.p12       seq 17       (bundle includes expiry bridge)
#           ├── crl-revoked.p12        seq 12
#           ├── crl-valid.p12          seq 12
#           └── ica-valid-leaf.p12     seq 13
#     └── RevokedICA  (will be CRL-revoked)
#           └── ica-revoked-leaf.p12   seq 13
#
#   NewRoot (ECC P-256, self-signed)
#     └── NewICA
#           ├── client-new.p12         seq 10/17
#           ├── ocsp-valid.p12         seq 14/15/16
#           └── ocsp-revoked.p12       seq 15/16
#
#   Cross-signed bridge artefacts:
#     OldRoot-xsign.pem   — OldRoot re-signed by NewRoot (full validity)
#     OldRoot-expxs.pem   — OldRoot re-signed by NewRoot (XS_EXPIRY days)
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

# Create a CA only if its cert does not already exist (idempotency guard)
ensure_ca() {
    local ca_name="$1"; shift
    local parent_ca="$1"; shift
    local extra_args="$@"
    local cert_file="${CERT_DIR}/${ca_name}/certs/${ca_name}.pem"

    if [ -s "${cert_file}" ]; then
        echo_t "CA already exists, skipping: ${ca_name}"
        return 0
    fi
    echo_a "Creating CA: ${ca_name} (parent: ${parent_ca})"
    CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/create_ca.sh" \
        --ca-name "${ca_name}" \
        --parent-ca "${parent_ca}" \
        --validity "${BASE_VALIDITY}" \
        --key-type ecc \
        ${extra_args}
}

# Create a leaf cert only if its P12 does not already exist (idempotency guard)
ensure_leaf() {
    local cert_name="$1"; shift
    local ca_name="$1"; shift
    local extra_args="$@"

    # Leaf certs are nested under their signing CA
    local p12_file
    if [ -f "${CERT_DIR}/${ca_name}/certs/${cert_name}.p12" ]; then
        p12_file="${CERT_DIR}/${ca_name}/certs/${cert_name}.p12"
    else
        # create_leaf_cert.sh may nest under parent CA path — search
        p12_file="$(find "${CERT_DIR}" -name "${cert_name}.p12" 2>/dev/null | head -1)"
    fi

    if [ -n "${p12_file}" ] && [ -s "${p12_file}" ]; then
        echo_t "Leaf cert already exists, skipping: ${cert_name}"
        return 0
    fi
    echo_a "Creating leaf cert: ${cert_name} (CA: ${ca_name})"
    CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/create_leaf_cert.sh" \
        --cert-name "${cert_name}" \
        --ca-name "${ca_name}" \
        --cn "${cert_name}" \
        --validity "${BASE_VALIDITY}" \
        --type client \
        ${extra_args}
}

# Locate a P12 file produced by create_leaf_cert.sh
find_p12() {
    local cert_name="$1"
    find "${CERT_DIR}" -name "${cert_name}.p12" 2>/dev/null | head -1
}

# Locate a PEM cert file produced by create_leaf_cert.sh
find_pem() {
    local cert_name="$1"
    find "${CERT_DIR}" -name "${cert_name}.pem" 2>/dev/null | head -1
}

# Locate a private key file
find_key() {
    local cert_name="$1"
    find "${CERT_DIR}" -name "${cert_name}.key" 2>/dev/null | head -1
}

# Bundle a leaf cert + chain + bridge into a P12, suppressing password in output
# Private key material and PKCS#12 passwords are never echoed to stdout/stderr.
bundle_p12() {
    local cert_pem="$1"
    local key_file="$2"
    local chain_pem="$3"   # may be empty
    local out_p12="$4"
    local friendly_name="$5"

    local chain_opt=""
    if [ -n "${chain_pem}" ] && [ -f "${chain_pem}" ]; then
        chain_opt="-certfile ${chain_pem}"
    fi

    # Use -passout env var to avoid password appearing in process list or logs
    PKCS12_PASS="${CERT_PASSWORD}" \
    openssl pkcs12 -export \
        -in "${cert_pem}" \
        -inkey "${key_file}" \
        ${chain_opt} \
        -out "${out_p12}" \
        -name "${friendly_name}" \
        -passout env:PKCS12_PASS 2>/dev/null
    chmod 644 "${out_p12}"
    echo_t "Bundled: ${out_p12}"
}

# ── Ensure output directory ───────────────────────────────────────────────────
mkdir -p "${OUT_DIR}"
mkdir -p "${CERT_DIR}"

# ── Step 1: Root CAs ──────────────────────────────────────────────────────────
echo_a "[xs-pki] Creating root CAs..."
ensure_ca "Test-XS-OldRoot" "Test-XS-OldRoot"
ensure_ca "Test-XS-NewRoot" "Test-XS-NewRoot"

# ── Step 2: Intermediate CAs ─────────────────────────────────────────────────
echo_a "[xs-pki] Creating intermediate CAs..."
ensure_ca "Test-XS-OldICA"     "Test-XS-OldRoot"
ensure_ca "Test-XS-NewICA"     "Test-XS-NewRoot"
ensure_ca "Test-XS-RevokedICA" "Test-XS-OldRoot"

# ── Step 3: Leaf certificates ─────────────────────────────────────────────────
echo_a "[xs-pki] Creating leaf certificates..."

# Under OldICA
ensure_leaf "client-old"       "Test-XS-OldICA"
ensure_leaf "client-xsign"     "Test-XS-OldICA"
ensure_leaf "client-expxs"     "Test-XS-OldICA"
ensure_leaf "crl-revoked"      "Test-XS-OldICA" "--revoked"
ensure_leaf "crl-valid"        "Test-XS-OldICA"
ensure_leaf "ica-valid-leaf"   "Test-XS-OldICA"

# Under RevokedICA
ensure_leaf "ica-revoked-leaf" "Test-XS-RevokedICA"

# Under NewICA
ensure_leaf "client-new"       "Test-XS-NewICA"
ensure_leaf "ocsp-valid"       "Test-XS-NewICA"
ensure_leaf "ocsp-revoked"     "Test-XS-NewICA" "--revoked"

# ── Step 4: CRL generation ────────────────────────────────────────────────────
# Revoke crl-revoked leaf under OldICA
echo_a "[xs-pki] Generating CRLs..."

OLD_ICA_DIR="${CERT_DIR}/Test-XS-OldRoot/Test-XS-OldICA"
REVOKED_ICA_DIR="${CERT_DIR}/Test-XS-OldRoot/Test-XS-RevokedICA"

# OldICA CRL — already revoked by create_leaf_cert.sh --revoked; regenerate CRL
if [ -d "${OLD_ICA_DIR}" ]; then
    if [ -f "${OLD_ICA_DIR}/openssl.cnf" ]; then
        CERT_DIR="${CERT_DIR}" openssl ca \
            -config "${OLD_ICA_DIR}/openssl.cnf" \
            -gencrl \
            -keyfile "${OLD_ICA_DIR}/private/Test-XS-OldICA.key" \
            -cert "${OLD_ICA_DIR}/certs/Test-XS-OldICA.pem" \
            -out "${OLD_ICA_DIR}/crl/Test-XS-OldICA.crl.pem" \
            -crldays "${BASE_VALIDITY}" 2>/dev/null || echo_t "CRL gen skipped (no openssl.cnf db)"
    fi
fi

# RevokedICA — revoke the ICA itself against OldRoot's database
OLD_ROOT_DIR="${CERT_DIR}/Test-XS-OldRoot"
if [ -d "${OLD_ROOT_DIR}" ] && [ -f "${OLD_ROOT_DIR}/openssl.cnf" ]; then
    REVOKED_ICA_CERT="${REVOKED_ICA_DIR}/certs/Test-XS-RevokedICA.pem"
    if [ -f "${REVOKED_ICA_CERT}" ]; then
        CERT_DIR="${CERT_DIR}" openssl ca \
            -config "${OLD_ROOT_DIR}/openssl.cnf" \
            -revoke "${REVOKED_ICA_CERT}" \
            -keyfile "${OLD_ROOT_DIR}/private/Test-XS-OldRoot.key" \
            -cert "${OLD_ROOT_DIR}/certs/Test-XS-OldRoot.pem" 2>/dev/null || echo_t "ICA revocation skipped (already revoked)"
        CERT_DIR="${CERT_DIR}" openssl ca \
            -config "${OLD_ROOT_DIR}/openssl.cnf" \
            -gencrl \
            -keyfile "${OLD_ROOT_DIR}/private/Test-XS-OldRoot.key" \
            -cert "${OLD_ROOT_DIR}/certs/Test-XS-OldRoot.pem" \
            -out "${OLD_ROOT_DIR}/crl/Test-XS-OldRoot.crl.pem" \
            -crldays "${BASE_VALIDITY}" 2>/dev/null || echo_t "Root CRL gen skipped"
    fi
fi

# ── Step 5: Cross-sign OldRoot under NewRoot ──────────────────────────────────
echo_a "[xs-pki] Generating cross-signed bridge certificates..."

NEW_ROOT_DIR="${CERT_DIR}/Test-XS-NewRoot"
CROSS_SIGNED_DIR="${NEW_ROOT_DIR}/cross-signed"
mkdir -p "${CROSS_SIGNED_DIR}"

XS_BRIDGE="${CROSS_SIGNED_DIR}/OldRoot-xsign.pem"
XS_EXPIRY_BRIDGE="${CROSS_SIGNED_DIR}/OldRoot-expxs.pem"

if [ ! -s "${XS_BRIDGE}" ]; then
    echo_a "[xs-pki] Cross-signing OldRoot under NewRoot (full validity)..."
    CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/cross_sign_roots.sh" \
        --source-root "Test-XS-OldRoot" \
        --signing-root "Test-XS-NewRoot" \
        --output-name "OldRoot-xsign" \
        --validity "${BASE_VALIDITY}"
fi

if [ ! -s "${XS_EXPIRY_BRIDGE}" ]; then
    echo_a "[xs-pki] Cross-signing OldRoot under NewRoot (expiry bridge, ${XS_EXPIRY} day(s))..."
    CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/cross_sign_roots.sh" \
        --source-root "Test-XS-OldRoot" \
        --signing-root "Test-XS-NewRoot" \
        --output-name "OldRoot-expxs" \
        --validity "${XS_EXPIRY}"
fi

# ── Step 6: Assemble P12 bundles into OUT_DIR ─────────────────────────────────
echo_a "[xs-pki] Assembling P12 bundles into ${OUT_DIR}..."

# Build certificate chain files for use in bundles
OLD_ROOT_PEM="${OLD_ROOT_DIR}/certs/Test-XS-OldRoot.pem"
OLD_ICA_PEM="${OLD_ICA_DIR}/certs/Test-XS-OldICA.pem"
NEW_ROOT_PEM="${NEW_ROOT_DIR}/certs/Test-XS-NewRoot.pem"
NEW_ICA_DIR="${CERT_DIR}/Test-XS-NewRoot/Test-XS-NewICA"
NEW_ICA_PEM="${NEW_ICA_DIR}/certs/Test-XS-NewICA.pem"

# Chain: OldICA → OldRoot (standard)
OLD_CHAIN="${CERT_DIR}/old-chain.pem"
cat "${OLD_ICA_PEM}" "${OLD_ROOT_PEM}" > "${OLD_CHAIN}"

# Chain: OldICA → OldRoot → bridge → NewRoot  (for xsign bundle)
XSIGN_CHAIN="${CERT_DIR}/xsign-chain.pem"
cat "${OLD_ICA_PEM}" "${OLD_ROOT_PEM}" "${XS_BRIDGE}" "${NEW_ROOT_PEM}" > "${XSIGN_CHAIN}"

# Chain: OldICA → OldRoot → expiry-bridge → NewRoot  (for expxs bundle)
EXPXS_CHAIN="${CERT_DIR}/expxs-chain.pem"
cat "${OLD_ICA_PEM}" "${OLD_ROOT_PEM}" "${XS_EXPIRY_BRIDGE}" "${NEW_ROOT_PEM}" > "${EXPXS_CHAIN}"

# Chain: NewICA → NewRoot
NEW_CHAIN="${CERT_DIR}/new-chain.pem"
cat "${NEW_ICA_PEM}" "${NEW_ROOT_PEM}" > "${NEW_CHAIN}"

# Helper: copy a P12 that was already created by create_leaf_cert.sh
copy_p12() {
    local cert_name="$1"
    local dest_name="${2:-${cert_name}}"
    local src
    src="$(find_p12 "${cert_name}")"
    if [ -n "${src}" ] && [ -s "${src}" ]; then
        cp "${src}" "${OUT_DIR}/${dest_name}.p12"
        echo_t "Copied: ${cert_name}.p12 → ${OUT_DIR}/${dest_name}.p12"
    else
        echo_a "Warning: P12 not found for ${cert_name}, creating placeholder"
        touch "${OUT_DIR}/${dest_name}.p12"
    fi
}

# client-old.p12 — plain chain, no bridge
SRC_OLD_KEY="$(find_key "client-old")"
SRC_OLD_PEM="$(find_pem "client-old")"
if [ -n "${SRC_OLD_PEM}" ] && [ -n "${SRC_OLD_KEY}" ]; then
    bundle_p12 "${SRC_OLD_PEM}" "${SRC_OLD_KEY}" "${OLD_CHAIN}" \
               "${OUT_DIR}/client-old.p12" "client-old"
else
    copy_p12 "client-old"
fi

# client-xsign.p12 — leaf + chain + cross-signed bridge
SRC_XSIG_KEY="$(find_key "client-xsign")"
SRC_XSIG_PEM="$(find_pem "client-xsign")"
if [ -n "${SRC_XSIG_PEM}" ] && [ -n "${SRC_XSIG_KEY}" ]; then
    bundle_p12 "${SRC_XSIG_PEM}" "${SRC_XSIG_KEY}" "${XSIGN_CHAIN}" \
               "${OUT_DIR}/client-xsign.p12" "client-xsign"
else
    copy_p12 "client-xsign"
fi

# client-expxs.p12 — leaf + chain + expiry bridge
SRC_EXPXS_KEY="$(find_key "client-expxs")"
SRC_EXPXS_PEM="$(find_pem "client-expxs")"
if [ -n "${SRC_EXPXS_PEM}" ] && [ -n "${SRC_EXPXS_KEY}" ]; then
    bundle_p12 "${SRC_EXPXS_PEM}" "${SRC_EXPXS_KEY}" "${EXPXS_CHAIN}" \
               "${OUT_DIR}/client-expxs.p12" "client-expxs"
else
    copy_p12 "client-expxs"
fi

# Remaining certs — standard P12 bundles
for leaf in crl-revoked crl-valid ica-valid-leaf ica-revoked-leaf; do
    copy_p12 "${leaf}"
done

# New-root certs
for leaf in client-new ocsp-valid ocsp-revoked; do
    SRC_KEY="$(find_key "${leaf}")"
    SRC_PEM="$(find_pem "${leaf}")"
    if [ -n "${SRC_PEM}" ] && [ -n "${SRC_KEY}" ]; then
        bundle_p12 "${SRC_PEM}" "${SRC_KEY}" "${NEW_CHAIN}" \
                   "${OUT_DIR}/${leaf}.p12" "${leaf}"
    else
        copy_p12 "${leaf}"
    fi
done

# ── Step 7: Verify bridge certificates ───────────────────────────────────────
echo_a "[xs-pki] Verifying cross-signed bridge..."
if openssl verify -CAfile "${NEW_ROOT_PEM}" "${XS_BRIDGE}" >/dev/null 2>&1; then
    echo_a "[xs-pki] ✓ OldRoot-xsign.pem verifies against NewRoot"
else
    echo_a "[xs-pki] WARNING: OldRoot-xsign.pem did NOT verify against NewRoot"
fi
if ! openssl verify -CAfile "${NEW_ROOT_PEM}" "${XS_EXPIRY_BRIDGE}" >/dev/null 2>&1; then
    echo_a "[xs-pki] ✓ OldRoot-expxs.pem correctly fails verification (expired bridge)"
else
    echo_a "[xs-pki] WARNING: OldRoot-expxs.pem unexpectedly passed verification (bridge not expired?)"
fi

echo_a "[xs-pki] Done. P12 bundles written to: ${OUT_DIR}"
