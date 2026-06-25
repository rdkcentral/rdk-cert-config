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
# generate_crl_test_certs.sh
#
# Generates the CRL mTLS PKI used by L3 CRL revocation and OCSP tests.
# Calls create_ca.sh, create_leaf_cert.sh, and cert_utils.sh helpers.
#
# PKI hierarchy produced:
#
#   Test-CRL-Root (ECC P-256, self-signed)
#     └── Test-CRL-ICA
#           ├── crl-server.pem   (serverAuth, SAN=mockxconf, NOT in CA DB)
#           ├── crl-client.pem   (clientAuth, tracked in CA DB for revocation)
#           ├── ocsp-server.pem  (serverAuth, AIA→OCSP, tracked in CA DB)
#           └── ocsp-responder.pem (OCSPSigning, NOT in CA DB)
#
# Environment variables:
#   CERT_DIR        Root directory for CA material    (default: /etc/pki/test-crl)
#   OUT_DIR         Target for server output files    (default: /etc/xconf/certs/crl)
#   CLIENT_OUT_DIR  Target for client cert assets     (default: OUT_DIR)
#   OCSP_OUT_DIR    Target for OCSP server certs      (default: OUT_DIR)
#   SERVER_CN       Common Name + SAN for server cert (default: mockxconf)
##########################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────
CERT_DIR="${CERT_DIR:-/etc/pki/test-crl}"
OUT_DIR="${OUT_DIR:-/etc/xconf/certs/crl}"
CLIENT_OUT_DIR="${CLIENT_OUT_DIR:-${OUT_DIR}}"
OCSP_OUT_DIR="${OCSP_OUT_DIR:-${OUT_DIR}}"
SERVER_CN="${SERVER_CN:-mockxconf}"
CERT_PASSWORD="${CERT_PASSWORD:-changeit}"

CRL_ROOT="Test-CRL-Root"
CRL_ICA="Test-CRL-ICA"
CRL_ROOT_DIR="${CERT_DIR}/${CRL_ROOT}"
CRL_ICA_DIR="${CRL_ROOT_DIR}/${CRL_ICA}"

echo "[crl-pki] Generating CRL mTLS test PKI..."
echo "[crl-pki]   CERT_DIR=${CERT_DIR}"
echo "[crl-pki]   OUT_DIR=${OUT_DIR}"
echo "[crl-pki]   CLIENT_OUT_DIR=${CLIENT_OUT_DIR}"
echo "[crl-pki]   OCSP_OUT_DIR=${OCSP_OUT_DIR}"
echo "[crl-pki]   SERVER_CN=${SERVER_CN}"
mkdir -p "${CERT_DIR}"
mkdir -p "${OUT_DIR}"

# ── 1. Create Root CA and Intermediate CA ─────────────────────────────────────
CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/create_ca.sh" \
    --ca-name "${CRL_ROOT}" --parent-ca "${CRL_ROOT}" \
    --validity 365 --key-type ecc

CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/create_ca.sh" \
    --ca-name "${CRL_ICA}" --parent-ca "${CRL_ROOT}" \
    --validity 365 --key-type ecc

echo "[crl-pki] Root CA and ICA created"

# ── 2. Create CRL client cert (tracked in CA DB for live revocation) ──────────
CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/create_leaf_cert.sh" \
    --cert-name "crl-client" --ca-name "${CRL_ICA}" \
    --cn "crl-client" --type client --validity 365 \
    --ca-track --no-p12

echo "[crl-pki] Client cert created (tracked in CA DB)"

# ── 3. Create CRL server cert (NOT tracked — stays valid during revoke) ───────
CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/create_leaf_cert.sh" \
    --cert-name "crl-server" --ca-name "${CRL_ICA}" \
    --cn "${SERVER_CN}" --type server --validity 365 \
    --no-p12

echo "[crl-pki] Server cert created (SAN=${SERVER_CN})"

# ── 4. Create OCSP server cert (tracked — responder can attest 'good') ────────
CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/create_leaf_cert.sh" \
    --cert-name "ocsp-server" --ca-name "${CRL_ICA}" \
    --cn "${SERVER_CN}" --type server --validity 365 \
    --ca-track --san "DNS:${SERVER_CN}" --aia "http://127.0.0.1:50063" --no-p12

echo "[crl-pki] OCSP server cert created (tracked, AIA→http://127.0.0.1:50063)"

# ── 5. Create OCSP responder cert (EKU=OCSPSigning) ──────────────────────────
CERT_DIR="${CERT_DIR}" "${SCRIPT_DIR}/create_leaf_cert.sh" \
    --cert-name "ocsp-responder" --ca-name "${CRL_ICA}" \
    --cn "ocsp-responder" --type client --validity 365 \
    --ca-track --eku "OCSPSigning" --no-p12

echo "[crl-pki] OCSP responder cert created (EKU=OCSPSigning)"

# ── 6. Generate empty CRLs ────────────────────────────────────────────────────
source "${SCRIPT_DIR}/cert_utils.sh"

generate_empty_crl "${CRL_ICA_DIR}" "${CRL_ICA}" "${OUT_DIR}/Test-CRL-ICA.crl.pem"
generate_empty_crl "${CRL_ROOT_DIR}" "${CRL_ROOT}" "${OUT_DIR}/Test-CRL-Root.crl.pem"
cp "${OUT_DIR}/Test-CRL-Root.crl.pem" "${CRL_ROOT_DIR}/crl/Test-CRL-Root.crl.pem"

echo "[crl-pki] Empty CRLs generated"

# ── 7. Bundle client P12 and copy outputs ─────────────────────────────────────
mkdir -p "${CLIENT_OUT_DIR}"
mkdir -p "${OCSP_OUT_DIR}"

create_cert_chain \
    "${CRL_ICA_DIR}/certs/${CRL_ICA}.pem" \
    "${CRL_ROOT_DIR}/${CRL_ROOT}_chain.pem" \
    "${CLIENT_OUT_DIR}/crl-ica-chain.pem"

create_pkcs12 \
    "${CRL_ICA_DIR}/certs/crl-client.pem" \
    "${CRL_ICA_DIR}/private/crl-client.key" \
    "${CLIENT_OUT_DIR}/crl-ica-chain.pem" \
    "${CLIENT_OUT_DIR}/crl-client.p12" \
    "${CERT_PASSWORD}" \
    "crl-client"

cp "${CRL_ICA_DIR}/certs/crl-client.pem"       "${CLIENT_OUT_DIR}/crl-client.pem"
cp "${CRL_ICA_DIR}/private/crl-client.key"     "${CLIENT_OUT_DIR}/crl-client.key"
chmod 600 "${CLIENT_OUT_DIR}/crl-client.key"

cp "${CRL_ROOT_DIR}/certs/${CRL_ROOT}.pem"     "${CLIENT_OUT_DIR}/Test-CRL-Root.pem"

cp "${CRL_ICA_DIR}/certs/crl-server.pem"       "${OUT_DIR}/crl-server.pem"
cp "${CRL_ICA_DIR}/private/crl-server.key"     "${OUT_DIR}/crl-server.key"
chmod 600 "${OUT_DIR}/crl-server.key"

cp "${CRL_ICA_DIR}/certs/${CRL_ICA}.pem"       "${OUT_DIR}/Test-CRL-ICA.pem"
cp "${CRL_ROOT_DIR}/certs/${CRL_ROOT}.pem"     "${OUT_DIR}/Test-CRL-Root.pem"

cp "${CRL_ICA_DIR}/certs/ocsp-server.pem"      "${OCSP_OUT_DIR}/ocsp-server.pem"
cp "${CRL_ICA_DIR}/private/ocsp-server.key"    "${OCSP_OUT_DIR}/ocsp-server.key"
chmod 600 "${OCSP_OUT_DIR}/ocsp-server.key"

cp "${CRL_ICA_DIR}/certs/ocsp-responder.pem"   "${OCSP_OUT_DIR}/ocsp-responder.pem"
cp "${CRL_ICA_DIR}/private/ocsp-responder.key" "${OCSP_OUT_DIR}/ocsp-responder.key"
chmod 600 "${OCSP_OUT_DIR}/ocsp-responder.key"

cp "${CRL_ICA_DIR}/certs/${CRL_ICA}.pem"       "${OCSP_OUT_DIR}/Test-CRL-ICA.pem"
cp "${CRL_ROOT_DIR}/certs/${CRL_ROOT}.pem"     "${OCSP_OUT_DIR}/Test-CRL-Root.pem"

# CA chain for OCSP daemon
cat "${CRL_ICA_DIR}/certs/${CRL_ICA}.pem" \
    "${CRL_ROOT_DIR}/certs/${CRL_ROOT}.pem" > "${OCSP_OUT_DIR}/ocsp-ca-chain.pem"

echo "[crl-pki] All CRL test cert assets generated"
echo "[crl-pki] Done."
