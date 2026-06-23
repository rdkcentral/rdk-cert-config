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
# Generates the CRL mTLS PKI used by L3 CRL revocation tests.
#
# PKI hierarchy produced:
#
#   Test-CRL-Root (ECC P-256, self-signed)
#     └── Test-CRL-ICA
#           ├── crl-server.pem   (serverAuth, SAN=mockxconf)
#           ├── crl-client.pem   (clientAuth, tracked in CA DB for revocation)
#           └── crl-client.p12   (PKCS#12 bundle for curl --cert)
#
# Outputs:
#   ${OUT_DIR}/crl-server.key          server private key
#   ${OUT_DIR}/crl-server.pem          server TLS cert
#   ${OUT_DIR}/Test-CRL-ICA.pem        ICA cert (for server CA trust)
#   ${OUT_DIR}/Test-CRL-Root.pem       root cert (for client trust store)
#   ${OUT_DIR}/Test-CRL-ICA.crl.pem    initial empty CRL (ICA-level)
#   ${OUT_DIR}/Test-CRL-Root.crl.pem   initial empty CRL (root-level)
#   ${OUT_DIR}/crl-client.pem          client cert
#   ${OUT_DIR}/crl-client.key          client private key
#   ${OUT_DIR}/crl-client.p12          client PKCS#12 bundle
#   ${OUT_DIR}/crl-ica-chain.pem       ICA + Root chain
#
# Environment variables:
#   CERT_DIR   Root directory for CA material    (default: /etc/pki/test-crl)
#   OUT_DIR    Target for final output files     (default: /etc/xconf/certs/crl)
#   SERVER_CN  Common Name + SAN for server cert (default: mockxconf)
##########################################################################

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
CERT_DIR="${CERT_DIR:-/etc/pki/test-crl}"
OUT_DIR="${OUT_DIR:-/etc/xconf/certs/crl}"
SERVER_CN="${SERVER_CN:-mockxconf}"
CERT_PASSWORD="${CERT_PASSWORD:-changeit}"

CRL_ROOT_DIR="${CERT_DIR}/Test-CRL-Root"
CRL_ICA_DIR="${CRL_ROOT_DIR}/Test-CRL-ICA"

echo "[crl-pki] Generating CRL mTLS test PKI..."
echo "[crl-pki]   CERT_DIR=${CERT_DIR}"
echo "[crl-pki]   OUT_DIR=${OUT_DIR}"
echo "[crl-pki]   SERVER_CN=${SERVER_CN}"

# ── Directory structure ───────────────────────────────────────────────────────
mkdir -p "${CRL_ROOT_DIR}/certs" "${CRL_ROOT_DIR}/private" "${CRL_ROOT_DIR}/crl" \
         "${CRL_ICA_DIR}/certs"  "${CRL_ICA_DIR}/private"  "${CRL_ICA_DIR}/crl"  \
         "${CRL_ICA_DIR}/csr"    "${OUT_DIR}"
chmod 700 "${CRL_ROOT_DIR}/private" "${CRL_ICA_DIR}/private"

# ── CA database files ─────────────────────────────────────────────────────────
touch "${CRL_ICA_DIR}/index.txt"
printf "01\n" > "${CRL_ICA_DIR}/serial"
printf "01\n" > "${CRL_ICA_DIR}/crlnumber"

# ── openssl.cnf for ICA (used by openssl ca -revoke / -gencrl) ────────────────
cat > "${CRL_ICA_DIR}/openssl.cnf" << CNFEOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = ${CRL_ICA_DIR}
database         = \$dir/index.txt
serial           = \$dir/serial
crlnumber        = \$dir/crlnumber
certificate      = \$dir/certs/Test-CRL-ICA.pem
private_key      = \$dir/private/Test-CRL-ICA.key
new_certs_dir    = \$dir/certs
default_md       = sha256
preserve         = no
policy           = policy_loose
default_crl_days = 365
default_days     = 365

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[ dn ]
CN = crl-client

[ client_cert ]
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = critical, clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ v3_ocsp_server ]
basicConstraints       = CA:FALSE
keyUsage               = critical,digitalSignature,keyEncipherment
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
subjectAltName         = DNS:${SERVER_CN}
authorityInfoAccess    = OCSP;URI:http://127.0.0.1:50063
CNFEOF

# ── Root CA (self-signed) ─────────────────────────────────────────────────────
openssl ecparam -name prime256v1 -genkey -noout \
    -out "${CRL_ROOT_DIR}/private/Test-CRL-Root.key" 2>/dev/null
chmod 600 "${CRL_ROOT_DIR}/private/Test-CRL-Root.key"

openssl req -new -x509 \
    -key "${CRL_ROOT_DIR}/private/Test-CRL-Root.key" \
    -out "${CRL_ROOT_DIR}/certs/Test-CRL-Root.pem" \
    -days 365 -sha256 \
    -subj "/C=US/O=RDK Test/CN=Test-CRL-Root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,cRLSign,keyCertSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null

# ── Root CA database and empty CRL ───────────────────────────────────────────
touch "${CRL_ROOT_DIR}/index.txt"
printf "01\n" > "${CRL_ROOT_DIR}/crlnumber"
cat > "${CRL_ROOT_DIR}/openssl.cnf" << ROOTCAEOF
[ ca ]
default_ca = CA_default
[ CA_default ]
database         = ${CRL_ROOT_DIR}/index.txt
serial           = ${CRL_ROOT_DIR}/serial
crlnumber        = ${CRL_ROOT_DIR}/crlnumber
certificate      = ${CRL_ROOT_DIR}/certs/Test-CRL-Root.pem
private_key      = ${CRL_ROOT_DIR}/private/Test-CRL-Root.key
new_certs_dir    = ${CRL_ROOT_DIR}/certs
default_md       = sha256
default_crl_days = 365
policy           = policy_loose
[ policy_loose ]
commonName = supplied
ROOTCAEOF
openssl ca -config "${CRL_ROOT_DIR}/openssl.cnf" -gencrl \
    -out "${CRL_ROOT_DIR}/crl/Test-CRL-Root.crl.pem" -batch 2>/dev/null

# ── Intermediate CA (signed by Root) ─────────────────────────────────────────
openssl ecparam -name prime256v1 -genkey -noout \
    -out "${CRL_ICA_DIR}/private/Test-CRL-ICA.key" 2>/dev/null
chmod 600 "${CRL_ICA_DIR}/private/Test-CRL-ICA.key"
openssl req -new \
    -key "${CRL_ICA_DIR}/private/Test-CRL-ICA.key" \
    -out "${CRL_ICA_DIR}/csr/Test-CRL-ICA.csr" \
    -subj "/C=US/O=RDK Test/CN=Test-CRL-ICA" 2>/dev/null
openssl x509 -req \
    -in "${CRL_ICA_DIR}/csr/Test-CRL-ICA.csr" \
    -CA "${CRL_ROOT_DIR}/certs/Test-CRL-Root.pem" \
    -CAkey "${CRL_ROOT_DIR}/private/Test-CRL-Root.key" \
    -CAcreateserial \
    -out "${CRL_ICA_DIR}/certs/Test-CRL-ICA.pem" \
    -days 365 -sha256 \
    -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,digitalSignature,cRLSign,keyCertSign\nsubjectKeyIdentifier=hash") 2>/dev/null

echo "[crl-pki] Root CA and ICA created"

# ── Server cert (signed by ICA, NOT tracked in CA DB) ────────────────────────
openssl ecparam -name prime256v1 -genkey -noout \
    -out "${OUT_DIR}/crl-server.key" 2>/dev/null
chmod 600 "${OUT_DIR}/crl-server.key"
openssl req -new \
    -key "${OUT_DIR}/crl-server.key" \
    -out /tmp/crl-server.csr \
    -subj "/C=US/O=RDK Test/CN=crl-server" 2>/dev/null
openssl x509 -req \
    -in /tmp/crl-server.csr \
    -CA "${CRL_ICA_DIR}/certs/Test-CRL-ICA.pem" \
    -CAkey "${CRL_ICA_DIR}/private/Test-CRL-ICA.key" \
    -CAcreateserial \
    -out "${OUT_DIR}/crl-server.pem" \
    -days 365 -sha256 \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nsubjectAltName=DNS:${SERVER_CN}") 2>/dev/null
rm -f /tmp/crl-server.csr
echo "[crl-pki] Server cert created (SAN=${SERVER_CN})"

# ── Client cert (via openssl ca — tracked in DB for revocation) ──────────────
openssl ecparam -name prime256v1 -genkey -noout \
    -out "${CRL_ICA_DIR}/private/crl-client.key" 2>/dev/null
chmod 600 "${CRL_ICA_DIR}/private/crl-client.key"
openssl req -new \
    -key "${CRL_ICA_DIR}/private/crl-client.key" \
    -out "${CRL_ICA_DIR}/csr/crl-client.csr" \
    -subj "/C=US/O=RDK Test/CN=crl-client" 2>/dev/null
openssl ca \
    -config "${CRL_ICA_DIR}/openssl.cnf" \
    -in "${CRL_ICA_DIR}/csr/crl-client.csr" \
    -out "${CRL_ICA_DIR}/certs/crl-client.pem" \
    -extensions client_cert \
    -days 365 \
    -batch \
    -notext 2>/dev/null

# ── Initial empty CRL (ICA level) ────────────────────────────────────────────
openssl ca \
    -config "${CRL_ICA_DIR}/openssl.cnf" \
    -gencrl \
    -out "${OUT_DIR}/Test-CRL-ICA.crl.pem" \
    -crldays 365 2>/dev/null
echo "[crl-pki] Client cert created in CA DB + initial empty CRL generated"

# ── OCSP server cert (via openssl ca — tracked in DB so responder returns 'good') ──
openssl ecparam -name prime256v1 -genkey -noout \
    -out "${OUT_DIR}/ocsp-server.key" 2>/dev/null
chmod 600 "${OUT_DIR}/ocsp-server.key"
openssl req -new \
    -key "${OUT_DIR}/ocsp-server.key" \
    -out /tmp/ocsp-server.csr \
    -subj "/C=US/O=RDK Test/CN=${SERVER_CN}" 2>/dev/null
openssl ca \
    -config "${CRL_ICA_DIR}/openssl.cnf" \
    -in /tmp/ocsp-server.csr \
    -out "${OUT_DIR}/ocsp-server.pem" \
    -extensions v3_ocsp_server \
    -days 365 \
    -batch \
    -notext 2>/dev/null
rm -f /tmp/ocsp-server.csr
chmod 644 "${OUT_DIR}/ocsp-server.pem"
echo "[crl-pki] OCSP server cert created (tracked in DB, AIA=http://127.0.0.1:50063)"

# ── OCSP responder cert (extendedKeyUsage = OCSPSigning) ─────────────────────
openssl ecparam -name prime256v1 -genkey -noout \
    -out "${OUT_DIR}/ocsp-responder.key" 2>/dev/null
chmod 600 "${OUT_DIR}/ocsp-responder.key"
openssl req -new \
    -key "${OUT_DIR}/ocsp-responder.key" \
    -out /tmp/ocsp-responder.csr \
    -subj "/C=US/O=RDK Test/CN=ocsp-responder" 2>/dev/null
openssl x509 -req \
    -in /tmp/ocsp-responder.csr \
    -CA "${CRL_ICA_DIR}/certs/Test-CRL-ICA.pem" \
    -CAkey "${CRL_ICA_DIR}/private/Test-CRL-ICA.key" \
    -CAcreateserial \
    -out "${OUT_DIR}/ocsp-responder.pem" \
    -days 365 -sha256 \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,OCSPSigning\nsubjectKeyIdentifier=hash") 2>/dev/null
rm -f /tmp/ocsp-responder.csr
chmod 644 "${OUT_DIR}/ocsp-responder.pem"
echo "[crl-pki] OCSP responder cert created (EKU=OCSPSigning)"

# ── Client P12 bundle ─────────────────────────────────────────────────────────
_CRL_ICA_CHAIN="${OUT_DIR}/crl-ica-chain.pem"
cat "${CRL_ICA_DIR}/certs/Test-CRL-ICA.pem" \
    "${CRL_ROOT_DIR}/certs/Test-CRL-Root.pem" > "${_CRL_ICA_CHAIN}"
PKCS12_PASS="${CERT_PASSWORD}" openssl pkcs12 -export \
    -in "${CRL_ICA_DIR}/certs/crl-client.pem" \
    -inkey "${CRL_ICA_DIR}/private/crl-client.key" \
    -certfile "${_CRL_ICA_CHAIN}" \
    -out "${OUT_DIR}/crl-client.p12" \
    -name "crl-client" \
    -passout env:PKCS12_PASS 2>/dev/null
chmod 644 "${OUT_DIR}/crl-client.p12"

# ── Copy remaining outputs ────────────────────────────────────────────────────
cp "${CRL_ICA_DIR}/certs/Test-CRL-ICA.pem"      "${OUT_DIR}/Test-CRL-ICA.pem"
cp "${CRL_ROOT_DIR}/certs/Test-CRL-Root.pem"     "${OUT_DIR}/Test-CRL-Root.pem"
cp "${CRL_ROOT_DIR}/crl/Test-CRL-Root.crl.pem"   "${OUT_DIR}/Test-CRL-Root.crl.pem"
cp "${CRL_ICA_DIR}/certs/crl-client.pem"         "${OUT_DIR}/crl-client.pem"
cp "${CRL_ICA_DIR}/private/crl-client.key"       "${OUT_DIR}/crl-client.key"
chmod 600 "${OUT_DIR}/crl-client.key"

# ── CA chain for OCSP daemon ─────────────────────────────────────────────────
cat "${CRL_ICA_DIR}/certs/Test-CRL-ICA.pem" \
    "${CRL_ROOT_DIR}/certs/Test-CRL-Root.pem" > "${OUT_DIR}/ocsp-ca-chain.pem"

echo "[crl-pki] All CRL test cert assets generated in ${OUT_DIR}"
echo "[crl-pki] Done."
