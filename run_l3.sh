#!/bin/sh

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
#
# RDK-61158: L3 CRL mTLS + Cross-signed PKI integration test runner.
#
# Executed *inside* the native-platform container, analogous to run_l2.sh
# for L2 tests.  The CI workflow (L3-tests.yml) starts mockxconf and
# native-platform with ENABLE_CRL_L3=true before invoking this script.
#
# Prerequisites (set up by native-platform/certs.sh at container startup):
#   /opt/certs/crl/crl-client.p12   — CRL PKI client credential
#   /opt/certs/xs/client-xsign.p12  — cross-signed P12 bundle
#   System trust store includes Test-CRL-Root and Test-XS-NewRoot
#
# mockxconf must be reachable at mockxconf:50061 (mTLS) and
# mockxconf:50062 (CRL control HTTP endpoint).

set -e

RESULT_DIR="/tmp/l3_test_report"
mkdir -p "$RESULT_DIR"

# ── Install Python dependency required by the test driver ────────────────────
# 'requests' is used by ctrl_post() to call POST /crl/revoke and /crl/reset.
# Use || true so a pre-installed package does not abort the script.
pip3 install --quiet requests 2>/dev/null || pip install --quiet requests 2>/dev/null || true

# ── Wait for native-platform cert setup to complete ─────────────────────────
# certs.sh (running in the container entrypoint) exports crl-client.p12 after
# receiving it from mock-xconf over the shared volume.  docker exec may fire
# before certs.sh finishes, so we poll here.
echo "[run_l3] Waiting for /opt/certs/crl/crl-client.p12 (max 120s)..."
i=0
while [ $i -lt 120 ]; do
    [ -f /opt/certs/crl/crl-client.p12 ] && break
    sleep 2
    i=$((i+2))
done
if [ ! -f /opt/certs/crl/crl-client.p12 ]; then
    echo "[run_l3] FAIL: /opt/certs/crl/crl-client.p12 not present after 120s." >&2
    echo "[run_l3] Check that mock-xconf started with ENABLE_CRL_L3=true." >&2
    exit 1
fi
echo "[run_l3] CRL cert assets ready"

# ── Wait for xsign P12 bundles ───────────────────────────────────────────────
echo "[run_l3] Waiting for /opt/certs/xs/client-xsign.p12 (max 60s)..."
i=0
while [ $i -lt 60 ]; do
    [ -f /opt/certs/xs/client-xsign.p12 ] && break
    sleep 2
    i=$((i+2))
done
if [ ! -f /opt/certs/xs/client-xsign.p12 ]; then
    echo "[run_l3] FAIL: /opt/certs/xs/client-xsign.p12 not present after 60s." >&2
    exit 1
fi
echo "[run_l3] xsign P12 bundles ready"

# ── Wait for mockxconf CRL mTLS server on port 50061 ────────────────────────
# This also validates the system trust store is correct (curl verifies the
# server cert against the CA installed by native-platform/certs.sh).
echo "[run_l3] Waiting for https://mockxconf:50061/health (max 60s)..."
i=0
while [ $i -lt 60 ]; do
    curl -sf https://mockxconf:50061/health >/dev/null 2>&1 && break
    sleep 2
    i=$((i+2))
done
if [ $i -ge 60 ]; then
    echo "[run_l3] FAIL: mockxconf:50061 not reachable after 60s." >&2
    echo "[run_l3] Check that Test-CRL-Root is in the system trust store." >&2
    exit 1
fi
echo "[run_l3] mockxconf:50061 ready"

# ── Run L3 test suite ────────────────────────────────────────────────────────
echo "[run_l3] Running L3 CRL / cross-signed mTLS test suite..."

ENABLE_CRL_L3=true \
    pytest \
    --json-report \
    --json-report-file "$RESULT_DIR/l3_crl_xsign_run.json" \
    test/functional-tests/tests/test_l3_crl_xsign.py \
    -v
