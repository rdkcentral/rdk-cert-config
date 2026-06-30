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
# L3 CRL mTLS + Cross-signed PKI integration test runner.
#
# Executed *inside* the native-platform container after run_l2.sh completes.
#
# Start order is enforced by the containers themselves, not the workflow:
#   1. mock-xconf generates the CRL and cross-signed PKI and exports the final
#      bundles to the shared volume.
#   2. native-platform's certs.sh (run from its entrypoint) waits for those
#      files, copies them, and installs the trust anchors before the container
#      services start.
#   3. run_l2.sh builds and runs the L2 tests, then calls this script.
#
# Because steps 1 and 2 complete before this script is invoked, no startup
# sleep is needed here.  The health-check below is a sanity assertion, not a
# timing gate.
#
# Prerequisites (already satisfied when called after run_l2.sh):
#   shared_certs/crl-client/  — CRL PKI client credentials on shared volume
#   shared_certs/xs-client/   — cross-signed P12 bundles on shared volume
#   System trust store includes Test-CRL-Root and Test-XS-NewRoot
#   mockxconf reachable at mockxconf:50061 (mTLS) and mockxconf:50062 (control)

set -e

SHARED_CERTS="/mnt/L2_CONTAINER_SHARED_VOLUME/shared_certs"
RESULT_DIR="/tmp/l3_test_report"
mkdir -p "$RESULT_DIR"

# ── Install Python dependency required by the test driver ────────────────────
pip3 install --quiet requests 2>/dev/null || pip install --quiet requests 2>/dev/null || true

# ── Verify prerequisites ─────────────────────────────────────────────────────
echo "[run_l3] Verifying L3 prerequisites..."
for f in "$SHARED_CERTS/crl-client/crl-client.p12" \
         "$SHARED_CERTS/xs-client/client-xsign.p12"; do
    if [ ! -f "$f" ]; then
        echo "[run_l3] FAIL: $f not found." >&2
        echo "[run_l3] Ensure mock-xconf started with ENABLE_CRL_L3=true." >&2
        exit 1
    fi
done
echo "[run_l3] Cert assets verified"

# ── Build L3 certsel config files (absolute cert paths under /opt/certs/) ─────
if [ -f test/l3-testapp/test_setup.sh ]; then
    sh test/l3-testapp/test_setup.sh
    echo "[run_l3] L3 certsel configs written"
fi

# Verify l3testapp binary was built (requires --enable-l2testing)
if [ ! -x test/l3-testapp/l3testapp ]; then
    echo "[run_l3] WARNING: test/l3-testapp/l3testapp not found." >&2
    echo "[run_l3] Ensure run_l2.sh built with --enable-l2testing." >&2
fi

# Sanity-check: confirm mockxconf CRL mTLS server is reachable.
# When invoked via run_tests.sh this should always pass — mock-xconf is
# guaranteed ready before run_l2.sh is exec'd.  A failure here indicates a
# misconfiguration (e.g. ENABLE_CRL_L3 not set, wrong container network)
# and is reported as a warning rather than an immediate abort so that the
# pytest run below produces a structured failure report.
if ! curl -sf \
    --cacert "$SHARED_CERTS/crl-client/crl-ica-chain.pem" \
    --cert   "$SHARED_CERTS/crl-client/crl-client.pem" \
    --key    "$SHARED_CERTS/crl-client/crl-client.key" \
    https://mockxconf:50061/health >/dev/null 2>&1; then
    echo "[run_l3] WARNING: mockxconf:50061 health-check failed." >&2
    echo "[run_l3] Ensure ENABLE_CRL_L3=true and L2-tests.yml orchestration was followed." >&2
else
    echo "[run_l3] mockxconf:50061 ready"
fi

# ── Run L3 test suite ────────────────────────────────────────────────────────
echo "[run_l3] Running L3 CRL / cross-signed mTLS test suite..."

ENABLE_CRL_L3=true \
    pytest \
    --json-report \
    --json-report-file "$RESULT_DIR/l3_crl_xsign_run.json" \
    test/functional-tests/tests/test_l3_crl_xsign.py \
    -v
PYTEST_RC=$?

# ── Print per-test summary from the JSON report ──────────────────────────────
if [ -f "$RESULT_DIR/l3_crl_xsign_run.json" ]; then
    echo ""
    echo "[run_l3] ── Test result summary ──────────────────────────────────"
    python3 -c "
import json, sys
data = json.load(open('$RESULT_DIR/l3_crl_xsign_run.json'))
tests = data.get('tests', [])
passed  = [t for t in tests if t.get('outcome') == 'passed']
failed  = [t for t in tests if t.get('outcome') == 'failed']
skipped = [t for t in tests if t.get('outcome') == 'skipped']
for t in tests:
    mark = 'PASS' if t.get('outcome') == 'passed' else ('SKIP' if t.get('outcome') == 'skipped' else 'FAIL')
    print(f'  [{mark}] {t[\"nodeid\"]}')
print(f'  Total: {len(tests)}  Passed: {len(passed)}  Failed: {len(failed)}  Skipped: {len(skipped)}')
sys.exit(1 if failed else 0)
" 2>/dev/null || true
    echo "[run_l3] ─────────────────────────────────────────────────────────"
fi

exit $PYTEST_RC
