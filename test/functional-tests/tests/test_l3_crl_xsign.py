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
"""
L3 CRL / Cross-signed mTLS test driver

Runs *inside* the native-platform container where:
  - l3testapp (built by run_l2.sh with --enable-l2testing) uses the
    RDK CertSelector API to select a PKCS#12 cert and then performs a
    real libcurl mTLS connection to mock-xconf
  - mockxconf:50061  is the CRL mTLS HTTPS server
  - mockxconf:50062  is the plain-HTTP CRL control endpoint
  - mockxconf:50064  is the OCSP stapling server

All six scenarios are delegated to l3testapp, which performs a real libcurl
mTLS handshake via the RDK CertSelector API and exits with the raw CURLcode.
For the CRL revocation scenario the Python driver first revokes the client
cert via the control endpoint (POST /crl/revoke); revocation is permanent, so
there is no reset step (matching real-world CRL behaviour).

The tests are skipped when ENABLE_CRL_L3 is not set to "true".
"""

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from collections import namedtuple

import pytest

# ─── Skip guard ──────────────────────────────────────────────────────────────

pytestmark = pytest.mark.skipif(
    os.environ.get("ENABLE_CRL_L3", "false").lower() != "true",
    reason="ENABLE_CRL_L3 is not set to 'true'",
)

# ─── Constants ────────────────────────────────────────────────────────────────

MOCKXCONF_HOST   = os.environ.get("MOCKXCONF_HOST", "mockxconf")
CRL_CONTROL_PORT = 50062

CTRL_URL = f"http://{MOCKXCONF_HOST}:{CRL_CONTROL_PORT}"

# Path to the client cert *inside mock-xconf container* — used for POST /crl/revoke
# This is the cert recorded in the ICA database (created via openssl ca).
MOCKXCONF_CRL_CLIENT_CERT = (
    "/etc/pki/test-crl/Test-CRL-Root/Test-CRL-ICA/certs/crl-client.pem"
)

# Path to the l3testapp binary (built alongside l2sampleapp by run_l2.sh)
L3TESTAPP = "./test/l3-testapp/l3testapp"

# ── libcurl CURLcode values used for precise per-scenario assertions ──────────
# l3testapp exits with the raw CURLcode from its handshake, so the tests assert
# on the exact expected error rather than a generic non-zero check.
CURLE_OK                    = 0   # success
CURLE_RECV_ERROR            = 56  # server rejected the cert and dropped the connection
CURLE_SSL_INVALIDCERTSTATUS = 91  # --cert-status: missing/invalid OCSP staple

# ─── Module-level setup ───────────────────────────────────────────────────────


@pytest.fixture(scope="module", autouse=True)
def _setup_l3_configs():
    """Write certsel config files for l3testapp before any L3 test runs."""
    setup = "./test/l3-testapp/test_setup.sh"
    if os.path.isfile(setup):
        subprocess.run(["sh", setup], check=True)
    else:
        pytest.skip(f"L3 test_setup.sh not found at {setup}")


# ─── Helpers ─────────────────────────────────────────────────────────────────


def run_l3testapp(scenario_id, timeout=10):
    """
    Invoke l3testapp <scenario_id> and return (returncode, stdout, stderr).

    The testapp calls rdkcertselector_getCert to obtain the PKCS#12 cert URI
    and password for the scenario, then makes a real libcurl mTLS connection,
    then calls rdkcertselector_setCurlStatus with the actual CURLcode.

    The return code is the raw libcurl CURLcode from the handshake: 0
    (CURLE_OK) on success, or a specific non-zero CURLcode on failure.
    """
    result = subprocess.run(
        [L3TESTAPP, str(scenario_id)],
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


# Minimal response wrapper exposing the subset of the requests.Response API
# used by these tests (.status_code and .text).
_CtrlResponse = namedtuple("_CtrlResponse", ["status_code", "text"])


def ctrl_post(endpoint, body=None):
    """POST to the CRL control server using only the Python standard library.

    Returns an object exposing .status_code and .text. Using urllib avoids a
    runtime ``pip install requests`` and keeps the L3 suite free of outbound
    network/package dependencies in egress-restricted CI.
    """
    data = json.dumps(body if body is not None else {}).encode("utf-8")
    req = urllib.request.Request(
        f"{CTRL_URL}{endpoint}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return _CtrlResponse(resp.status, resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        # An HTTP error response still carries a status code and body.
        return _CtrlResponse(exc.code, exc.read().decode("utf-8", "replace"))


# ─── Test cases ───────────────────────────────────────────────────────────────


def test_l3_crl_valid_cert_succeeds():
    """A valid (non-revoked) client cert must be accepted by the mTLS server.

    Runs before the revocation test; the server starts with a clean (empty)
    CRL, so no reset is required.
    """
    rc, stdout, stderr = run_l3testapp(1)
    assert rc == CURLE_OK, (
        f"Expected l3testapp scenario 1 (CRL valid) to succeed "
        f"(rc={rc}, expected CURLE_OK={CURLE_OK}).\n"
        f"stdout: {stdout}\nstderr: {stderr}"
    )


def test_l3_crl_revoked_cert_fails():
    """After revoking a cert the mTLS server must reject it (CRL check).

    Revocation is permanent: once the client cert is added to the CRL the
    server rejects it for the remainder of the container's lifetime.
    """
    resp = ctrl_post("/crl/revoke", {"certFile": MOCKXCONF_CRL_CLIENT_CERT})
    assert resp.status_code == 200, (
        f"POST /crl/revoke failed: {resp.status_code} {resp.text}"
    )
    # Brief pause to let setSecureContext() propagate the new CRL to the server
    time.sleep(0.3)

    rc, _, stderr = run_l3testapp(1)
    assert rc == CURLE_RECV_ERROR, (
        f"Expected l3testapp scenario 1 to fail with "
        f"CURLE_RECV_ERROR={CURLE_RECV_ERROR} after revocation "
        f"(got rc={rc}).\nstderr: {stderr}"
    )


def test_l3_xsign_bridge_succeeds():
    """
    A client cert whose chain includes a valid cross-signed bridge must be
    accepted.  The server trusts Test-XS-NewRoot; the bridge cert links
    Test-XS-OldRoot to Test-XS-NewRoot.
    """
    rc, stdout, stderr = run_l3testapp(2)
    assert rc == CURLE_OK, (
        f"Expected l3testapp scenario 2 (xsign bridge) to succeed "
        f"(rc={rc}, expected CURLE_OK={CURLE_OK}).\n"
        f"stdout: {stdout}\nstderr: {stderr}"
    )


def test_l3_xsign_no_bridge_fails():
    """
    A client cert under Test-XS-OldRoot with no bridge must be rejected: the
    server does not directly trust Test-XS-OldRoot.
    """
    rc, _, stderr = run_l3testapp(3)
    assert rc == CURLE_RECV_ERROR, (
        f"Expected l3testapp scenario 3 (xsign no bridge) to fail with "
        f"CURLE_RECV_ERROR={CURLE_RECV_ERROR} (got rc={rc}).\n"
        f"stderr: {stderr}"
    )


def test_l3_xsign_expired_bridge_fails():
    """
    A client cert whose chain includes an already-expired bridge cert must be
    rejected.  The test must also complete in under 5 seconds (no TLS retry
    hang).
    """
    start = time.monotonic()
    rc, _, stderr = run_l3testapp(4, timeout=5)
    elapsed = time.monotonic() - start

    assert rc == CURLE_RECV_ERROR, (
        f"Expected l3testapp scenario 4 (expired bridge) to fail with "
        f"CURLE_RECV_ERROR={CURLE_RECV_ERROR} (got rc={rc}).\n"
        f"stderr: {stderr}"
    )
    assert elapsed < 5.0, (
        f"Test took {elapsed:.1f}s — expected under 5s (possible TLS hang on "
        "expired bridge cert)."
    )


# ─── OCSP Stapling tests ───────────────────────────────────────────────────────


def test_l3_ocsp_staple_present():
    """
    OCSP Stapling – happy path.

    Scenario 5 connects to the OCSP stapling server (port 50064) with
    CURLOPT_SSL_VERIFYSTATUS=1.  libcurl fails the handshake unless the server
    staples a valid OCSP response with status=good, so CURLE_OK proves the
    staple was present and good.
    """
    rc, stdout, stderr = run_l3testapp(5)
    assert rc == CURLE_OK, (
        f"Expected l3testapp scenario 5 (OCSP staple present) to succeed "
        f"(rc={rc}, expected CURLE_OK={CURLE_OK}).\n"
        f"stdout: {stdout}\nstderr: {stderr}\n"
        "Server must staple a valid OCSP response when ENABLE_CRL_L3=true."
    )


def test_l3_ocsp_staple_absent_rejected():
    """
    OCSP Stapling – negative control.

    Scenario 6 connects to the CRL mTLS server (port 50061), which does NOT
    implement OCSP stapling, with CURLOPT_SSL_VERIFYSTATUS=1.  libcurl must
    fail with CURLE_SSL_INVALIDCERTSTATUS because no staple is returned,
    proving the scenario-5 assertion is meaningful and not a false positive.
    """
    rc, _, stderr = run_l3testapp(6)
    assert rc == CURLE_SSL_INVALIDCERTSTATUS, (
        f"Expected l3testapp scenario 6 (no OCSP staple) to fail with "
        f"CURLE_SSL_INVALIDCERTSTATUS={CURLE_SSL_INVALIDCERTSTATUS} "
        f"(got rc={rc}).\nstderr: {stderr}"
    )
