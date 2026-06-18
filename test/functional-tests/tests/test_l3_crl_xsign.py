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
L3 CRL / Cross-signed mTLS test driver  (RDK-61158)

Runs *inside* the native-platform container where:
  - curl is available with OpenSSL mTLS support
  - /opt/certs/crl/  holds the CRL-PKI client cert assets
  - /opt/certs/xs/   holds the cross-signed P12 bundles
  - mockxconf:50061  is the CRL mTLS HTTPS server
  - mockxconf:50062  is the plain-HTTP CRL control endpoint

The tests are skipped when ENABLE_CRL_L3 is not set to "true" so they do
not interfere with the L2 pytest run.
"""

import datetime
import os
import subprocess
import time

import pytest
import requests

# ─── Skip guard ──────────────────────────────────────────────────────────────

pytestmark = pytest.mark.skipif(
    os.environ.get("ENABLE_CRL_L3", "false").lower() != "true",
    reason="ENABLE_CRL_L3 is not set to 'true'",
)

# ─── Constants ────────────────────────────────────────────────────────────────

MOCKXCONF_HOST   = os.environ.get("MOCKXCONF_HOST", "mockxconf")
CRL_MTLS_PORT    = 50061
CRL_CONTROL_PORT = 50062

BASE_URL = f"https://{MOCKXCONF_HOST}:{CRL_MTLS_PORT}"
CTRL_URL = f"http://{MOCKXCONF_HOST}:{CRL_CONTROL_PORT}"

# Client cert assets (copied by native-platform certs.sh from shared volume)
CRL_CLIENT_P12    = "/opt/certs/crl/crl-client.p12"
XS_CLIENT_XSIGN   = "/opt/certs/xs/client-xsign.p12"
XS_CLIENT_OLD     = "/opt/certs/xs/client-old.p12"
XS_CLIENT_EXPXS   = "/opt/certs/xs/client-expxs.p12"

# Path to the client cert *inside mock-xconf container* — used for POST /crl/revoke
# This is the cert recorded in the ICA database (created via openssl ca).
MOCKXCONF_CRL_CLIENT_CERT = (
    "/etc/pki/test-crl/Test-CRL-Root/Test-CRL-ICA/certs/crl-client.pem"
)

CERT_PASS = "changeit"

# ─── Helpers ─────────────────────────────────────────────────────────────────


def curl_mtls(p12_file, url=None, timeout=10):
    """
    Run curl with mTLS client authentication using a PKCS#12 bundle.

    Returns (returncode, stdout_str, stderr_str).
    The server certificate is verified against the system trust store which
    includes Test-CRL-Root and Test-XS-NewRoot after certs.sh runs.
    """
    if url is None:
        url = f"{BASE_URL}/health"
    cmd = [
        "curl",
        "--silent",
        "--fail-with-body",
        "--cert",      p12_file,
        "--cert-type", "P12",
        "--pass",      CERT_PASS,
        url,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr


def ctrl_post(endpoint, body=None):
    """POST to the CRL control server and return the Response object."""
    return requests.post(f"{CTRL_URL}{endpoint}", json=body, timeout=5)


# ─── Fixture: reset CRL before and after every test ─────────────────────────


@pytest.fixture(autouse=True)
def clean_crl_state():
    """
    Ensure a fresh empty CRL both before and after each test.

    This prevents revocation state from leaking between tests even when a
    test fails before its own cleanup.
    """
    ctrl_post("/crl/reset")   # pre-test reset
    yield
    try:
        ctrl_post("/crl/reset")   # post-test cleanup
    except Exception:
        pass


# ─── Test cases ───────────────────────────────────────────────────────────────


def test_l3_crl_valid_cert_succeeds():
    """A valid (non-revoked) client cert must be accepted by the mTLS server."""
    rc, stdout, stderr = curl_mtls(CRL_CLIENT_P12)
    assert rc == 0, (
        f"Expected curl to succeed with a valid cert (rc={rc}).\n"
        f"stdout: {stdout}\nstderr: {stderr}"
    )


def test_l3_crl_revoked_cert_fails():
    """After revoking a cert the mTLS server must reject it (CRL check)."""
    resp = ctrl_post("/crl/revoke", {"certFile": MOCKXCONF_CRL_CLIENT_CERT})
    assert resp.status_code == 200, (
        f"POST /crl/revoke failed: {resp.status_code} {resp.text}"
    )
    # Brief pause to let setSecureContext() propagate
    time.sleep(0.3)

    rc, _, stderr = curl_mtls(CRL_CLIENT_P12)
    assert rc != 0, (
        "Expected curl to fail after revocation but it succeeded.\n"
        f"stderr: {stderr}"
    )


def test_l3_crl_reset_restores():
    """After a CRL reset a previously revoked cert should be accepted again."""
    # Revoke first
    resp = ctrl_post("/crl/revoke", {"certFile": MOCKXCONF_CRL_CLIENT_CERT})
    assert resp.status_code == 200
    time.sleep(0.3)

    # Confirm cert is rejected while revoked
    rc_revoked, _, _ = curl_mtls(CRL_CLIENT_P12)
    assert rc_revoked != 0, "Cert should be rejected while revoked"

    # Reset CRL
    resp = ctrl_post("/crl/reset")
    assert resp.status_code == 200, (
        f"POST /crl/reset failed: {resp.status_code} {resp.text}"
    )

    # Now cert should be accepted again
    rc, _, stderr = curl_mtls(CRL_CLIENT_P12)
    assert rc == 0, (
        f"Expected cert to be accepted after CRL reset (rc={rc}).\n"
        f"stderr: {stderr}"
    )


def test_l3_xsign_bridge_succeeds():
    """
    A client cert whose chain includes a valid cross-signed bridge must be
    accepted.  The server trusts Test-XS-NewRoot; the bridge cert links
    Test-XS-OldRoot to Test-XS-NewRoot.
    """
    rc, stdout, stderr = curl_mtls(XS_CLIENT_XSIGN)
    assert rc == 0, (
        f"Expected cross-signed bridge cert to succeed (rc={rc}).\n"
        f"stdout: {stdout}\nstderr: {stderr}"
    )


def test_l3_xsign_no_bridge_fails():
    """
    A client cert under Test-XS-OldRoot with no bridge must be rejected: the
    server does not directly trust Test-XS-OldRoot.
    """
    rc, _, stderr = curl_mtls(XS_CLIENT_OLD)
    assert rc != 0, (
        "Expected old-root cert without a bridge to fail, but curl succeeded.\n"
        f"stderr: {stderr}"
    )


def test_l3_xsign_expired_bridge_fails():
    """
    A client cert whose chain includes an already-expired bridge cert must be
    rejected.  The test must also complete in under 5 seconds (no TLS retry
    hang).
    """
    start = datetime.datetime.now()
    rc, _, stderr = curl_mtls(XS_CLIENT_EXPXS, timeout=10)
    elapsed = (datetime.datetime.now() - start).total_seconds()

    assert rc != 0, (
        "Expected expired-bridge cert to fail, but curl succeeded.\n"
        f"stderr: {stderr}"
    )
    assert elapsed < 5.0, (
        f"Test took {elapsed:.1f}s — expected under 5s (possible TLS hang on "
        "expired bridge cert)."
    )
