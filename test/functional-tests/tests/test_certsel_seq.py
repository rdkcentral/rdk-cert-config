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

import os
import subprocess
import sys
import pytest

TEST_SETUP = "./test/l2-sampleapp/test_setup.sh"

sequence_descriptions = {
    1: "Sequence 1: If the first cert fails, the second is used; subsequent tries skip the first.",
    2: "Sequence 2: If the second certificate is invalid, fallback to the first. If the first also fails, use the third. Subsequent attempts skip both the first and second certificates.",
    3: "Sequence 3: If the first certificate fails, the second is used. Once the first is restored, it becomes the preferred choice again. Subsequent attempts use the first certificate.",
    4: "Sequence 4: First is unavailable; if the second fails, fallback to the third. Once the second is restored, it is used while skipping the first. When the first is restored, it regains priority.Subsequent attempts use the first.",
    5: "Sequence 5: When the first fails, the second is used. The second is used again on the next attempt. A network error (code 56) occurs. After recovery, the second is used twice.",
    6: "Sequence 6: If the first fails, the second is also failed, third is also failed then renew first, use the first",
    7: "Sequence 7: There are two objects running in parallel. For obj1, the first cert fails, so it switches to the second cert. Meanwhile, obj2 successfully uses the first cert without any fallback.",
    8: "Sequence 8: Two consecutive get operations, Two consecutive set operations",
    9: "Sequence 9: Cross-sign — Root B absent, no bridge cert. Single cert fails with issuer error (80), no fallback available.",
    10: "Sequence 10: Cross-sign — Root B absent, bridge cert present. Bridge chains Root B to Root C; cert succeeds and is reused.",
    11: "Sequence 11: Cross-sign — All roots present, no bridge needed. Direct trust via Root B; cert succeeds and is reused.",
    12: "Sequence 12: Cross-sign — Root B absent, expired bridge cert. Expired bridge fails with issuer error (80), no fallback available.",
    13: "Sequence 13: Cross-sign — Root B absent, revoked bridge cert. Revoked bridge fails with cert status error (91), no fallback available.",
    14: "Sequence 14: CRL — Revoked leaf cert on CRL. Fails with cert status error (91), falls back to valid cert. Subsequent calls skip revoked cert.",
    15: "Sequence 15: CRL — Revoked intermediate CA. Fails with issuer error (80), falls back to cert under valid ICA.",
    16: "Sequence 16: OCSP — Good OCSP staple. Cert succeeds, no fallback needed. Reused on subsequent calls.",
    17: "Sequence 17: OCSP — Revoked OCSP staple. First cert goes bad with cert status error (91), falls back to second cert. Revoked cert stays bad.",
    18: "Sequence 18: OCSP hard-fail — Responder unreachable. Cert fails with status error (91), falls back. After responder recovers (file touch), original cert eligible again."
}


@pytest.fixture(scope="session", autouse=True)
def run_test_setup():
    """Run test_setup.sh once before all sequence tests."""
    if not os.path.isfile(TEST_SETUP):
        pytest.exit(f"[ERROR] {TEST_SETUP} not found — cannot run L2 tests.", returncode=1)
    result = subprocess.run(["bash", TEST_SETUP], capture_output=True, text=True)
    if result.returncode != 0:
        pytest.exit(
            f"[ERROR] test_setup.sh failed (rc={result.returncode}):\n{result.stderr}",
            returncode=1,
        )
    print(f"\n[INFO] test_setup.sh executed successfully.")


@pytest.mark.parametrize(
    "sequence_num",
    list(sequence_descriptions.keys()),
    ids=[f"seq{n:02d}" for n in sequence_descriptions.keys()],
)
def test_certsel_seq(sequence_num):
    """Run a single L2 certsel sequence and assert it passes."""
    description = sequence_descriptions[sequence_num]
    print(f"\n[INFO] Running sequence {sequence_num}: {description}")

    binary_path = "./test/l2-sampleapp/l2sampleapp"
    result = subprocess.run(
        [binary_path, str(sequence_num)],
        capture_output=True,
        text=True,
    )

    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    assert result.returncode == 0, (
        f"Sequence {sequence_num} FAILED (rc={result.returncode})\n"
        f"stdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )

