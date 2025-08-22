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
    8: "Sequence 8: Two consecutive get operations, Two consecutive set operations"
}
def test_certsel_seq():
    if os.path.isfile(TEST_SETUP):
        try:
            subprocess.run(["bash", TEST_SETUP], check=True)
            print(f"[INFO] setup_env.sh executed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to run setup_env.sh: {e}")
    else:
        print(f"[ERROR] {test_setup} not found.")
        sys.exit(1)
    
    binary_path = "./test/l2-sampleapp/l2sampleapp"
    for sequence_num, description in sequence_descriptions.items():
        try:
            print(f"\n[INFO] Running sequence {sequence_num}:  {description}")
            result = subprocess.run([binary_path, str(sequence_num)], stdout=subprocess.PIPE)
            assert result.returncode == 0
            print(f"[PASS] Sequence {sequence_num} executed successfully.")
            print(result.stdout)
        except AssertionError:
            print(f"[FAIL] Sequence {sequence_num} failed with return code {result.returncode}")
            print(f"Stderr: {result.stderr}")
        except Exception as e:
            print(f"[ERROR] Unexpected error in sequence {sequence_num}: {e}")

