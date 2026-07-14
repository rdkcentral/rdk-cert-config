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

WORKDIR=`pwd`
export ROOT=/usr
export INSTALL_DIR=${ROOT}/local
mkdir -p $INSTALL_DIR

#copying reuire header file for L2 testing 
cp CertSelector/include/rdkcertselector.h test/l2-sampleapp/include/
cp CertSelector/src/unit_test.h test/l2-sampleapp/include/

#Build rdk-cert-config & sample application of L2

autoreconf -i
./configure --enable-l2testing --prefix=${INSTALL_DIR}
make && make install


RESULT_DIR="/tmp/l2_test_report"
mkdir -p "$RESULT_DIR"

# Run L2 Test cases
pytest --json-report  --json-report-file $RESULT_DIR/certsel_seq_run.json test/functional-tests/tests/test_certsel_seq.py
L2_RC=$?

# ── Run L3 tests if mock-xconf is available ──────────────────────────────────
# When the container is started with ENABLE_CRL_L3=true and linked to mockxconf,
# L3 certs are already deployed by the time L2 build+test completes.
L3_RC=0
if [ "${ENABLE_CRL_L3}" = "true" ]; then
    echo "[run_l2] L2 complete — invoking L3 test suite..."
    sh run_l3.sh
    L3_RC=$?
fi

# Propagate the worst of L2 and L3 results to CI
if [ $L2_RC -ne 0 ] || [ $L3_RC -ne 0 ]; then
    echo "[run_l2] FAIL: L2_RC=${L2_RC} L3_RC=${L3_RC}"
    exit 1
fi
exit 0
