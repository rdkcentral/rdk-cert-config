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
#pytest --json-report --json-report-summary --json-report-file $RESULT_DIR/certsel_seq_run.json test/functional-tests/tests/test_certsel_seq.py
pytest --json-report  --json-report-file $RESULT_DIR/certsel_seq_run.json test/functional-tests/tests/test_certsel_seq.py
