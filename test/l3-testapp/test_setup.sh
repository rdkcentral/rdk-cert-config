#!/bin/sh
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
#
# test_setup.sh — write certsel config files for L3 testapp scenarios.
#
# Called from run_l3.sh before pytest.  The configs use absolute cert paths
# under /opt/certs/, which native-platform/certs.sh populates when
# ENABLE_CRL_L3=true.
#
# All entries use the credential ref "l3pass", which certsel_l3.c's
# rdkconfig_getStr mock maps to "changeit" (the default CERT_PASSWORD
# used by both generate_crl_test_certs.sh and generate_cross_signed_test_certs.sh).

set -e

mkdir -p ./l3

# hrot.properties — no HROT hardware engine for L3 test environment
echo "hrotengine=" > ./l3/hrot.properties

# crl.cfg — single CRL client cert (used for scenarios 1 and 6)
echo "CRL_L3_GRP,CRLC,P12,file:///opt/certs/crl/crl-client.p12,l3pass" \
    > ./l3/crl.cfg

# xs_bridge.cfg — xsign bundle with valid cross-signed bridge embedded
echo "XS_BRIDGE_GRP,XSIG,P12,file:///opt/certs/xs/client-xsign.p12,l3pass" \
    > ./l3/xs_bridge.cfg

# xs_nobridge.cfg — old-root cert with no bridge (chain cannot reach NewRoot)
echo "XS_OLD_GRP,XSOL,P12,file:///opt/certs/xs/client-old.p12,l3pass" \
    > ./l3/xs_nobridge.cfg

# xs_expxs.cfg — expired bridge cert bundle (bridge cert is already expired)
echo "XS_EXPXS_GRP,EXPX,P12,file:///opt/certs/xs/client-expxs.p12,l3pass" \
    > ./l3/xs_expxs.cfg

echo "[test_setup] L3 certsel configs written to ./l3/"
