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
mkdir -p ./l2/etc/ssl/certsel

echo "TSTGRP1,FRST,TMP,file://./l2/etc/ssl/certsel/tst1def.tmp,./l2/etc/ssl/certsel/pcdef" > ./l2/etc/ssl/certsel/certsel.cfg
touch ./l2/etc/ssl/certsel/tst1def.tmp l2/etc/ssl/certsel/pcdef
echo "hrotengine=e4tstdef" > ./l2/etc/ssl/certsel/hrot.properties
echo "TSTGRP1,FRST,TMP,file://./l2/tst1first.tmp,pc1" > ./l2/tst1certsel.cfg
echo "TSTGRP1,SCND,TMP,file://./l2/tst1second.tmp,pc2" >> ./l2/tst1certsel.cfg
echo "TSTGRP10,NOPC,TMP,file://./l2/tst1first.tmp,pc10" >> ./l2/tst1certsel.cfg
echo "TSTGRP1|TSTGRP3,THRD,TMP,file://./l2/tst1third.tmp,pc3" >> ./l2/tst1certsel.cfg
echo "TSTGRP2,ALPHA,TMP,file://./l2/tst1alpha.tmp,pcalpha" >> ./l2/tst1certsel.cfg
echo "UNKNWN,UNKNO,TMP,file://./l2/tst1unknown.tmp,pcunk" >> ./l2/tst1certsel.cfg
echo "A1|A2|A3|A4|A5|A6|A7|A8|A9|A10,ALPHA,TMP,file://./l2/tst1alpha.tmp,pcalpha" >> ./l2/tst1certsel.cfg
touch ./l2/tst1first.tmp
touch ./l2/tst1second.tmp
touch ./l2/tst1third.tmp
touch ./l2/tst1alpha.tmp
echo "hrotengine=e4tst1" > ./l2/tst1hrot.properties
echo "\nhrotengine=e4tst1" > ./l2/tst2hrot.properties
echo "hrotprovider=e4tst1" > ./l2/bad3hrot.properties
echo -n "GRP1,FRST,TMP,t1.tmp,pc1" > ./l2/tst1toolong.cfg

# Cross-sign test setup
mkdir -p ./l2/xs

# Cross-sign placeholder P12 files
touch ./l2/xs/client-nobridge.p12
touch ./l2/xs/client-xsign.p12
touch ./l2/xs/client-expxs.p12
touch ./l2/xs/client-revxs.p12
touch ./l2/xs/crl-revoked.p12
touch ./l2/xs/crl-valid.p12
touch ./l2/xs/ica-revoked-leaf.p12
touch ./l2/xs/ica-valid-leaf.p12
touch ./l2/xs/ocsp-valid.p12
touch ./l2/xs/ocsp-revoked.p12

# Cross-sign hrot.properties
echo "hrotengine=e4xstest" > ./l2/xs/hrot.properties

# Cross-sign certsel config files
# Seq 9: single cert, no bridge (Root B absent)
echo "XSGRP,NOBR,TMP,file://./l2/xs/client-nobridge.p12,pc_nobridge" > ./l2/xs/xs_nobridge.cfg

# Seq 10: single cert, bridge present (Root B absent)
echo "XSGRP,XSGN,TMP,file://./l2/xs/client-xsign.p12,pc_xsign" > ./l2/xs/xs_bridge.cfg

# Seq 11: single cert, no bridge (all roots present)
echo "XSGRP,NOBR,TMP,file://./l2/xs/client-nobridge.p12,pc_nobridge" > ./l2/xs/xs_allroots.cfg

# Seq 12: single cert, expired bridge
echo "XSGRP,EXPB,TMP,file://./l2/xs/client-expxs.p12,pc_expxs" > ./l2/xs/xs_expbridge.cfg

# Seq 13: single cert, revoked bridge
echo "XSGRP,REVB,TMP,file://./l2/xs/client-revxs.p12,pc_revxs" > ./l2/xs/xs_revbridge.cfg

# Seq 14-15: CRL tests (revoked + valid certs in same group)
echo "CRLGRP,CREV,TMP,file://./l2/xs/crl-revoked.p12,pc_crlrev" > ./l2/xs/xs_crl.cfg
echo "CRLGRP,CVAL,TMP,file://./l2/xs/crl-valid.p12,pc_crlval" >> ./l2/xs/xs_crl.cfg
echo "CRLGRP,IREV,TMP,file://./l2/xs/ica-revoked-leaf.p12,pc_icarev" >> ./l2/xs/xs_crl.cfg
echo "CRLGRP,IVAL,TMP,file://./l2/xs/ica-valid-leaf.p12,pc_icaval" >> ./l2/xs/xs_crl.cfg

# Seq 16-18: OCSP tests (valid + revoked certs in same group)
echo "OCSPGRP,OVAL,TMP,file://./l2/xs/ocsp-valid.p12,pc_ocspval" > ./l2/xs/xs_ocsp.cfg
echo "OCSPGRP,OREV,TMP,file://./l2/xs/ocsp-revoked.p12,pc_ocsprev" >> ./l2/xs/xs_ocsp.cfg

