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

# ── Cross-signed / CRL / OCSP test setup (sequences 9-17) ──────────────────
mkdir -p ./l2/xs

# 3.1 Placeholder P12 files (touch is sufficient for L2 state-machine tests)
touch ./l2/xs/client-xsign.p12
touch ./l2/xs/client-old.p12
touch ./l2/xs/client-new.p12
touch ./l2/xs/client-expxs.p12
touch ./l2/xs/crl-revoked.p12
touch ./l2/xs/crl-valid.p12
touch ./l2/xs/ica-valid-leaf.p12
touch ./l2/xs/ica-revoked-leaf.p12
touch ./l2/xs/ocsp-valid.p12
touch ./l2/xs/ocsp-revoked.p12
touch ./l2/xs/ocsp-noresponder.p12

# 3.2 xs_both_roots.cfg — both roots trusted; xsign cert (seq 9)
echo "XSGRP,XSIG,TMP,file://./l2/xs/client-xsign.p12,xs-client" > ./l2/xs/xs_both_roots.cfg

# 3.3 xs_old_root_only.cfg — old-root-only config (seq 10 phase A)
echo "XSOLDGRP,OLD,TMP,file://./l2/xs/client-old.p12,xs-old" > ./l2/xs/xs_old_root_only.cfg

# 3.4 xs_new_root_only.cfg — new-root-only config (seq 10 phase B, seq 11)
echo "XSNEWGRP,XSIG,TMP,file://./l2/xs/client-xsign.p12,xs-newonly" > ./l2/xs/xs_new_root_only.cfg
echo "XSNEWGRP,OLD,TMP,file://./l2/xs/client-old.p12,xs-old" >> ./l2/xs/xs_new_root_only.cfg

# 3.5 xs_crl.cfg — CRL revocation (seq 12: CRLGRP, seq 13: ICAGRP)
echo "CRLGRP,REVO,TMP,file://./l2/xs/crl-revoked.p12,crl-revoked" > ./l2/xs/xs_crl.cfg
echo "CRLGRP,VALI,TMP,file://./l2/xs/crl-valid.p12,crl-valid" >> ./l2/xs/xs_crl.cfg
echo "ICAGRP,REVO,TMP,file://./l2/xs/ica-revoked-leaf.p12,ica-revoked" >> ./l2/xs/xs_crl.cfg
echo "ICAGRP,VALI,TMP,file://./l2/xs/ica-valid-leaf.p12,ica-valid" >> ./l2/xs/xs_crl.cfg

# 3.6 xs_ocsp.cfg — OCSP scenarios (seq 14: OCSPGOODGRP, seq 15: OCSPGRP, seq 16: OCSPNRGRP)
echo "OCSPGOODGRP,GOOD,TMP,file://./l2/xs/ocsp-valid.p12,ocsp-good" > ./l2/xs/xs_ocsp.cfg
echo "OCSPGRP,REVO,TMP,file://./l2/xs/ocsp-revoked.p12,ocsp-revoked" >> ./l2/xs/xs_ocsp.cfg
echo "OCSPGRP,GOOD,TMP,file://./l2/xs/ocsp-valid.p12,ocsp-good" >> ./l2/xs/xs_ocsp.cfg
echo "OCSPNRGRP,NOR,TMP,file://./l2/xs/ocsp-noresponder.p12,ocsp-noresponder" >> ./l2/xs/xs_ocsp.cfg
echo "OCSPNRGRP,GOOD,TMP,file://./l2/xs/ocsp-valid.p12,ocsp-good" >> ./l2/xs/xs_ocsp.cfg

# 3.7 xs_expxs.cfg — bridge-expiry (seq 17)
echo "EXPXSGRP,EXPX,TMP,file://./l2/xs/client-expxs.p12,xs-expxs" > ./l2/xs/xs_expxs.cfg
echo "EXPXSGRP,NEWC,TMP,file://./l2/xs/client-new.p12,xs-new" >> ./l2/xs/xs_expxs.cfg

