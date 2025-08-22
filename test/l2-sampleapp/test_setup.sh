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

