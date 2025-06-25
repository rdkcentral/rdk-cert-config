#!/bin/sh

# Copyright 2024 Comcast Cable Communications Management, LLC
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
echo "********************"
echo "**** RUNNING GT STARTS ****"
echo "********************"
automake --add-missing
autoreconf --install

echo "********************"
echo "**** BUILD CERT SELECTOR/LOCATOR GT ****"
echo "********************"
./configure --enable-gtestapp
cd .//CertSelector/gtest/
mkdir -p ./ut/etc/ssl/certsel
echo "TSTGRP1,FRST,TMP,file://./ut/etc/ssl/certsel/tst1def.tmp,./ut/etc/ssl/certsel/pcdef" > ./ut/etc/ssl/certsel/certsel.cfg
touch ./ut/etc/ssl/certsel/tst1def.tmp ut/etc/ssl/certsel/pcdef
echo "hrotengine=e4tstdef" > ./ut/etc/ssl/certsel/hrot.properties
echo "TSTGRP1,FRST,TMP,file://./ut/tst1first.tmp,pc1" > ./ut/tst1certsel.cfg
echo "TSTGRP1,SCND,TMP,file://./ut/tst1second.tmp,pc2" >> ./ut/tst1certsel.cfg
echo "TSTGRP10,NOPC,TMP,file://./ut/tst1first.tmp,pc10" >> ./ut/tst1certsel.cfg
echo "TSTGRP1|TSTGRP3,THRD,TMP,file://./ut/tst1third.tmp,pc3" >> ./ut/tst1certsel.cfg
echo "TSTGRP2,ALPHA,TMP,file://./ut/tst1alpha.tmp,pcalpha" >> ./ut/tst1certsel.cfg
echo "UNKNWN,UNKNO,TMP,file://./ut/tst1unknown.tmp,pcunk" >> ./ut/tst1certsel.cfg
echo "A1|A2|A3|A4|A5|A6|A7|A8|A9|A10,ALPHA,TMP,file://./ut/tst1alpha.tmp,pcalpha" >> ./ut/tst1certsel.cfg
touch ./ut/tst1first.tmp
touch ./ut/tst1second.tmp
touch ./ut/tst1third.tmp
touch ./ut/tst1alpha.tmp
echo "hrotengine=e4tst1" > ./ut/tst1hrot.properties
echo "\nhrotengine=e4tst1" > ./ut/tst2hrot.properties
echo "hrotprovider=e4tst1" > ./ut/bad3hrot.properties
echo -n "GRP1,FRST,TMP,t1.tmp,pc1" > ./ut/tst1toolong.cfg
echo -n "0123456789112345678921234567893123456789412345678951234567896123456789712345678981234567899123456789" >> ./ut/tst1toolong.cfg
echo -n "0123456789112345678921234567893123456789412345678951234567896123456789712345678981234567899123456789" >> ./ut/tst1toolong.cfg
echo -n "0123456789112345678921234567893123456789412345678951234567896123456789712345678981234567899123456789" >> ./ut/tst1toolong.cfg
echo -n "0123456789112345678921234567893123456789412345678951234567896123456789712345678981234567899123456789" >> ./ut/tst1toolong.cfg
echo -n "0123456789112345678921234567893123456789412345678951234567896123456789712345678981234567899123456789" >> ./ut/tst1toolong.cfg
echo -n "0123456789112345678921234567893123456789412345678951234567896123456789712345678981234567899123456789" >> ./ut/tst1toolong.cfg
echo -n "0123456789112345678921234567893123456789412345678951234567896123456789712345678981234567899123456789" >> ./ut/tst1toolong.cfg
echo -n "0123456789112345678921234567893123456789412345678951234567896123456789712345678981234567899123456789" >> ./ut/tst1toolong.cfg
echo -n "0123456789112345678921234567893123456789412345678951234567896123456789712345678981234567899123456789" >> ./ut/tst1toolong.cfg
echo -n "0123456789112345678921234567893123456789412345678951234567896123456789712345678981234567899123456789" >> ./ut/tst1toolong.cfg
cp ./ut/tst1toolong.cfg ./ut/long4hrot.properties
echo "TSTGRP1" > ./ut/tst1miss2.cfg
echo "TSTGRP1,FRST," > ./ut/tst1miss3.cfg
echo "TSTGRP1,FRST,TMP" > ./ut/tst1miss4.cfg
echo "TSTGRP1,FRST,TMP,file://./ut/tst1first.tmp," > ./ut/tst1miss5.cfg
make


echo "**************************************"
echo "**** RUN CERT SELECTOR GT ****"
echo "**************************************"
./rdkcertselector_gtest
gRRDUTret=$?

if [ "0x$gRRDUTret" != "0x0"  ]; then
   echo "Error!!! RDK CERT SELECTOR GT FAILED. EXIT!!!"
   exit 1
fi

echo "**************************************"
echo "**** RUN CERT LOCATOR GT ****"
echo "**************************************"
./rdkcertlocator_gtest
gRRDUTret=$?

if [ "0x$gRRDUTret" != "0x0"  ]; then
   echo "Error!!! RDK CERT LOCATOR GT FAILED. EXIT!!!"
   exit 1
fi

echo "*********************************************************"
echo "**** CAPTURE RDK CERT SELECTOR/LOCATOR COVERAGE DATA ****"
echo "*********************************************************"
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage.filtered.info
genhtml coverage.filtered.info --output-directory out

echo "*************************"
echo "**** RUNNING UT ENDS ****"
echo "*************************"
