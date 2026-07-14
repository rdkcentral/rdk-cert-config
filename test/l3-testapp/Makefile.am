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

# l3testapp is a test binary — build but do not install
noinst_PROGRAMS = l3testapp

# Include the CertSelector headers; the compiler finds curl/curl.h via
# libcurl4-openssl-dev installed in the native-platform Docker image.
AM_CFLAGS = -Werror -Wall -Os $(CFLAGS) -I$(top_srcdir)/CertSelector/include/

l3testapp_SOURCES = l3_main.c certsel_l3.c

# Link against libRdkCertSelector (provides rdkcertselector_*) and libcurl
# (provides curl_easy_*).  The .la file is the libtool archive built earlier
# in the same 'make' run; the .so is the actual shared library.
l3testapp_LDADD = \
	../../CertSelector/src/libRdkCertSelector.la \
	../../CertSelector/src/.libs/libRdkCertSelector.so \
	$(CURL_LIBS)
