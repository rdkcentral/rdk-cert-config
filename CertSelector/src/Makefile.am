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

# Automake options
AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -I$(top_srcdir)/CertSelector/include 
if !CSPC_RDKCONFIG_SUPPORT_ENABLED
AM_CPPFLAGS += -I$(top_srcdir)/RdkConfigApi/include
endif
AM_CXXFLAGS = -Wall
AM_CFLAGS =  -Werror -Wall -Os $(CFLAGS)

if RDKLOGGER
AM_CFLAGS += -DRDKLOGGER
endif

lib_LTLIBRARIES = libRdkCertSelector.la

libRdkCertSelector_la_SOURCES = rdkcertselector.c
libRdkCertSelector_la_CFLAGS = $(AM_CFLAGS)
libRdkCertSelector_la_LDFLAGS = -no-undefined -shared
libRdkCertSelector_la_includedir = ${includedir}
libRdkCertSelector_la_include_HEADERS = ../include/rdkcertselector.h
if !CSPC_RDKCONFIG_SUPPORT_ENABLED
libRdkCertSelector_la_include_HEADERS = ../../RdkConfigApi/include/rdkconfig.h
endif

lib_LTLIBRARIES += libRdkCertLocator.la

libRdkCertLocator_la_SOURCES = rdkcertlocator.c
libRdkCertLocator_la_CFLAGS = $(AM_CFLAGS)
libRdkCertLocator_la_LDFLAGS = -no-undefined -shared
libRdkCertLocator_la_includedir = ${includedir}
libRdkCertLocator_la_include_HEADERS = ../include/rdkcertlocator.h
if !CSPC_RDKCONFIG_SUPPORT_ENABLED
libRdkCertLocator_la_include_HEADERS = ../../RdkConfigApi/include/rdkconfig.h
endif
