##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2018 RDK Management
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
##########################################################################
# Automake options
AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -I$(top_srcdir)/CertSelector/include -I$(top_srcdir)/setTlsCert/include
AM_CXXFLAGS = -Wall
AM_CFLAGS =  -Werror -Wall -Os $(CFLAGS)

if RDKLOGGER
AM_CFLAGS += -DRDKLOGGER
endif

lib_LTLIBRARIES = libsetTlsCert.la

libsetTlsCert_la_SOURCES = rdksettlscert.c
libsetTlsCert_la_CFLAGS = $(AM_CFLAGS)
libsetTlsCert_la_LDFLAGS = -no-undefined -shared
libsetTlsCert_la_includedir = $(includedir)
libsetTlsCert_la_LIBADD = $(top_builddir)/CertSelector/src/libRdkCertSelector.la
libsetTlsCert_la_DEPENDENCIES = $(top_builddir)/CertSelector/src/libRdkCertSelector.la
libsetTlsCert_la_include_HEADERS = \
    $(top_srcdir)/setTlsCert/include/rdkSetTlsCert.h \
    $(top_srcdir)/CertSelector/include/rdkcertselector.h
