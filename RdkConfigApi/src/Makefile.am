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

AM_CPPFLAGS = -I$(top_srcdir)/RdkConfigApi/include
AM_CFLAGS = -Werror -Wall -Os $(CFLAGS)

# Source files for GetConfigFile binary
bin_PROGRAMS = GetConfigFile
GetConfigFile_SOURCES = GetSaveConfigFile.c rdkconfig.c
GetConfigFile_CFLAGS = $(AM_CFLAGS)

# Source files for rdkconfig static library
noinst_LIBRARIES = librdkconfig.a
librdkconfig_a_SOURCES = rdkconfig.c
librdkconfig_a_CFLAGS = $(AM_CFLAGS)
