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

# Define the program name and the source files
bin_PROGRAMS = rdkcertselector_gtest rdkcertlocator_gtest

# Define the include directories
COMMON_CPPFLAGS = -I../ -I../../ -I../include -I./mock -DGTEST_ENABLE

# Define the libraries to link against
COMMON_LDADD = -lgtest -lgtest_main -lgmock_main -lgmock -lgcov  

# Define the compiler flags
COMMON_CXXFLAGS = -frtti -fprofile-arcs -ftest-coverage

# Define the source files
rdkcertselector_gtest_SOURCES = rdkcertselector_gtest.cpp 
rdkcertlocator_gtest_SOURCES = rdkcertlocator_gtest.cpp
# Apply common properties to each program
rdkcertselector_gtest_CPPFLAGS = $(COMMON_CPPFLAGS)
rdkcertselector_gtest_LDADD = $(COMMON_LDADD)
rdkcertselector_gtest_CXXFLAGS = $(COMMON_CXXFLAGS)
rdkcertselector_gtest_CFLAGS = $(COMMON_CXXFLAGS)

rdkcertlocator_gtest_CPPFLAGS = $(COMMON_CPPFLAGS)
rdkcertlocater_gtest_LDADD = $(COMMON_LDADD)
rdkcertlocater_gtest_CXXFLAGS = $(COMMON_CXXFLAGS)
rdkcertlocater_gtest_CFLAGS = $(COMMON_CXXFLAGS)
