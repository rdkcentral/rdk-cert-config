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
AC_PREREQ([2.65])

AC_INIT([libcertconfig], [1.0], [piramanayagammoneka_lakshmi.com])
AC_CONFIG_SRCDIR([CertSelector])

AC_ENABLE_SHARED
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign])

LT_INIT

# Define and initialize GTest support variables
GTEST_SUPPORT_ENABLED=false
GTEST_ENABLE_FLAG=""
CSPC_RDKCONFIG_SUPPORT_ENABLED=false
CSPC_RDKCONFIG_ENABLE_FLAG=""
CSPC_L2_TEST=false
# Checks for following programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)
AC_PROG_INSTALL

# Checks for following header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h stdio.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_SUBST(TRACE_CFLAGS)
AC_SUBST(TRACE_LIBS)

#check for test program

AC_ARG_ENABLE([rdklogger],
AS_HELP_STRING([--enable-rdklogger],[This will enable/disable rdk logger ]),
[case "${enableval}" in
   yes) RDKLOGGER=true;;
   no) echo[RDK logger is not enabled];;
   *) AC_MSG_ERROR([bad value ${enableval} for --enable-rdklogger ]) ;;
esac],[echo " rdklogger is enabled"])
AM_CONDITIONAL([RDKLOGGER], [test x$RDKLOGGER = xtrue])

# Command-line option to enable GTest support
AC_ARG_ENABLE([gtestapp],
             AS_HELP_STRING([--enable-gtestapp],[enable Gtest support (default is no)]),
             [
               case "${enableval}" in
                yes) GTEST_SUPPORT_ENABLED=true
                     GTEST_ENABLE_FLAG="-DGTEST_ENABLE"
                     m4_if(m4_sysval,[0],[AC_CONFIG_FILES([CertSelector/gtest/Makefile])]);;
                no) GTEST_SUPPORT_ENABLED=false AC_MSG_ERROR([Gtest support is disabled]);;
                 *) AC_MSG_ERROR([bad value ${enableval} for --enable-gtestapp ]);;
               esac
             ],
             [echo "Gtestapp is disabled"])
AM_CONDITIONAL([GTEST_SUPPORT_ENABLED], [test x$GTEST_SUPPORT_ENABLED = xtrue])
# Set condition for GTest support
#Command-line option to disable stub function. 
AC_ARG_ENABLE([cspcrdkconfig],
             AS_HELP_STRING([--enable-cspcrdkconfig],[enable cspcrdkconfig support (default is no)]),
             [
               case "${enableval}" in
                yes) CSPC_RDKCONFIG_SUPPORT_ENABLED=true
                     CSPC_RDKCONFIG_ENABLE_FLAG="-DCSPC_RDKCONFIG_ENABLE" ;;
                no) CSPC_RDKCONFIG_SUPPORT_ENABLED=false AC_MSG_ERROR([cpcrdkconfig support is disabled]);;
                 *) AC_MSG_ERROR([bad value ${enableval} for --enable-cspcrdkconfig ]);;
               esac
             ],
             [echo "cspcrdkconfig is disabled"])
AM_CONDITIONAL([CSPC_RDKCONFIG_SUPPORT_ENABLED], [test x$CSPC_RDKCONFIG_SUPPORT_ENABLED = xtrue])

#set condition for l2 support
AC_ARG_ENABLE([l2testing],
             AS_HELP_STRING([--enable-l2testing],[enable l2 testing (default is no)]),
             [
               case "${enableval}" in
                yes) CSPC_L2_TEST=true
                     L2_TEST_FLAG="-DL2_ENABLE" ;;
                no)  CSPC_L2_TEST=false AC_MSG_ERROR([l2 support is disabled]);;
                 *) AC_MSG_ERROR([bad value ${enableval} for --enable-l2testing ]);;
               esac
             ],
             [echo "l2 is disabled"])
AM_CONDITIONAL([CSPC_L2_TEST], [test x$CSPC_L2_TEST = xtrue])
# Check for necessary programs
AC_PROG_CXX

# Initialize Libtool
AM_PROG_LIBTOOL(libtool)

# Check for necessary header files
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h stdio.h])

# Check for necessary libraries
AC_CHECK_LIB([jsoncpp], [main])
AC_CHECK_LIB([gtest], [main])
AC_CHECK_LIB([gmock], [main])
AC_CHECK_LIB([stdc++], [main])

# Check for typedefs, structures, and compiler characteristics
AC_C_INLINE
AC_HEADER_STDBOOL
AC_C_CONST

# Check for library functions
AC_FUNC_MALLOC
AC_FUNC_REALLOC

if test x$GTEST_SUPPORT_ENABLED == xfalse; then
AC_CONFIG_FILES([
     Makefile
     CertSelector/Makefile
     CertSelector/src/Makefile
     ])
AM_COND_IF([CSPC_RDKCONFIG_SUPPORT_ENABLED],[],[AC_CONFIG_FILES([RdkConfigApi/Makefile RdkConfigApi/src/Makefile])])
fi

AM_COND_IF([CSPC_L2_TEST],[AC_CONFIG_FILES([test/Makefile test/l2-sampleapp/Makefile])],[])

if test x$GTEST_SUPPORT_ENABLED == xtrue; then
# Checks for library functions.
AC_CHECK_HEADERS([jsoncpp/json/json.h gtest/gtest.h gmock/gmock.h])
fi

# Substitutions for GTest support
AC_SUBST(GTEST_ENABLE_FLAG)
AC_SUBST(CSPC_RDKCONFIG_ENABLE_FLAG)

AC_OUTPUT
