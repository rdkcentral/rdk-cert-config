/*
 * Copyright 2025 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __L2_TEST_H__
#define __L2_TEST_H__

unsigned long get_file_timestamp( const char *fname );
int run_seq1cs();
int run_seq2cs();
int run_seq3cs();
int run_seq4cs();
int run_seq5cs();
int run_seq6cs();
int run_dualseq1cs();
int run_badseq1();

#define RDK_LOG(a1, a2, args...) fprintf(stderr, args)
#define RDK_LOG_INFO 0
#define RDK_LOG_ERROR 0
#define RDK_LOG_DEBUG 0
#define LOG_LIB 0

#define ERROR_LOG(...) RDK_LOG(RDK_LOG_ERROR, LOG_LIB, __VA_ARGS__)
#define DEBUG_LOG(...) RDK_LOG(RDK_LOG_INFO, LOG_LIB, __VA_ARGS__)

#define L2_HROTPROP  "./l2/etc/ssl/certsel/hrot.properties"
#define FILESCHEME "file://"
#define CURLERR_LOCALCERT 58
#define CURLERR_NONCERT 1
#define CURL_SUCCESS 0
#define L2_SUCCESS 0
#define L2_FAIL 1

#define UTDIR "./l2"
#define CERTSEL_CFG UTDIR "/tst1certsel.cfg"
#define HROT_PROP UTDIR "/tst1hrot.properties"
#define HROT_PROP2 UTDIR "/tst2hrot.properties"
#define HROT_PROP_BAD UTDIR "/bad3hrot.properties" // bad format
#define HROT_PROP_LONG UTDIR "/long4hrot.properties" // long line
#define DEF_HROT_PROP UTDIR "/hrot.properties"
#define GRP1 "TSTGRP1"
#define GRP2 "TSTGRP2"
#define GRP3 "TSTGRP3"
#define GRP10 "TSTGRP10" // pc not found
#define LONGPATH "/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789"
#define UTCERT1 UTDIR "/tst1first.tmp"
#define UTCERT2 UTDIR "/tst1second.tmp"
#define UTCERT3 UTDIR "/tst1third.tmp"
#define UTCERTALPHA UTDIR "/tst1alpha.tmp"
#define UTCRED1 "pc1"
#define UTCRED2 "pc2"
#define UTCRED3 "pc3"
#define UTCREDALPHA "pcalpha"
#define UTPASS1 UTCRED1 "pass"
#define UTPASS2 UTCRED2 "pass"
#define UTPASS3 UTCRED3 "pass"
#define UTPASSALPHA UTCREDALPHA "pass"

#define L2_TST( a ) { \
        long tst=(long)(a); \
        if ( tst!=0 ) { fprintf(stderr,"act:%ld\n",tst); \
        return L2_FAIL; }}

#define L2_NOTNULL( a , str ) {\
        void *ptr=(a); \
        if ( ptr==NULL ) { \
        printf("failed to allocate memory\n"); \
        fprintf(stderr,"%s\n",str); \
        return L2_FAIL;  } }

#define L2_NULL( a , str) { \
        void *ptr=(a); \
        if ( ptr!=NULL ) { fprintf(stderr,"%s\n",str); \
        return L2_FAIL; }} 

#endif
