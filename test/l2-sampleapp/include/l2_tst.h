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
int run_seq9cs();
int run_seq10cs();
int run_seq11cs();
int run_seq12cs();
int run_seq13cs();
int run_seq14cs();
int run_seq15cs();
int run_seq16cs();
int run_seq17cs();
int run_seq18cs();

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
#define CURLERR_ISSUER 80
#define CURLERR_CERTSTATUS 91
#define CURL_SUCCESS 0
#define L2_SUCCESS 0
#define L2_FAIL 1

#define UTDIR "./l2"
#define XSDIR UTDIR "/xs"
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

/* Cross-sign test config files */
#define XS_NOBRIDGE_CFG  XSDIR "/xs_nobridge.cfg"
#define XS_BRIDGE_CFG    XSDIR "/xs_bridge.cfg"
#define XS_ALLROOTS_CFG  XSDIR "/xs_allroots.cfg"
#define XS_EXPBRIDGE_CFG XSDIR "/xs_expbridge.cfg"
#define XS_REVBRIDGE_CFG XSDIR "/xs_revbridge.cfg"
#define XS_CRL_CFG       XSDIR "/xs_crl.cfg"
#define XS_OCSP_CFG      XSDIR "/xs_ocsp.cfg"
#define XS_HROTPROP      XSDIR "/hrot.properties"

/* Cross-sign cert groups */
#define XSGRP   "XSGRP"
#define CRLGRP  "CRLGRP"
#define OCSPGRP "OCSPGRP"

/* Cross-sign P12 placeholder paths */
#define XSCERT_NOBRIDGE   XSDIR "/client-nobridge.p12"
#define XSCERT_XSIGN      XSDIR "/client-xsign.p12"
#define XSCERT_EXPXS      XSDIR "/client-expxs.p12"
#define XSCERT_REVXS      XSDIR "/client-revxs.p12"
#define XSCERT_CRL_REVOKED XSDIR "/crl-revoked.p12"
#define XSCERT_CRL_VALID   XSDIR "/crl-valid.p12"
#define XSCERT_ICA_REVOKED XSDIR "/ica-revoked-leaf.p12"
#define XSCERT_ICA_VALID   XSDIR "/ica-valid-leaf.p12"
#define XSCERT_OCSP_VALID  XSDIR "/ocsp-valid.p12"
#define XSCERT_OCSP_REVOKED XSDIR "/ocsp-revoked.p12"

/* Cross-sign credential references and passwords */
#define UTCRED_NOBRIDGE  "pc_nobridge"
#define UTCRED_XSIGN     "pc_xsign"
#define UTCRED_EXPXS     "pc_expxs"
#define UTCRED_REVXS     "pc_revxs"
#define UTCRED_CRLREV    "pc_crlrev"
#define UTCRED_CRLVAL    "pc_crlval"
#define UTCRED_ICAREV    "pc_icarev"
#define UTCRED_ICAVAL    "pc_icaval"
#define UTCRED_OCSPVAL   "pc_ocspval"
#define UTCRED_OCSPREV   "pc_ocsprev"
#define UTPASS_NOBRIDGE  UTCRED_NOBRIDGE "pass"
#define UTPASS_XSIGN     UTCRED_XSIGN "pass"
#define UTPASS_EXPXS     UTCRED_EXPXS "pass"
#define UTPASS_REVXS     UTCRED_REVXS "pass"
#define UTPASS_CRLREV    UTCRED_CRLREV "pass"
#define UTPASS_CRLVAL    UTCRED_CRLVAL "pass"
#define UTPASS_ICAREV    UTCRED_ICAREV "pass"
#define UTPASS_ICAVAL    UTCRED_ICAVAL "pass"
#define UTPASS_OCSPVAL   UTCRED_OCSPVAL "pass"
#define UTPASS_OCSPREV   UTCRED_OCSPREV "pass"

#define GETSZ 50
#define RDKCONFIG_OK 0
#define RDKCONFIG_FAIL 1 // general failure

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
