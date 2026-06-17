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
/* Cross-signed / CRL / OCSP sequences (9-17) */
int run_seq9cs();
int run_seq10cs();
int run_seq11cs();
int run_seq12cs();
int run_seq13cs();
int run_seq14cs();
int run_seq15cs();
int run_seq16cs();
int run_seq17cs();

#define RDK_LOG(a1, a2, args...) fprintf(stderr, args)
#define RDK_LOG_INFO 0
#define RDK_LOG_ERROR 0
#define RDK_LOG_DEBUG 0
#define LOG_LIB 0

#define ERROR_LOG(...) RDK_LOG(RDK_LOG_ERROR, LOG_LIB, __VA_ARGS__)
#define DEBUG_LOG(...) RDK_LOG(RDK_LOG_INFO, LOG_LIB, __VA_ARGS__)

#define L2_HROTPROP  "./l2/etc/ssl/certsel/hrot.properties"
#define FILESCHEME "file://"
#define CURLERR_LOCALCERT   58  /* CURLE_SSL_CERTPROBLEM  - local cert error   */
#define CURLERR_CACERT      60  /* CURLE_SSL_CACERT       - server CA failure   */
#define CURLERR_ISSUER      80  /* CURLE_SSL_ISSUER_ERROR - issuer chain error  */
#define CURLERR_CERTSTATUS  91  /* CURLE_SSL_INVALIDCERTSTATUS - CRL/OCSP revoked */
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

/* ── Cross-signed / CRL / OCSP cert paths (sequences 9-17) ── */
#define XSDIR           UTDIR "/xs"

/* cert file paths */
#define XSCERT_XSIG     XSDIR "/client-xsign.p12"
#define XSCERT_OLD      XSDIR "/client-old.p12"
#define XSCERT_NEW      XSDIR "/client-new.p12"
#define XSCERT_EXPXS    XSDIR "/client-expxs.p12"
#define CRLCERT_REVOKED XSDIR "/crl-revoked.p12"
#define CRLCERT_VALID   XSDIR "/crl-valid.p12"
#define ICACERT_REVOKED XSDIR "/ica-revoked-leaf.p12"
#define ICACERT_VALID   XSDIR "/ica-valid-leaf.p12"
#define OCSPCERT_VALID  XSDIR "/ocsp-valid.p12"
#define OCSPCERT_REVOKED XSDIR "/ocsp-revoked.p12"
#define OCSPCERT_NORESP  XSDIR "/ocsp-noresponder.p12"

/* credential refs */
#define XSCRED_XSIG     "xs-client"
#define XSCRED_OLD      "xs-old"
#define XSCRED_NEW      "xs-new"
#define XSCRED_EXPXS    "xs-expxs"
#define XSCRED_NEWONLY  "xs-newonly"
#define CRLCRED_REVOKED "crl-revoked"
#define CRLCRED_VALID   "crl-valid"
#define ICACRED_REVOKED "ica-revoked"
#define ICACRED_VALID   "ica-valid"
#define OCSPCRED_VALID  "ocsp-good"
#define OCSPCRED_REVOKED "ocsp-revoked"
#define OCSPCRED_NORESP  "ocsp-noresponder"

/* passwords (credref + "pass") */
#define XSPASS_XSIG     XSCRED_XSIG "pass"
#define XSPASS_OLD      XSCRED_OLD "pass"
#define XSPASS_NEW      XSCRED_NEW "pass"
#define XSPASS_EXPXS    XSCRED_EXPXS "pass"
#define XSPASS_NEWONLY  XSCRED_NEWONLY "pass"
#define CRLPASS_REVOKED CRLCRED_REVOKED "pass"
#define CRLPASS_VALID   CRLCRED_VALID "pass"
#define ICAPASS_REVOKED ICACRED_REVOKED "pass"
#define ICAPASS_VALID   ICACRED_VALID "pass"
#define OCSPPASS_VALID  OCSPCRED_VALID "pass"
#define OCSPPASS_REVOKED OCSPCRED_REVOKED "pass"
#define OCSPPASS_NORESP  OCSPCRED_NORESP "pass"

/* certsel config files */
#define XS_CFG_BOTH  XSDIR "/xs_both_roots.cfg"
#define XS_CFG_OLD   XSDIR "/xs_old_root_only.cfg"
#define XS_CFG_NEW   XSDIR "/xs_new_root_only.cfg"
#define XS_CFG_CRL   XSDIR "/xs_crl.cfg"
#define XS_CFG_OCSP  XSDIR "/xs_ocsp.cfg"
#define XS_CFG_EXPXS XSDIR "/xs_expxs.cfg"

/* certsel groups */
#define XSGRP    "XSGRP"
#define XSOLDGRP "XSOLDGRP"
#define XSNEWGRP "XSNEWGRP"
#define CRLGRP   "CRLGRP"
#define ICAGRP   "ICAGRP"
#define OCSPGOODGRP "OCSPGOODGRP"
#define OCSPGRP     "OCSPGRP"
#define OCSPNRGRP   "OCSPNRGRP"
#define EXPXSGRP    "EXPXSGRP"

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
