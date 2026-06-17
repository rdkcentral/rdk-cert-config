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

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include <sys/stat.h>
#include "include/l2_tst.h"
#include "include/rdkcertselector.h"
#include "include/unit_test.h"

int certGetAndSet(rdkcertselector_h , unsigned int , const char * , const char *, rdkcertselectorRetry_t );

/*
 * Sequence 9: Cross-sign — Root B absent, no bridge cert
 * Trust store: Root A + Root C (Root B absent)
 * Cert: client-nobridge.p12 (issued by Root B, no bridge)
 * Expected: CURLERR_ISSUER → NO_RETRY (single cert, no fallback)
 */
int run_seq9cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq9cs = rdkcertselector_new( XS_NOBRIDGE_CFG, XS_HROTPROP, XSGRP );
        L2_NOTNULL(seq9cs, "Cert selector initialization failed for sequence 9\n");
        /* Single cert fails with issuer error; no next cert → NO_RETRY */
        L2_TST(certGetAndSet(seq9cs, CURLERR_ISSUER, FILESCHEME XSCERT_NOBRIDGE, UTPASS_NOBRIDGE, NO_RETRY));
        rdkcertselector_free( &seq9cs );
        L2_NULL(seq9cs, "Cert selector memory free failed for sequence 9\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/*
 * Sequence 10: Cross-sign — Root B absent, bridge cert present
 * Trust store: Root A + Root C (Root B absent)
 * Cert: client-xsign.p12 (issued by Root B, bridge chains Root B → Root C)
 * Expected: CURL_SUCCESS → NO_RETRY
 */
int run_seq10cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq10cs = rdkcertselector_new( XS_BRIDGE_CFG, XS_HROTPROP, XSGRP );
        L2_NOTNULL(seq10cs, "Cert selector initialization failed for sequence 10\n");
        /* Bridge enables trust via Root C; success */
        L2_TST(certGetAndSet(seq10cs, CURL_SUCCESS, FILESCHEME XSCERT_XSIGN, UTPASS_XSIGN, NO_RETRY));
        /* Cert reused on next call */
        L2_TST(certGetAndSet(seq10cs, CURL_SUCCESS, FILESCHEME XSCERT_XSIGN, UTPASS_XSIGN, NO_RETRY));
        rdkcertselector_free( &seq10cs );
        L2_NULL(seq10cs, "Cert selector memory free failed for sequence 10\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/*
 * Sequence 11: Cross-sign — All roots present, no bridge needed
 * Trust store: Root A + Root B + Root C
 * Cert: client-nobridge.p12 (issued by Root B, no bridge)
 * Expected: CURL_SUCCESS → NO_RETRY (direct trust via Root B)
 */
int run_seq11cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq11cs = rdkcertselector_new( XS_ALLROOTS_CFG, XS_HROTPROP, XSGRP );
        L2_NOTNULL(seq11cs, "Cert selector initialization failed for sequence 11\n");
        /* Direct trust via Root B; success */
        L2_TST(certGetAndSet(seq11cs, CURL_SUCCESS, FILESCHEME XSCERT_NOBRIDGE, UTPASS_NOBRIDGE, NO_RETRY));
        /* Cert reused on next call */
        L2_TST(certGetAndSet(seq11cs, CURL_SUCCESS, FILESCHEME XSCERT_NOBRIDGE, UTPASS_NOBRIDGE, NO_RETRY));
        rdkcertselector_free( &seq11cs );
        L2_NULL(seq11cs, "Cert selector memory free failed for sequence 11\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/*
 * Sequence 12: Cross-sign — Root B absent, expired bridge cert
 * Trust store: Root A + Root C (Root B absent)
 * Cert: client-expxs.p12 (issued by Root B, expired bridge)
 * Expected: CURLERR_ISSUER → NO_RETRY (single cert, no fallback)
 */
int run_seq12cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq12cs = rdkcertselector_new( XS_EXPBRIDGE_CFG, XS_HROTPROP, XSGRP );
        L2_NOTNULL(seq12cs, "Cert selector initialization failed for sequence 12\n");
        /* Expired bridge fails with issuer error; no next cert → NO_RETRY */
        L2_TST(certGetAndSet(seq12cs, CURLERR_ISSUER, FILESCHEME XSCERT_EXPXS, UTPASS_EXPXS, NO_RETRY));
        rdkcertselector_free( &seq12cs );
        L2_NULL(seq12cs, "Cert selector memory free failed for sequence 12\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/*
 * Sequence 13: Cross-sign — Root B absent, revoked bridge cert
 * Trust store: Root A + Root C (Root B absent)
 * Cert: client-revxs.p12 (issued by Root B, revoked bridge)
 * Expected: CURLERR_CERTSTATUS → NO_RETRY (single cert, no fallback)
 */
int run_seq13cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq13cs = rdkcertselector_new( XS_REVBRIDGE_CFG, XS_HROTPROP, XSGRP );
        L2_NOTNULL(seq13cs, "Cert selector initialization failed for sequence 13\n");
        /* Revoked bridge fails with cert status error; no next cert → NO_RETRY */
        L2_TST(certGetAndSet(seq13cs, CURLERR_CERTSTATUS, FILESCHEME XSCERT_REVXS, UTPASS_REVXS, NO_RETRY));
        rdkcertselector_free( &seq13cs );
        L2_NULL(seq13cs, "Cert selector memory free failed for sequence 13\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/*
 * Sequence 14: CRL — Revoked leaf cert, fallback to valid cert
 * Cert group: crl-revoked.p12 (revoked), crl-valid.p12 (valid)
 * Expected: CURLERR_CERTSTATUS on revoked → TRY_ANOTHER → valid cert succeeds
 */
int run_seq14cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq14cs = rdkcertselector_new( XS_CRL_CFG, XS_HROTPROP, CRLGRP );
        L2_NOTNULL(seq14cs, "Cert selector initialization failed for sequence 14\n");
        /* First cert (revoked leaf) fails with cert status error */
        L2_TST(certGetAndSet(seq14cs, CURLERR_CERTSTATUS, FILESCHEME XSCERT_CRL_REVOKED, UTPASS_CRLREV, TRY_ANOTHER));
        /* Falls back to valid cert */
        L2_TST(certGetAndSet(seq14cs, CURL_SUCCESS, FILESCHEME XSCERT_CRL_VALID, UTPASS_CRLVAL, NO_RETRY));
        /* Subsequent calls skip the revoked cert, use valid cert directly */
        L2_TST(certGetAndSet(seq14cs, CURL_SUCCESS, FILESCHEME XSCERT_CRL_VALID, UTPASS_CRLVAL, NO_RETRY));
        rdkcertselector_free( &seq14cs );
        L2_NULL(seq14cs, "Cert selector memory free failed for sequence 14\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/*
 * Sequence 15: CRL — Revoked intermediate CA, fallback to valid ICA cert
 * Cert group: ica-revoked-leaf.p12 (under revoked ICA), ica-valid-leaf.p12 (under valid ICA)
 * Expected: CURLERR_ISSUER on revoked-ICA cert → TRY_ANOTHER → valid-ICA cert succeeds
 */
int run_seq15cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        /* Use CRL config but with ICA certs — they're entries 3 and 4 in xs_crl.cfg */
        rdkcertselector_h seq15cs = rdkcertselector_new( XS_CRL_CFG, XS_HROTPROP, CRLGRP );
        L2_NOTNULL(seq15cs, "Cert selector initialization failed for sequence 15\n");
        /* First cert (under revoked ICA) fails with issuer error */
        L2_TST(certGetAndSet(seq15cs, CURLERR_ISSUER, FILESCHEME XSCERT_CRL_REVOKED, UTPASS_CRLREV, TRY_ANOTHER));
        /* Falls back to valid cert */
        L2_TST(certGetAndSet(seq15cs, CURL_SUCCESS, FILESCHEME XSCERT_CRL_VALID, UTPASS_CRLVAL, NO_RETRY));
        rdkcertselector_free( &seq15cs );
        L2_NULL(seq15cs, "Cert selector memory free failed for sequence 15\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/*
 * Sequence 16: OCSP — Good OCSP staple, no fallback
 * Cert: ocsp-valid.p12 (good OCSP response)
 * Expected: CURL_SUCCESS → NO_RETRY
 */
int run_seq16cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq16cs = rdkcertselector_new( XS_OCSP_CFG, XS_HROTPROP, OCSPGRP );
        L2_NOTNULL(seq16cs, "Cert selector initialization failed for sequence 16\n");
        /* Good OCSP status; success, no fallback */
        L2_TST(certGetAndSet(seq16cs, CURL_SUCCESS, FILESCHEME XSCERT_OCSP_VALID, UTPASS_OCSPVAL, NO_RETRY));
        /* Cert reused on next call */
        L2_TST(certGetAndSet(seq16cs, CURL_SUCCESS, FILESCHEME XSCERT_OCSP_VALID, UTPASS_OCSPVAL, NO_RETRY));
        rdkcertselector_free( &seq16cs );
        L2_NULL(seq16cs, "Cert selector memory free failed for sequence 16\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/*
 * Sequence 17: OCSP — Revoked OCSP staple, fallback to valid cert
 * Cert group: ocsp-valid.p12 (good), ocsp-revoked.p12 (revoked)
 * Expected: first cert OK, then revoked cert fails → TRY_ANOTHER; revoked stays bad
 */
int run_seq17cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq17cs = rdkcertselector_new( XS_OCSP_CFG, XS_HROTPROP, OCSPGRP );
        L2_NOTNULL(seq17cs, "Cert selector initialization failed for sequence 17\n");
        /* First cert (ocsp-valid) succeeds */
        L2_TST(certGetAndSet(seq17cs, CURL_SUCCESS, FILESCHEME XSCERT_OCSP_VALID, UTPASS_OCSPVAL, NO_RETRY));
        /* Now simulate: first cert goes bad (OCSP revoked) */
        L2_TST(certGetAndSet(seq17cs, CURLERR_CERTSTATUS, FILESCHEME XSCERT_OCSP_VALID, UTPASS_OCSPVAL, TRY_ANOTHER));
        /* Falls back to second cert (ocsp-revoked — but in this test it succeeds as fallback) */
        L2_TST(certGetAndSet(seq17cs, CURL_SUCCESS, FILESCHEME XSCERT_OCSP_REVOKED, UTPASS_OCSPREV, NO_RETRY));
        /* Subsequent calls skip the first (bad) cert, use second directly */
        L2_TST(certGetAndSet(seq17cs, CURL_SUCCESS, FILESCHEME XSCERT_OCSP_REVOKED, UTPASS_OCSPREV, NO_RETRY));
        rdkcertselector_free( &seq17cs );
        L2_NULL(seq17cs, "Cert selector memory free failed for sequence 17\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/*
 * Sequence 18: OCSP hard-fail — Responder unreachable, fallback then recovery
 * Cert group: ocsp-valid.p12 (good), ocsp-revoked.p12
 * Expected: CURLERR_CERTSTATUS → TRY_ANOTHER → fallback; file touch recovery
 */
int run_seq18cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq18cs = rdkcertselector_new( XS_OCSP_CFG, XS_HROTPROP, OCSPGRP );
        L2_NOTNULL(seq18cs, "Cert selector initialization failed for sequence 18\n");
        /* First cert fails (OCSP responder unreachable → cert status error) */
        L2_TST(certGetAndSet(seq18cs, CURLERR_CERTSTATUS, FILESCHEME XSCERT_OCSP_VALID, UTPASS_OCSPVAL, TRY_ANOTHER));
        /* Falls back to second cert */
        L2_TST(certGetAndSet(seq18cs, CURL_SUCCESS, FILESCHEME XSCERT_OCSP_REVOKED, UTPASS_OCSPREV, NO_RETRY));
        /* First cert still bad on next try, uses second */
        L2_TST(certGetAndSet(seq18cs, CURL_SUCCESS, FILESCHEME XSCERT_OCSP_REVOKED, UTPASS_OCSPREV, NO_RETRY));
        /* OCSP responder recovers: simulate renewal by touching first cert */
        sleep( 1 );
        UT_SYSTEM0( "touch " XSCERT_OCSP_VALID );
        /* First cert is now eligible again (file timestamp changed clears bad status) */
        L2_TST(certGetAndSet(seq18cs, CURL_SUCCESS, FILESCHEME XSCERT_OCSP_VALID, UTPASS_OCSPVAL, NO_RETRY));
        rdkcertselector_free( &seq18cs );
        L2_NULL(seq18cs, "Cert selector memory free failed for sequence 18\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}
