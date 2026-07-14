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

/*
 * certsel_xsign.c — L2 test sequences 9-17
 *
 * Covers:
 *   Seq 9-11  : Cross-signed mTLS (XSign)
 *   Seq 12-13 : CRL revocation
 *   Seq 14-16 : OCSP stapling
 *   Seq 17    : Cross-signed bridge expiry mid-session
 *
 * All sequences feed synthetic curl error codes via certGetAndSet() —
 * no real TLS connections are made. Placeholder P12 files in ./l2/xs/
 * are created by test_setup.sh.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "include/l2_tst.h"
#include "include/rdkcertselector.h"
#include "include/unit_test.h"

/* certGetAndSet is implemented in certsel_seq.c; forward-declare it here so the
 * sequence 9-17 tests can call it, resolved at link time. */
int certGetAndSet(rdkcertselector_h, unsigned int, const char *, const char *, rdkcertselectorRetry_t);

/* ──────────────────────────────────────────────────────────────────────────
 * Sequence 9 — XSign: both OldRoot and NewRoot present in CA store
 *
 * Config: xs_both_roots.cfg / XSGRP
 * Certs:  [1] client-xsign.p12 (bridge embedded)
 *
 * Step 1: getCert → client-xsign.p12; setCurlStatus(SUCCESS) → NO_RETRY
 * Step 2: next call reuses client-xsign.p12 → NO_RETRY
 * ──────────────────────────────────────────────────────────────────────────*/
int run_seq9cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq9cs = rdkcertselector_new(XS_CFG_BOTH, L2_HROTPROP, XSGRP);
        L2_NOTNULL(seq9cs, "Cert selector initialization failed for sequence 9\n");

        /* both roots present — xsign cert selected immediately */
        L2_TST(certGetAndSet(seq9cs, CURL_SUCCESS, FILESCHEME XSCERT_XSIG, XSPASS_XSIG, NO_RETRY));
        /* next call: same cert reused */
        L2_TST(certGetAndSet(seq9cs, CURL_SUCCESS, FILESCHEME XSCERT_XSIG, XSPASS_XSIG, NO_RETRY));

        rdkcertselector_free(&seq9cs);
        L2_NULL(seq9cs, "Cert selector memory free failed for sequence 9\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Sequence 10 — XSign: OldRoot expires; operator migrates to new-root config
 *
 * Phase A — xs_old_root_only.cfg / XSOLDGRP
 *   Step 1: old cert works         → SUCCESS / NO_RETRY
 *   Step 2: OldRoot expired on SVR → CACERT(60) / NO_RETRY
 *            (server-side trust failure — selector does NOT try another cert)
 *
 * Phase B — xs_new_root_only.cfg / XSNEWGRP (new session after config migration)
 *   Step 3: xsign cert via bridge  → SUCCESS / NO_RETRY
 * ──────────────────────────────────────────────────────────────────────────*/
int run_seq10cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);

        /* ── Phase A: old-root-only config ── */
        rdkcertselector_h seq10a = rdkcertselector_new(XS_CFG_OLD, L2_HROTPROP, XSOLDGRP);
        L2_NOTNULL(seq10a, "Cert selector init failed for sequence 10 phase A\n");

        /* old cert works */
        L2_TST(certGetAndSet(seq10a, CURL_SUCCESS, FILESCHEME XSCERT_OLD, XSPASS_OLD, NO_RETRY));
        /* OldRoot expires on the server side — server sends CACERT error;
         * certsel maps CURLERR_CACERT → NO_RETRY (server trust failure, not
         * a local cert problem — don't try another client cert) */
        L2_TST(certGetAndSet(seq10a, CURLERR_CACERT, FILESCHEME XSCERT_OLD, XSPASS_OLD, NO_RETRY));

        rdkcertselector_free(&seq10a);
        L2_NULL(seq10a, "Cert selector memory free failed for sequence 10 phase A\n");

        /* ── Phase B: new-root-only config (config migrated by operator) ── */
        rdkcertselector_h seq10b = rdkcertselector_new(XS_CFG_NEW, L2_HROTPROP, XSNEWGRP);
        L2_NOTNULL(seq10b, "Cert selector init failed for sequence 10 phase B\n");

        /* xsign cert succeeds via cross-signed bridge to NewRoot */
        L2_TST(certGetAndSet(seq10b, CURL_SUCCESS, FILESCHEME XSCERT_XSIG, XSPASS_NEWONLY, NO_RETRY));

        rdkcertselector_free(&seq10b);
        L2_NULL(seq10b, "Cert selector memory free failed for sequence 10 phase B\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Sequence 11 — XSign: NewRoot absent from CA store
 *
 * Config: xs_new_root_only.cfg / XSNEWGRP
 * Certs:  [1] client-xsign.p12  [2] client-old.p12
 *
 * Client trust store has only OldRoot — server cert (signed by NewRoot)
 * cannot be verified; both certs fail with CURLERR_ISSUER → NoCert state.
 *
 * Step 1: xsign cert → ISSUER(80) / TRY_ANOTHER
 * Step 2: old cert  → ISSUER(80) / NO_RETRY  (NoCert — no more certs)
 * ──────────────────────────────────────────────────────────────────────────*/
int run_seq11cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq11cs = rdkcertselector_new(XS_CFG_NEW, L2_HROTPROP, XSNEWGRP);
        L2_NOTNULL(seq11cs, "Cert selector initialization failed for sequence 11\n");

        /* NewRoot absent — server cert unverifiable by client */
        L2_TST(certGetAndSet(seq11cs, CURLERR_ISSUER, FILESCHEME XSCERT_XSIG, XSPASS_NEWONLY, TRY_ANOTHER));
        /* fallback old cert also fails (same issuer chain failure) → NoCert */
        L2_TST(certGetAndSet(seq11cs, CURLERR_ISSUER, FILESCHEME XSCERT_OLD, XSPASS_OLD, NO_RETRY));

        rdkcertselector_free(&seq11cs);
        L2_NULL(seq11cs, "Cert selector memory free failed for sequence 11\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Sequence 12 — CRL: leaf cert is on the CRL
 *
 * Config: xs_crl.cfg / CRLGRP
 * Certs:  [1] crl-revoked.p12  [2] crl-valid.p12
 *
 * Step 1: revoked cert  → CERTSTATUS(91) / TRY_ANOTHER
 * Step 2: valid cert    → SUCCESS / NO_RETRY
 * Step 3: next call skips revoked, uses valid directly
 * ──────────────────────────────────────────────────────────────────────────*/
int run_seq12cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq12cs = rdkcertselector_new(XS_CFG_CRL, L2_HROTPROP, CRLGRP);
        L2_NOTNULL(seq12cs, "Cert selector initialization failed for sequence 12\n");

        /* revoked leaf cert triggers CRL status failure */
        L2_TST(certGetAndSet(seq12cs, CURLERR_CERTSTATUS, FILESCHEME CRLCERT_REVOKED, CRLPASS_REVOKED, TRY_ANOTHER));
        /* valid cert selected */
        L2_TST(certGetAndSet(seq12cs, CURL_SUCCESS, FILESCHEME CRLCERT_VALID, CRLPASS_VALID, NO_RETRY));
        /* subsequent call: revoked cert permanently skipped, valid cert reused */
        L2_TST(certGetAndSet(seq12cs, CURL_SUCCESS, FILESCHEME CRLCERT_VALID, CRLPASS_VALID, NO_RETRY));

        rdkcertselector_free(&seq12cs);
        L2_NULL(seq12cs, "Cert selector memory free failed for sequence 12\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Sequence 13 — CRL: intermediate CA is revoked
 *
 * Config: xs_crl.cfg / ICAGRP
 * Certs:  [1] ica-revoked-leaf.p12  [2] ica-valid-leaf.p12
 *
 * CURLERR_ISSUER(80) signals that the ICA's chain cannot be verified
 * (ICA is on the CRL — issuer of the leaf is untrusted).
 *
 * Step 1: revoked ICA leaf → ISSUER(80) / TRY_ANOTHER
 * Step 2: valid ICA leaf   → SUCCESS / NO_RETRY
 * ──────────────────────────────────────────────────────────────────────────*/
int run_seq13cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq13cs = rdkcertselector_new(XS_CFG_CRL, L2_HROTPROP, ICAGRP);
        L2_NOTNULL(seq13cs, "Cert selector initialization failed for sequence 13\n");

        /* leaf under revoked ICA — issuer chain failure */
        L2_TST(certGetAndSet(seq13cs, CURLERR_ISSUER, FILESCHEME ICACERT_REVOKED, ICAPASS_REVOKED, TRY_ANOTHER));
        /* leaf under valid ICA succeeds */
        L2_TST(certGetAndSet(seq13cs, CURL_SUCCESS, FILESCHEME ICACERT_VALID, ICAPASS_VALID, NO_RETRY));

        rdkcertselector_free(&seq13cs);
        L2_NULL(seq13cs, "Cert selector memory free failed for sequence 13\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Sequence 14 — OCSP: server staples a good OCSP response
 *
 * Config: xs_ocsp.cfg / OCSPGOODGRP
 * Certs:  [1] ocsp-valid.p12
 *
 * Step 1: good OCSP status → SUCCESS / NO_RETRY
 * Step 2: reused on next call
 * ──────────────────────────────────────────────────────────────────────────*/
int run_seq14cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq14cs = rdkcertselector_new(XS_CFG_OCSP, L2_HROTPROP, OCSPGOODGRP);
        L2_NOTNULL(seq14cs, "Cert selector initialization failed for sequence 14\n");

        /* good OCSP — cert selected without fallback */
        L2_TST(certGetAndSet(seq14cs, CURL_SUCCESS, FILESCHEME OCSPCERT_VALID, OCSPPASS_VALID, NO_RETRY));
        /* reused */
        L2_TST(certGetAndSet(seq14cs, CURL_SUCCESS, FILESCHEME OCSPCERT_VALID, OCSPPASS_VALID, NO_RETRY));

        rdkcertselector_free(&seq14cs);
        L2_NULL(seq14cs, "Cert selector memory free failed for sequence 14\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Sequence 15 — OCSP: server staples a revoked OCSP response
 *
 * Config: xs_ocsp.cfg / OCSPGRP
 * Certs:  [1] ocsp-revoked.p12  [2] ocsp-valid.p12
 *
 * Step 1: revoked OCSP → CERTSTATUS(91) / TRY_ANOTHER
 * Step 2: valid cert   → SUCCESS / NO_RETRY
 * Step 3: revoked cert stays skipped, valid cert reused
 * ──────────────────────────────────────────────────────────────────────────*/
int run_seq15cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq15cs = rdkcertselector_new(XS_CFG_OCSP, L2_HROTPROP, OCSPGRP);
        L2_NOTNULL(seq15cs, "Cert selector initialization failed for sequence 15\n");

        /* revoked OCSP status */
        L2_TST(certGetAndSet(seq15cs, CURLERR_CERTSTATUS, FILESCHEME OCSPCERT_REVOKED, OCSPPASS_REVOKED, TRY_ANOTHER));
        /* fallback to valid cert */
        L2_TST(certGetAndSet(seq15cs, CURL_SUCCESS, FILESCHEME OCSPCERT_VALID, OCSPPASS_VALID, NO_RETRY));
        /* revoked cert stays skipped */
        L2_TST(certGetAndSet(seq15cs, CURL_SUCCESS, FILESCHEME OCSPCERT_VALID, OCSPPASS_VALID, NO_RETRY));

        rdkcertselector_free(&seq15cs);
        L2_NULL(seq15cs, "Cert selector memory free failed for sequence 15\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Sequence 16 — OCSP hard-fail: OCSP responder unreachable
 *
 * Config: xs_ocsp.cfg / OCSPNRGRP
 * Certs:  [1] ocsp-noresponder.p12  [2] ocsp-valid.p12
 *
 * Step 1: noresponder → CERTSTATUS(91) / TRY_ANOTHER
 * Step 2: fallback to valid cert → SUCCESS / NO_RETRY
 * Step 3: noresponder stays skipped → valid cert reused
 * Step 4: touch noresponder file (simulates cert renewal after responder recovery)
 * Step 5: noresponder cert reused → SUCCESS / NO_RETRY
 * ──────────────────────────────────────────────────────────────────────────*/
int run_seq16cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq16cs = rdkcertselector_new(XS_CFG_OCSP, L2_HROTPROP, OCSPNRGRP);
        L2_NOTNULL(seq16cs, "Cert selector initialization failed for sequence 16\n");

        /* OCSP responder unreachable — hard-fail */
        L2_TST(certGetAndSet(seq16cs, CURLERR_CERTSTATUS, FILESCHEME OCSPCERT_NORESP, OCSPPASS_NORESP, TRY_ANOTHER));
        /* fallback cert used */
        L2_TST(certGetAndSet(seq16cs, CURL_SUCCESS, FILESCHEME OCSPCERT_VALID, OCSPPASS_VALID, NO_RETRY));
        /* noresponder cert still skipped */
        L2_TST(certGetAndSet(seq16cs, CURL_SUCCESS, FILESCHEME OCSPCERT_VALID, OCSPPASS_VALID, NO_RETRY));

        /* responder recovers — simulate cert renewal by updating file timestamp */
        sleep(1);
        UT_SYSTEM0("touch " OCSPCERT_NORESP);

        /* noresponder cert is now fresh — selector reselects it */
        L2_TST(certGetAndSet(seq16cs, CURL_SUCCESS, FILESCHEME OCSPCERT_NORESP, OCSPPASS_NORESP, NO_RETRY));

        rdkcertselector_free(&seq16cs);
        L2_NULL(seq16cs, "Cert selector memory free failed for sequence 16\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

/* ──────────────────────────────────────────────────────────────────────────
 * Sequence 17 — XSign bridge expiry mid-session
 *
 * Config: xs_expxs.cfg / EXPXSGRP
 * Certs:  [1] client-expxs.p12 (expired bridge)  [2] client-new.p12
 *
 * Step 1: first call with valid bridge     → SUCCESS / NO_RETRY
 * Step 2: bridge expires mid-session       → ISSUER(80) / TRY_ANOTHER
 * Step 3: fallback to new-root cert        → SUCCESS / NO_RETRY
 * Step 4: expxs cert stays skipped         → new-root cert reused
 * Step 5: touch expxs (simulate reissuance of bundle with fresh bridge)
 * Step 6: expxs cert freshened             → SUCCESS / NO_RETRY
 * ──────────────────────────────────────────────────────────────────────────*/
int run_seq17cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq17cs = rdkcertselector_new(XS_CFG_EXPXS, L2_HROTPROP, EXPXSGRP);
        L2_NOTNULL(seq17cs, "Cert selector initialization failed for sequence 17\n");

        /* first call — bridge still valid */
        L2_TST(certGetAndSet(seq17cs, CURL_SUCCESS, FILESCHEME XSCERT_EXPXS, XSPASS_EXPXS, NO_RETRY));

        /* bridge expires mid-session — issuer chain failure */
        L2_TST(certGetAndSet(seq17cs, CURLERR_ISSUER, FILESCHEME XSCERT_EXPXS, XSPASS_EXPXS, TRY_ANOTHER));
        /* new-root cert takes over */
        L2_TST(certGetAndSet(seq17cs, CURL_SUCCESS, FILESCHEME XSCERT_NEW, XSPASS_NEW, NO_RETRY));
        /* expired-bridge cert stays skipped */
        L2_TST(certGetAndSet(seq17cs, CURL_SUCCESS, FILESCHEME XSCERT_NEW, XSPASS_NEW, NO_RETRY));

        /* simulate bundle reissuance with fresh bridge */
        sleep(1);
        UT_SYSTEM0("touch " XSCERT_EXPXS);

        /* expxs cert freshened — reselected */
        L2_TST(certGetAndSet(seq17cs, CURL_SUCCESS, FILESCHEME XSCERT_EXPXS, XSPASS_EXPXS, NO_RETRY));

        rdkcertselector_free(&seq17cs);
        L2_NULL(seq17cs, "Cert selector memory free failed for sequence 17\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}
