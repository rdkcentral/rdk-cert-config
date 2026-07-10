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
 * certsel_l3.c — L3 testapp implementation
 *
 * Unlike the L2 sampleapp (which feeds synthetic curl error codes),
 * this testapp makes real TLS connections using libcurl.  The cert-selector
 * API (rdkcertselector_getCert / rdkcertselector_setCurlStatus) is exercised
 * with the actual CURLcode returned by the live handshake, validating the
 * full stack: certsel → libcurl → mock-xconf TLS server.
 *
 * rdkconfig_getStr / rdkconfig_freeStr are mocked here (same pattern as
 * certsel_seq.c in l2-sampleapp).  All L3 test certificates use the
 * password "changeit" mapped via the single credential ref "l3pass".
 *
 * Security: private key material (the PKCS#12 passphrase) is passed to
 * libcurl via CURLOPT_KEYPASSWD and never written to stdout/stderr.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>

/* curl/curl.h transitively includes <linux/limits.h>, which defines PATH_MAX
 * as 4096.  rdkcertselector.h redefines PATH_MAX as 128 for its own object
 * length limits.  Drop the system definition here so the header's redefinition
 * is clean and does not trip -Werror.  This keeps the fix local to the L3
 * testapp and leaves the shared production header (and the L1 gtest build)
 * untouched. */
#undef PATH_MAX

#include "../../CertSelector/include/rdkcertselector.h"
#include "certsel_l3.h"

/* ── rdkconfig mock ─────────────────────────────────────────────────────────
 * Maps the single L3 credential ref "l3pass" to "changeit".
 * All other refs return RDKCONFIG_FAIL so misconfigured tests fail visibly.
 */

int rdkconfig_getStr(char **sbuff, size_t *sbuffsz, const char *refname)
{
    char *buf = (char *)malloc(GETSZ);
    if (!buf)
        return RDKCONFIG_FAIL;
    memset(buf, '.', GETSZ);

    if (strcmp(refname, L3_CRED_REF) == 0) {
        strncpy(buf, L3_CERT_PASS, GETSZ - 1);
        buf[GETSZ - 1] = '\0';
    } else {
        free(buf);
        fprintf(stderr, "[l3] rdkconfig_getStr: unknown ref '%s'\n", refname);
        return RDKCONFIG_FAIL;
    }

    *sbuff   = buf;
    *sbuffsz = strlen(buf) + 1;
    return RDKCONFIG_OK;
}

int rdkconfig_freeStr(char **sbuff, size_t sbuffsz)
{
    (void)sbuffsz;
    free(*sbuff);
    *sbuff = NULL;
    return RDKCONFIG_OK;
}

/* ── libcurl helpers ────────────────────────────────────────────────────────*/

/* Discard response body — we only care about the TLS handshake result */
static size_t discard_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

/*
 * do_mtls_curl() — perform a real mTLS connection using a PKCS#12 client cert.
 *
 * The server certificate is verified against the system trust store (updated by
 * native-platform/certs.sh with Test-CRL-Root and Test-XS-NewRoot).
 *
 * @param url          Target HTTPS URL
 * @param p12_path     Absolute path to PKCS#12 bundle (no "file://" prefix)
 * @param pass         PKCS#12 passphrase
 * @param ocsp_check   Non-zero to request OCSP stapling verification
 *
 * Returns the raw CURLcode (CURLE_OK == 0 means the handshake and request
 * succeeded; any other value means failure).
 */
static unsigned int do_mtls_curl(const char *url, const char *p12_path,
                                  const char *pass, int ocsp_check)
{
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "[l3] curl_easy_init failed\n");
        return (unsigned int)CURLE_FAILED_INIT;
    }

    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_SSLCERT,       p12_path);
    curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,   "P12");
    curl_easy_setopt(curl, CURLOPT_KEYPASSWD,     pass);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR,   1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_cb);
    if (ocsp_check)
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK)
        fprintf(stderr, "[l3] curl error %u: %s\n",
                (unsigned int)rc, curl_easy_strerror(rc));

    curl_easy_cleanup(curl);
    return (unsigned int)rc;
}

/* ── Generic certsel + libcurl scenario ─────────────────────────────────────
 *
 * 1. rdkcertselector_new()  — reads @cfg, locates first cert for @group.
 * 2. rdkcertselector_getCert() — returns cert URI ("file:///...") and password.
 * 3. do_mtls_curl()         — makes the real TLS connection.
 * 4. rdkcertselector_setCurlStatus() — feeds the real CURLcode back to certsel.
 *
 * Returns 0 if the TLS connection succeeded (CURLE_OK), 1 otherwise.
 */
static int run_l3_scenario(const char *cfg, const char *hrot,
                             const char *group, const char *url)
{
    rdkcertselector_h cs = rdkcertselector_new(cfg, hrot, group);
    if (!cs) {
        fprintf(stderr, "[l3] certsel init failed (cfg=%s grp=%s)\n", cfg, group);
        return 1;
    }

    char *uri  = NULL;
    char *pass = NULL;
    rdkcertselectorStatus_t st = rdkcertselector_getCert(cs, &uri, &pass);
    if (st != certselectorOk) {
        fprintf(stderr, "[l3] getCert failed: %d (cfg=%s grp=%s)\n",
                (int)st, cfg, group);
        rdkcertselector_free(&cs);
        return 1;
    }

    /* certsel returns the URI with the "file://" scheme; strip it for libcurl */
    const char *p12_path = uri;
    if (strncmp(uri, "file://", 7) == 0)
        p12_path = uri + 7;

    fprintf(stdout, "[l3] connecting: url=%s cert=%s\n", url, p12_path);

    unsigned int curl_rc = do_mtls_curl(url, p12_path, pass, 0 /* no OCSP */);
    fprintf(stdout, "[l3] curl rc=%u (%s)\n", curl_rc,
            curl_rc == 0 ? "CURLE_OK" : curl_easy_strerror((CURLcode)curl_rc));

    rdkcertselector_setCurlStatus(cs, curl_rc, url);
    rdkcertselector_free(&cs);

    /* Return the raw CURLcode so the Python driver can assert on the specific
     * error (e.g. CURLE_OK=0 for expected success, CURLE_PEER_FAILED_VERIFICATION
     * for a rejected client cert). */
    return (int)curl_rc;
}

/* ── Scenario entry points ──────────────────────────────────────────────────*/

/* Scenario 1 — CRL mTLS: connect using the CRL client cert via certsel.
 * Server state (cert valid or revoked) is controlled externally by the Python
 * test driver (POST /crl/revoke or /crl/reset before invoking this scenario). */
int run_l3_crl(void)
{
    return run_l3_scenario(L3_CFG_CRL, L3_HROT, L3_GRP_CRL, L3_MTLS_URL);
}

/* Scenario 2 — XSign bridge: client-xsign.p12 embeds a valid cross-signed
 * bridge cert.  The server trusts Test-XS-NewRoot only.  Expects success. */
int run_l3_xs_bridge(void)
{
    return run_l3_scenario(L3_CFG_XSBRIDGE, L3_HROT, L3_GRP_BRIDGE, L3_MTLS_URL);
}

/* Scenario 3 — XSign no bridge: client-old.p12 has no bridge cert.  The
 * server cannot verify the chain to Test-XS-NewRoot.  Expects failure. */
int run_l3_xs_nobridge(void)
{
    return run_l3_scenario(L3_CFG_XSOLD, L3_HROT, L3_GRP_OLD, L3_MTLS_URL);
}

/* Scenario 4 — XSign expired bridge: client-expxs.p12 has an already-expired
 * bridge cert.  The TLS handshake must fail without a long timeout. */
int run_l3_xs_expxs(void)
{
    return run_l3_scenario(L3_CFG_XSEXPXS, L3_HROT, L3_GRP_EXPXS, L3_MTLS_URL);
}

/* Scenario 5 — OCSP staple present: connect to the OCSP stapling server
 * (port 50064) with CURLOPT_SSL_VERIFYSTATUS=1.  Returns 0 if the server
 * staples a valid OCSP response (CURLE_OK), 1 if not.
 * No client cert needed — this tests server-side stapling only. */
int run_l3_ocsp_staple(void)
{
    CURL *curl = curl_easy_init();
    if (!curl) return 1;

    curl_easy_setopt(curl, CURLOPT_URL,               L3_OCSP_URL);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR,        1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS,   1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,      discard_cb);

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK)
        fprintf(stderr, "[l3] ocsp_staple curl error %u: %s\n",
                (unsigned int)rc, curl_easy_strerror(rc));
    curl_easy_cleanup(curl);
    fprintf(stdout, "[l3] ocsp_staple rc=%u (expected 0)\n", (unsigned int)rc);
    /* Return the raw CURLcode (0 == staple present & good). */
    return (int)rc;
}

/* Scenario 6 — OCSP staple absent (negative control): connect to the CRL mTLS
 * server (port 50061) which does NOT implement OCSP stapling.  Uses the CRL
 * client cert from certsel for the mTLS handshake with CURLOPT_SSL_VERIFYSTATUS.
 * Expected result: curl fails with CURLE_SSL_INVALIDCERTSTATUS because no OCSP
 * staple is returned.
 * Returns the raw CURLcode (non-zero on the expected failure). */
int run_l3_ocsp_nostaple(void)
{
    rdkcertselector_h cs = rdkcertselector_new(L3_CFG_CRL, L3_HROT, L3_GRP_CRL);
    if (!cs) {
        fprintf(stderr, "[l3] certsel init failed for ocsp_nostaple\n");
        return 1;
    }

    char *uri = NULL, *pass = NULL;
    if (rdkcertselector_getCert(cs, &uri, &pass) != certselectorOk) {
        rdkcertselector_free(&cs);
        return 1;
    }
    const char *p12_path = (strncmp(uri, "file://", 7) == 0) ? uri + 7 : uri;

    CURL *curl = curl_easy_init();
    if (!curl) { rdkcertselector_free(&cs); return 1; }

    curl_easy_setopt(curl, CURLOPT_URL,               L3_MTLS_URL);
    curl_easy_setopt(curl, CURLOPT_SSLCERT,           p12_path);
    curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,       "P12");
    curl_easy_setopt(curl, CURLOPT_KEYPASSWD,         pass);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR,        1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS,   1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,      discard_cb);

    CURLcode rc = curl_easy_perform(curl);
    fprintf(stdout, "[l3] ocsp_nostaple rc=%u (expected non-zero)\n", (unsigned int)rc);

    rdkcertselector_setCurlStatus(cs, (unsigned int)rc, L3_MTLS_URL);
    curl_easy_cleanup(curl);
    rdkcertselector_free(&cs);

    /* Return the raw CURLcode; the negative control expects a non-zero
     * CURLE_SSL_INVALIDCERTSTATUS because the server does not staple. */
    return (int)rc;
}
