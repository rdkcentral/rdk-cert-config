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
 * certsel_l3.h — L3 testapp constants and scenario declarations
 *
 * Certsel config files are written at runtime by test_setup.sh (called from
 * run_l3.sh before pytest).  All cert URIs point to absolute paths under
 * /opt/certs/, where native-platform/certs.sh installs PKI assets when
 * ENABLE_CRL_L3=true.
 *
 * Scenario IDs (used by l3_main.c dispatch and test_l3_crl_xsign.py):
 *   1  CRL mTLS  — connect with CRL client cert via certsel
 *   2  XSign     — connect with xsign bridge cert via certsel (expects success)
 *   3  XSign     — connect with old (no bridge) cert via certsel (expects failure)
 *   4  XSign     — connect with expired bridge cert via certsel (expects failure)
 *   5  OCSP      — connect to OCSP stapling server; verify staple present
 *   6  OCSP      — connect to non-stapling server with cert-status check; verify failure
 */

#ifndef __CERTSEL_L3_H__
#define __CERTSEL_L3_H__

/* ── Certsel config paths (relative to repo root, created by test_setup.sh) ── */
#define L3DIR            "./l3"
#define L3_HROT          L3DIR "/hrot.properties"
#define L3_CFG_CRL       L3DIR "/crl.cfg"
#define L3_CFG_XSBRIDGE  L3DIR "/xs_bridge.cfg"
#define L3_CFG_XSOLD     L3DIR "/xs_nobridge.cfg"
#define L3_CFG_XSEXPXS   L3DIR "/xs_expxs.cfg"

/* ── Certsel group names (must match test_setup.sh config entries) ── */
#define L3_GRP_CRL       "CRL_L3_GRP"
#define L3_GRP_BRIDGE    "XS_BRIDGE_GRP"
#define L3_GRP_OLD       "XS_OLD_GRP"
#define L3_GRP_EXPXS     "XS_EXPXS_GRP"

/* ── Credential ref and password (all L3 test certs use "changeit") ── */
#define L3_CRED_REF      "l3pass"
#define L3_CERT_PASS     "changeit"

/* ── Target URLs (mock-xconf reachable from native-platform via --link) ── */
#define L3_MTLS_URL      "https://mockxconf:50061/health"
#define L3_OCSP_URL      "https://mockxconf:50064/health"

/* ── Mock rdkconfig constants (same values as l2_tst.h) ── */
#define GETSZ            50
#define RDKCONFIG_OK     0
#define RDKCONFIG_FAIL   1

/* ── Scenario function declarations ── */
int run_l3_crl(void);         /* scenario 1: CRL client cert via certsel    */
int run_l3_xs_bridge(void);   /* scenario 2: xsign bridge cert via certsel  */
int run_l3_xs_nobridge(void); /* scenario 3: old (no bridge) cert           */
int run_l3_xs_expxs(void);    /* scenario 4: expired bridge cert            */
int run_l3_ocsp_staple(void); /* scenario 5: OCSP staple present check      */
int run_l3_ocsp_nostaple(void); /* scenario 6: non-stapling server check    */

#endif /* __CERTSEL_L3_H__ */
