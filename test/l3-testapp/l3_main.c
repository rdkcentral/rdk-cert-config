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
 * l3_main.c — L3 cert-selector + libcurl integration test runner
 *
 * Usage:  l3testapp <scenario_id>
 *
 * Scenario IDs:
 *   1  CRL mTLS  — connect with CRL client cert via certsel
 *                  (server state: valid or revoked, set by test driver)
 *   2  XSign     — connect with xsign bridge cert (expects CURLE_OK)
 *   3  XSign     — connect with old (no bridge) cert (expects failure)
 *   4  XSign     — connect with expired bridge cert (expects failure, fast)
 *   5  OCSP      — connect to OCSP stapling server (expects staple present)
 *   6  OCSP      — connect to non-stapling server with cert-status (expects failure)
 *
 * Exit code: 0 = expected outcome (see certsel_l3.c docstrings), 1 = failure.
 *
 * Prerequisites (ensured by run_l3.sh before pytest):
 *   ./l3/crl.cfg, ./l3/xs_bridge.cfg etc. written by test_setup.sh
 *   /opt/certs/crl/ and /opt/certs/xs/ populated by native-platform/certs.sh
 *   System trust store contains Test-CRL-Root and Test-XS-NewRoot
 *   mockxconf reachable at mockxconf:50061 and mockxconf:50064
 */

#include <stdio.h>
#include <stdlib.h>
#include "certsel_l3.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <scenario_id>\n", argv[0]);
        fprintf(stderr, "  1=crl  2=xs_bridge  3=xs_nobridge  4=xs_expxs"
                        "  5=ocsp_staple  6=ocsp_nostaple\n");
        return 1;
    }

    int scenario = atoi(argv[1]);
    int ret;

    switch (scenario) {
        case 1:  ret = run_l3_crl();          break;
        case 2:  ret = run_l3_xs_bridge();    break;
        case 3:  ret = run_l3_xs_nobridge();  break;
        case 4:  ret = run_l3_xs_expxs();     break;
        case 5:  ret = run_l3_ocsp_staple();  break;
        case 6:  ret = run_l3_ocsp_nostaple(); break;
        default:
            fprintf(stderr, "[l3] Unknown scenario %d\n", scenario);
            return 1;
    }

    fprintf(ret == 0 ? stdout : stderr,
            "[l3] scenario %d %s\n", scenario, ret == 0 ? "PASS" : "FAIL");
    return ret;
}
