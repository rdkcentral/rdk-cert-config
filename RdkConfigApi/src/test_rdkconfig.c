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
 * Test override for rdkconfig APIs when TEST_RDK_CERTS is enabled.
 * Provides rdkconfig_get and rdkconfig_getStr implementations returning "changeit".
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "rdkconfig.h"

/*
 Contract:
 - rdkconfig_get: allocate buffer with exact data length and return RDKCONFIG_OK
 - rdkconfig_getStr: allocate buffer including null terminator (via strdup) and return RDKCONFIG_OK
 - Caller must free with rdkconfig_free / rdkconfig_freeStr
 - On error, return RDKCONFIG_FAIL and do not modify outputs
*/

static const char *kTestValue = "changeit";

int rdkconfig_get(uint8_t **sbuff, size_t *sbuffsz, const char *refname) {
    (void)refname; // unused in test override
    if (!sbuff || !sbuffsz) {
        return RDKCONFIG_FAIL;
    }
    size_t value_len = strlen(kTestValue);
    uint8_t *out_buffer = (uint8_t *)malloc(value_len);
    if (!out_buffer) {
        return RDKCONFIG_FAIL;
    }
    memcpy(out_buffer, kTestValue, value_len);
    *sbuff = out_buffer;
    *sbuffsz = value_len;
    return RDKCONFIG_OK;
}

int rdkconfig_getStr(char **strbuff, size_t *strbuffsz, const char *refname) {
    (void)refname; // unused in test override
    if (!strbuff || !strbuffsz) {
        return RDKCONFIG_FAIL;
    }
    char *out_string = strdup(kTestValue);
    if (!out_string) {
        return RDKCONFIG_FAIL;
    }
    *strbuff = out_string;
    *strbuffsz = strlen(kTestValue) + 1;
    return RDKCONFIG_OK;
}
