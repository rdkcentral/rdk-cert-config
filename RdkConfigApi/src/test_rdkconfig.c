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
