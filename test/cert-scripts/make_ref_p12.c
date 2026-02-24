/*
 * make_ref_p12.c - Helper to create reference P12 from existing cert/key
 *
 * Copyright 2026 RDK Management
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

#include <stdio.h>
#include <stdlib.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main(int argc, char *argv[]) {
    FILE *f = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    PKCS12 *p12 = NULL;
    PKCS7 *p7 = NULL;
    STACK_OF(PKCS7) *safes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;

    int ret = 1;

    const char *cert_file = "cert.pem";
    const char *key_file  = "sentinel_key.pem";
    const char *p12_file  = "reference.p12";
    const char *password  = "changeit";

    if (argc > 1) cert_file = argv[1];
    if (argc > 2) key_file  = argv[2];
    if (argc > 3) p12_file  = argv[3];
    if (argc > 4) password = argv[4];

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Load certificate */
    f = fopen(cert_file, "r");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", cert_file);
        goto cleanup;
    }
    cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    f = NULL;

    /* Load sentinel key */
    f = fopen(key_file, "r");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", key_file);
        goto cleanup;
    }
    pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    f = NULL;

    if (!cert || !pkey) {
        fprintf(stderr, "ERROR: Failed to load cert or key\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Create bag stack */
    bags = sk_PKCS12_SAFEBAG_new_null();
    if (!bags) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Add cert bag */
    if (!PKCS12_add_cert(&bags, cert)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Add key bag (no validation) */
    if (!PKCS12_add_key(&bags, pkey, -1, 0, -1, NULL)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Pack bags into PKCS7 */
    p7 = PKCS12_pack_p7data(bags);
    if (!p7) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Create safes stack */
    safes = sk_PKCS7_new_null();
    if (!safes) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (!sk_PKCS7_push(safes, p7)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    p7 = NULL; /* ownership transferred */

    /* Build PKCS12 */
    p12 = PKCS12_init(NID_pkcs7_data);
    if (!p12) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (!PKCS12_pack_authsafes(p12, safes)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Set MAC */
    if (!PKCS12_set_mac(p12, password, -1, NULL, 0, 2048, NULL)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Write P12 */
    f = fopen(p12_file, "wb");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", p12_file);
        goto cleanup;
    }

    if (!i2d_PKCS12_fp(f, p12)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    fclose(f);
    f = NULL;

    printf("✓ Successfully created reference P12: %s\n", p12_file);
    printf("  Certificate: %s\n", cert_file);

    ret = 0; /* success */

cleanup:
    if (f)
        fclose(f);
    PKCS12_free(p12);
    PKCS7_free(p7);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    return ret;
}
