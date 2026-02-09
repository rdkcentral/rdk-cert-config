#include <stdio.h>
#include <stdlib.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main(int argc, char *argv[]) {
    FILE *f;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    PKCS12 *p12 = NULL;
    PKCS7 *p7 = NULL;
    STACK_OF(PKCS7) *safes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    
    const char *cert_file = "cert.pem";
    const char *key_file = "sentinel_key.pem";
    const char *p12_file = "reference.p12";
    const char *password = "changeit";

    if (argc > 1) cert_file = argv[1];
    if (argc > 2) key_file = argv[2];
    if (argc > 3) p12_file = argv[3];
    if (argc > 4) password = argv[4];

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Load certificate */
    f = fopen(cert_file, "r");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", cert_file);
        return 1;
    }
    cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    /* Load sentinel key */
    f = fopen(key_file, "r");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", key_file);
        X509_free(cert);
        return 1;
    }
    pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    if (!cert || !pkey) {
        fprintf(stderr, "ERROR: Failed to load cert or key\n");
        ERR_print_errors_fp(stderr);
        if (cert) X509_free(cert);
        if (pkey) EVP_PKEY_free(pkey);
        return 1;
    }

    /* Create bag stack */
    bags = sk_PKCS12_SAFEBAG_new_null();
    if (!bags) {
        fprintf(stderr, "ERROR: Failed to create bag stack\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Add cert bag */
    if (!PKCS12_add_cert(&bags, cert)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Add key bag — NO key/cert validation */
    /* PKCS12_add_key signature: pbags, pkey, key_usage, iter, key_nid, pass */
    /* Use -1 for key_nid to disable PBE encryption (avoid legacy provider requirement) */
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
        fprintf(stderr, "ERROR: Failed to create safes stack\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if (!sk_PKCS7_push(safes, p7)) {
        fprintf(stderr, "ERROR: Failed to push P7 to safes stack\n");
        goto cleanup;
    }

    /* Build PKCS12 */
    p12 = PKCS12_init(NID_pkcs7_data);
    if (!p12) {
        fprintf(stderr, "ERROR: Failed to initialize PKCS12\n");
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
    i2d_PKCS12_fp(f, p12);
    fclose(f);

    printf("✓ Successfully created reference P12: %s\n", p12_file);
    printf("  Certificate: %s\n", cert_file);
    printf("  Sentinel key: %s (no validation)\n", key_file);

    /* Success - clean up and exit */
    PKCS12_free(p12);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return 0;

cleanup:
    /* Centralized cleanup on error */
    if (p12) PKCS12_free(p12);
    if (safes) sk_PKCS7_pop_free(safes, PKCS7_free);
    if (bags) sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);
    return 1;
}
