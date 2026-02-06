/*
 * make_ref_p12.c - Create reference P12 file with sentinel key
 * 
 * This tool creates a PKCS#12 file with:
 * - A valid certificate (from input PEM file)
 * - A sentinel EC private key (minimal valid value = 1, not zero)
 * 
 * The sentinel key triggers the PKCS#11 migration patch behavior
 * in OpenSSL, causing it to fetch the real key from PKCS#11 slot 0x2c.
 * 
 * CRITICAL: Uses low-level PKCS12 ASN.1 API to bypass X509_check_private_key validation
 * 
 * Build: gcc -o make_ref_p12 make_ref_p12.c -lssl -lcrypto
 * Usage: ./make_ref_p12 <cert.pem> <output.p12> <password>
 */

#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/*
 * Create EC sentinel key with private key = 1
 * (minimal valid value to satisfy OpenSSL internal checks)
 */
static EVP_PKEY *create_sentinel_ec_key(void)
{
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec = NULL;
    BIGNUM *priv = NULL;
    const EC_GROUP *group = NULL;
    EC_POINT *pub = NULL;

    /* Create EC key for P-256 curve */
    ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) {
        fprintf(stderr, "Failed to create EC key\n");
        return NULL;
    }

    group = EC_KEY_get0_group(ec);

    /* Set private key = 1 (minimal valid, not zero to satisfy OpenSSL) */
    priv = BN_new();
    if (!priv) goto err;
    
    BN_one(priv);

    if (!EC_KEY_set_private_key(ec, priv)) {
        fprintf(stderr, "Failed to set private key\n");
        goto err;
    }

    /* Compute public key from private key */
    pub = EC_POINT_new(group);
    if (!pub) goto err;
    
    if (!EC_POINT_mul(group, pub, priv, NULL, NULL, NULL)) {
        fprintf(stderr, "Failed to compute public key\n");
        goto err;
    }
    
    if (!EC_KEY_set_public_key(ec, pub)) {
        fprintf(stderr, "Failed to set public key\n");
        goto err;
    }

    /* Wrap in EVP_PKEY */
    pkey = EVP_PKEY_new();
    if (!pkey) goto err;
    
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec)) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto err;
    }

    BN_free(priv);
    EC_POINT_free(pub);
    return pkey;

err:
    if (priv) BN_free(priv);
    if (pub) EC_POINT_free(pub);
    if (ec) EC_KEY_free(ec);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <cert.pem> <output.p12> <password>\n", argv[0]);
        return 1;
    }

    const char *certfile = argv[1];
    const char *outfile  = argv[2];
    const char *pass     = argv[3];

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Load certificate */
    printf("Loading certificate from: %s\n", certfile);
    FILE *f = fopen(certfile, "r");
    if (!f) {
        fprintf(stderr, "Failed to open certificate file: %s\n", certfile);
        return 1;
    }
    
    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    if (!cert) {
        fprintf(stderr, "Failed to read certificate\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Create sentinel EC key */
    printf("Creating EC sentinel key (P-256 with private=1)...\n");
    EVP_PKEY *pkey = create_sentinel_ec_key();
    if (!pkey) {
        fprintf(stderr, "Failed to create sentinel key\n");
        X509_free(cert);
        return 1;
    }

    /* Build PKCS#12 using low-level API (bypasses validation) */
    printf("Building PKCS#12 structure (ASN.1 low-level API)...\n");
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;

    /* Add cert bag */
    if (!PKCS12_add_cert(&bags, cert)) {
        fprintf(stderr, "PKCS12_add_cert failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }

    /* Add key bag (NO X509_check_private_key validation happens here) */
    if (!PKCS12_add_key(&bags, pkey, 0, 0, 0, pass)) {
        fprintf(stderr, "PKCS12_add_key failed\n");
        ERR_print_errors_fp(stderr);
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }

    /* Pack into PKCS7 authsafe */
    PKCS7 *p7 = PKCS12_pack_p7data(bags);
    if (!p7) {
        fprintf(stderr, "PKCS12_pack_p7data failed\n");
        ERR_print_errors_fp(stderr);
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    
    STACK_OF(PKCS7) *safes = sk_PKCS7_new_null();
    if (!safes) {
        fprintf(stderr, "Failed to create authsafes\n");
        PKCS7_free(p7);
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    sk_PKCS7_push(safes, p7);

    /* Create PKCS12 structure */
    PKCS12 *p12 = PKCS12_init(NID_pkcs7_data);
    if (!p12) {
        fprintf(stderr, "PKCS12_init failed\n");
        ERR_print_errors_fp(stderr);
        sk_PKCS7_pop_free(safes, PKCS7_free);
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    
    if (!PKCS12_pack_authsafes(p12, safes)) {
        fprintf(stderr, "PKCS12_pack_authsafes failed\n");
        ERR_print_errors_fp(stderr);
        PKCS12_free(p12);
        sk_PKCS7_pop_free(safes, PKCS7_free);
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }

    /* Write P12 to file */
    printf("Writing P12 to: %s\n", outfile);
    FILE *out = fopen(outfile, "wb");
    if (!out) {
        fprintf(stderr, "Failed to open output file: %s\n", outfile);
        PKCS12_free(p12);
        sk_PKCS7_pop_free(safes, PKCS7_free);
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    
    if (!i2d_PKCS12_fp(out, p12)) {
        fprintf(stderr, "Failed to write P12 file\n");
        ERR_print_errors_fp(stderr);
        fclose(out);
        PKCS12_free(p12);
        sk_PKCS7_pop_free(safes, PKCS7_free);
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    fclose(out);

    printf("✓ Reference P12 created successfully\n");
    printf("  Certificate: %s\n", certfile);
    printf("  Sentinel key: EC P-256 with private=1 (triggers PKCS#11 patch)\n");
    printf("  Output: %s\n", outfile);

    /* Cleanup */
    PKCS12_free(p12);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    EVP_PKEY_free(pkey);
    X509_free(cert);

    return 0;
}
