/*
 * create_reference_p12.c - Generate reference P12 with sentinel key for PKCS#11
 *
 * Pure C implementation - no shell script required.
 * Creates a P12 file with a real certificate and a sentinel key (all zeros)
 * that triggers PKCS#11 P12 patch to load keys from hardware token.
 *
 * Usage: create_reference_p12 <cert_file> <output_p12> [password]
 *
 * Copyright 2026 RDK Management
 * Licensed under the Apache License, Version 2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

/* Create sentinel EC key with all-zero private value for PKCS#11 */
static EVP_PKEY* create_sentinel_ec_key(void) {
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    BIGNUM *priv_bn = NULL;
    EC_POINT *pub_point = NULL;
    
    /* Create EC key with P-256 curve (prime256v1) */
    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        fprintf(stderr, "ERROR: Failed to create EC key\n");
        return NULL;
    }
    
    /* Generate a temporary valid key pair to get public key point */
    if (!EC_KEY_generate_key(ec_key)) {
        fprintf(stderr, "ERROR: Failed to generate EC key\n");
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    /* Get the public key (we keep this) */
    pub_point = EC_POINT_dup(EC_KEY_get0_public_key(ec_key), EC_KEY_get0_group(ec_key));
    if (!pub_point) {
        fprintf(stderr, "ERROR: Failed to duplicate public key\n");
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    /* Create BIGNUM with value 0 (zero private key) */
    priv_bn = BN_new();
    if (!priv_bn) {
        fprintf(stderr, "ERROR: Failed to create BIGNUM\n");
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        return NULL;
    }
    BN_zero(priv_bn);  /* Set to zero - void in OpenSSL 3.0+ */
    
    /* Set private key to zero (THIS IS THE SENTINEL KEY) */
    if (!EC_KEY_set_private_key(ec_key, priv_bn)) {
        fprintf(stderr, "ERROR: Failed to set private key\n");
        BN_free(priv_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    /* Keep the public key (needed for valid EC key structure) */
    if (!EC_KEY_set_public_key(ec_key, pub_point)) {
        fprintf(stderr, "ERROR: Failed to set public key\n");
        BN_free(priv_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        return NULL;
    }
    
    /* Wrap in EVP_PKEY */
    pkey = EVP_PKEY_new();
    if (!pkey || !EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        fprintf(stderr, "ERROR: Failed to create EVP_PKEY\n");
        BN_free(priv_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    /* Cleanup (EC_KEY ownership transferred to EVP_PKEY) */
    BN_free(priv_bn);
    EC_POINT_free(pub_point);
    
    return pkey;
}

/* Verify sentinel key has all-zero private value */
static int verify_sentinel_key(EVP_PKEY *pkey) {
    const EC_KEY *ec_key = NULL;
    const BIGNUM *priv_bn = NULL;
    
    if (!pkey) return 0;
    
    ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec_key) return 0;
    
    priv_bn = EC_KEY_get0_private_key(ec_key);
    if (!priv_bn) return 0;
    
    /* Check if private key is zero */
    return BN_is_zero(priv_bn);
}

/* Create reference P12 file with certificate and sentinel key */
static int create_reference_p12(const char *cert_file, const char *p12_file, 
                                const char *password) {
    FILE *f = NULL;
    X509 *cert = NULL;
    EVP_PKEY *sentinel_key = NULL;
    PKCS12 *p12 = NULL;
    PKCS7 *p7 = NULL;
    STACK_OF(PKCS7) *safes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    int ret = 0;
    
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("Reference P12 Generator - Pure C Implementation\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    
    printf("Configuration:\n");
    printf("  Certificate: %s\n", cert_file);
    printf("  Output P12:  %s\n", p12_file);
    printf("  Password:    [hidden]\n");
    printf("  PKCS#11 Key ID: 0x2c (fixed)\n\n");
    
    /* Load certificate */
    printf("Step 1: Load certificate\n");
    printf("───────────────────────────────────────────────────────────────\n");
    
    f = fopen(cert_file, "r");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open certificate file: %s\n", cert_file);
        goto cleanup;
    }
    
    cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    f = NULL;
    
    if (!cert) {
        fprintf(stderr, "ERROR: Failed to load certificate\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    printf("✓ Certificate loaded successfully\n\n");
    
    /* Create sentinel key */
    printf("Step 2: Create sentinel EC key (all zeros)\n");
    printf("───────────────────────────────────────────────────────────────\n");
    
    sentinel_key = create_sentinel_ec_key();
    if (!sentinel_key) {
        fprintf(stderr, "ERROR: Failed to create sentinel key\n");
        goto cleanup;
    }
    
    /* Verify it's actually zero */
    if (!verify_sentinel_key(sentinel_key)) {
        fprintf(stderr, "ERROR: Sentinel key verification failed (not all zeros)\n");
        goto cleanup;
    }
    
    printf("✓ Sentinel key created (32 bytes of zeros)\n");
    printf("  OpenSSL P12 patch will detect this and use PKCS#11 slot 0x2c\n\n");
    
    /* Create PKCS12 structure */
    printf("Step 3: Create PKCS12 structure\n");
    printf("───────────────────────────────────────────────────────────────\n");
    
    /* Create bag stack */
    bags = sk_PKCS12_SAFEBAG_new_null();
    if (!bags) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    /* Add certificate bag */
    if (!PKCS12_add_cert(&bags, cert)) {
        fprintf(stderr, "ERROR: Failed to add certificate\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    /* Add sentinel key bag (bypasses OpenSSL validation) */
    if (!PKCS12_add_key(&bags, sentinel_key, -1, 0, -1, NULL)) {
        fprintf(stderr, "ERROR: Failed to add sentinel key\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    /* Pack bags into PKCS7 */
    p7 = PKCS12_pack_p7data(bags);
    if (!p7) {
        fprintf(stderr, "ERROR: Failed to pack PKCS7\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    /* Create safes stack */
    safes = sk_PKCS7_new_null();
    if (!safes || !sk_PKCS7_push(safes, p7)) {
        fprintf(stderr, "ERROR: Failed to create safes\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    p7 = NULL; /* ownership transferred */
    
    /* Build PKCS12 */
    p12 = PKCS12_init(NID_pkcs7_data);
    if (!p12 || !PKCS12_pack_authsafes(p12, safes)) {
        fprintf(stderr, "ERROR: Failed to build PKCS12\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    /* Set MAC */
    if (!PKCS12_set_mac(p12, password, -1, NULL, 0, 2048, NULL)) {
        fprintf(stderr, "ERROR: Failed to set MAC\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    printf("✓ PKCS12 structure created\n\n");
    
    /* Write to file */
    printf("Step 4: Write P12 file\n");
    printf("───────────────────────────────────────────────────────────────\n");
    
    f = fopen(p12_file, "wb");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open output file: %s\n", p12_file);
        goto cleanup;
    }
    
    if (!i2d_PKCS12_fp(f, p12)) {
        fprintf(stderr, "ERROR: Failed to write PKCS12\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    fclose(f);
    f = NULL;
    
    printf("✓ P12 file written successfully\n\n");
    
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("✓ Reference P12 generation complete\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
    
    printf("Output file: %s\n", p12_file);
    printf("Password: (not displayed; provided via argument or default)\n\n");
    
    printf("This P12 file contains:\n");
    printf("  • Real certificate from %s\n", cert_file);
    printf("  • Sentinel key (32 bytes of zeros) → redirects to PKCS#11 slot 0x2c\n\n");
    
    printf("When used with the PKCS#11 P12 patch, OpenSSL will:\n");
    printf("  1. Detect the sentinel key pattern (all zeros)\n");
    printf("  2. Load the real private key from PKCS#11 hardware token (slot 0x2c)\n");
    printf("  3. Complete mTLS handshake using hardware-backed key\n\n");
    
    ret = 1; /* success */
    
cleanup:
    if (f) fclose(f);
    PKCS12_free(p12);
    PKCS7_free(p7);
    sk_PKCS7_pop_free(safes, PKCS7_free);
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    X509_free(cert);
    EVP_PKEY_free(sentinel_key);
    
    return ret;
}

int main(int argc, char *argv[]) {
    const char *cert_file = "client.pem";
    const char *p12_file = "reference.p12";
    const char *password = "changeit";
    
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <cert_file> <output_p12> [password]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Arguments:\n");
        fprintf(stderr, "  cert_file   - Path to certificate PEM file\n");
        fprintf(stderr, "  output_p12  - Path to output P12 file\n");
        fprintf(stderr, "  password    - P12 password (default: changeit)\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Note: The sentinel key always uses PKCS#11 slot 0x2c (hardcoded)\n");
        return 1;
    }
    
    cert_file = argv[1];
    p12_file = argv[2];
    if (argc > 3) password = argv[3];
    
    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    /* Create reference P12 */
    int success = create_reference_p12(cert_file, p12_file, password);
    
    /* Cleanup OpenSSL */
    EVP_cleanup();
    ERR_free_strings();
    
    return success ? 0 : 1;
}
