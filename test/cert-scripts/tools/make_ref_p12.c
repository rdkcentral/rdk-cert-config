/*
 * make_ref_p12.c - Create reference P12 file with sentinel key
 * 
 * This tool creates a PKCS#12 file with:
 * - A valid certificate (from input PEM file)
 * - A sentinel private key (all zeros - 32 bytes)
 * 
 * The sentinel key triggers the PKCS#11 migration patch behavior
 * in OpenSSL, causing it to fetch the real key from PKCS#11 slot 0x2c.
 * 
 * Build: gcc -o make_ref_p12 make_ref_p12.c -lssl -lcrypto
 * Usage: ./make_ref_p12 <cert.pem> <output.p12> <password>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#define SENTINEL_KEY_SIZE 32

/*
 * Create a dummy RSA key with all-zero private exponent (sentinel)
 */
EVP_PKEY* create_sentinel_key() {
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    unsigned char zero_bytes[SENTINEL_KEY_SIZE];
    
    memset(zero_bytes, 0, SENTINEL_KEY_SIZE);
    
    // Create RSA structure
    rsa = RSA_new();
    if (!rsa) {
        fprintf(stderr, "Failed to create RSA key\n");
        return NULL;
    }
    
    // Set modulus (n) - use a dummy value
    n = BN_new();
    BN_set_word(n, 65537);
    
    // Set public exponent (e)
    e = BN_new();
    BN_set_word(e, 65537);
    
    // Set private exponent (d) - ALL ZEROS (sentinel)
    d = BN_bin2bn(zero_bytes, SENTINEL_KEY_SIZE, NULL);
    
    // Assign to RSA key
    RSA_set0_key(rsa, n, e, d);
    
    // Wrap in EVP_PKEY
    pkey = EVP_PKEY_new();
    if (!pkey) {
        RSA_free(rsa);
        fprintf(stderr, "Failed to create EVP_PKEY\n");
        return NULL;
    }
    
    EVP_PKEY_assign_RSA(pkey, rsa);
    
    return pkey;
}

/*
 * Load certificate from PEM file
 */
X509* load_certificate(const char *cert_file) {
    FILE *fp = NULL;
    X509 *cert = NULL;
    
    fp = fopen(cert_file, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open certificate file: %s\n", cert_file);
        return NULL;
    }
    
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!cert) {
        fprintf(stderr, "Failed to read certificate from file\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    return cert;
}

/*
 * Create P12 file with certificate and sentinel key
 */
int create_reference_p12(const char *cert_file, const char *output_file, const char *password) {
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    PKCS12 *p12 = NULL;
    FILE *fp = NULL;
    int ret = 0;
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Load certificate
    printf("Loading certificate from: %s\n", cert_file);
    cert = load_certificate(cert_file);
    if (!cert) {
        goto cleanup;
    }
    
    // Create sentinel key (all zeros)
    printf("Creating sentinel key (32 bytes of zeros)...\n");
    pkey = create_sentinel_key();
    if (!pkey) {
        goto cleanup;
    }
    
    // Create PKCS#12 structure
    printf("Creating PKCS#12 file...\n");
    p12 = PKCS12_create(
        password,           // Password
        "RDK_REFERENCE",    // Friendly name
        pkey,               // Private key (sentinel)
        cert,               // Certificate
        NULL,               // CA certificates
        0,                  // Key PBE NID
        0,                  // Cert PBE NID
        0,                  // Iterations
        0,                  // MAC iterations
        0                   // Key type
    );
    
    if (!p12) {
        fprintf(stderr, "Failed to create PKCS#12\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    // Write P12 to file
    printf("Writing P12 to: %s\n", output_file);
    fp = fopen(output_file, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open output file: %s\n", output_file);
        goto cleanup;
    }
    
    if (i2d_PKCS12_fp(fp, p12) != 1) {
        fprintf(stderr, "Failed to write PKCS#12 to file\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    printf("✓ Reference P12 created successfully\n");
    ret = 1;
    
cleanup:
    if (fp) fclose(fp);
    if (p12) PKCS12_free(p12);
    if (pkey) EVP_PKEY_free(pkey);
    if (cert) X509_free(cert);
    
    return ret;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <cert.pem> <output.p12> <password>\n", argv[0]);
        return 1;
    }
    
    const char *cert_file = argv[1];
    const char *output_file = argv[2];
    const char *password = argv[3];
    
    if (!create_reference_p12(cert_file, output_file, password)) {
        return 1;
    }
    
    return 0;
}
