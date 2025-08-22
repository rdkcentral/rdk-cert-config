/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
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
*/


#ifdef RDKLOGGER
    #include "rdk_debug.h"
    #define LOG_LIB "LOG.RDK.CERTSELECTOR"
#else
    #define RDK_LOG(a1, a2, args...) fprintf(stderr, args)
    #define RDK_LOG_INFO 0
    #define RDK_LOG_ERROR 0
    #define RDK_LOG_DEBUG 0
    #define LOG_LIB 0
#endif

#define ERROR_LOG(...) RDK_LOG(RDK_LOG_ERROR, LOG_LIB, __VA_ARGS__)
#define DEBUG_LOG(...) RDK_LOG(RDK_LOG_INFO, LOG_LIB, __VA_ARGS__)
#define EXTRA_DEBUG_LOG(...) RDK_LOG(RDK_LOG_DEBUG, LOG_LIB, __VA_ARGS__)

#include "rdkSetTlsCert.h"

/**
 * Constructs a PKCS#11 certificate URI string using the given key ID.
 *     The URI will follow the format:
 *         "pkcs11:id=%02X;type=cert"
 *     This URI identifies a certificate object by its key ID in a PKCS#11 token.
 *
 * In @param keyID The key ID (single byte) used to identify the certificate object.
 * Out @param CertUri The output buffer where the generated URI will be stored.
 *                   Caller must provide a buffer of at least CS_PATH_MAX bytes.
 */
void getCertUri(char *CertUri, uint8_t keyID) {
    // Clear the output buffer
    memset(CertUri, 0, CS_PATH_MAX);
    // Format the URI string with the correct syntax
    snprintf(CertUri, CS_PATH_MAX, "pkcs11:id=%u;type=cert", keyID);
}

/**
 * Constructs a PKCS#11 private key URI string using the given key ID.
 *     The URI will follow the format:
 *         "pkcs11:id=%02X;type=private"
 *     This URI identifies a private key object by its key ID in a PKCS#11 token.
 *
 * In @param keyID The key ID (single byte) used to identify the private key object.
 * Out @param KeyUri The output buffer where the generated URI will be stored.
 *                  Caller must provide a buffer of at least CS_PATH_MAX bytes.
 */
void getKeyUri(char *KeyUri, uint8_t keyID) {
    // Clear the output buffer
    memset(KeyUri, 0, CS_PATH_MAX);
    // Format the private key URI string
    snprintf(KeyUri, CS_PATH_MAX, "pkcs11:id=%u;type=private", keyID);
}

bool open_read_privatekey(const char *pCertFile, const char *passcode, uint8_t *pkey) {
    FILE *fp = NULL;
    PKCS12 *p12 = NULL;
    EVP_PKEY *evp_pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    int ret = false;
    if (!pCertFile || !pkey) {
        ERROR_LOG("Invalid input to open_read_privatekey\n");
        return ret;
    }
    fp = fopen(pCertFile, "rb");
    if (!fp) {
        ERROR_LOG("Failed to open cert file\n");
        return ret;
    }
    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    if (!p12) {
	ERROR_LOG("Failed to load p12 file\n");
        return ret;
    }
    if (!PKCS12_parse(p12, passcode ? passcode : "", &evp_pkey, &cert, &ca)) {
        PKCS12_free(p12);
	ERROR_LOG("Failed to parse p12 file\n");
        return ret;
    }
    uint8_t *tmp = pkey;
    int keylen = i2d_PrivateKey(evp_pkey, &tmp);
    if (keylen <= 0 || keylen > MAX_KEY_LEN) {
	ERROR_LOG("Invalide key length\n");
        ret = ret;
    }
    EVP_PKEY_free(evp_pkey);
    X509_free(cert);
    if (ca) sk_X509_pop_free(ca, X509_free);
    PKCS12_free(p12);
    return true;
}

rdkcertselectorStatus_t rdkcertselector_getCertForCurl( CURL *curl, rdkcertselector_h certsel ) {
    char *pCertFile = NULL;
    char *pPasswd = NULL;
    char *pCertURI = NULL;
    char *pEngine=NULL;
    uint8_t pkey[32];
    //static const uint8_t refkey[31] = {0};
    CURLcode curl_code = CURLE_OK;
    rdkcertselectorStatus_t cs_status = rdkcertselector_getCert( certsel, &pCertURI, &pPasswd);
    if ( cs_status != certselectorOk) {
        // process error
        return cs_status;
    }
    // process schemes
    pCertFile = pCertURI;
    if ( strncmp( pCertFile, FILESCHEME, sizeof(FILESCHEME) - 1 ) == 0 ) {
        pCertFile += (sizeof(FILESCHEME) - 1);
	if(!open_read_privatekey( pCertFile,pPasswd, pkey ) ) return certselectorBadArgument;
	//if ( memcmp( pkey, refkey, sizeof( refkey ) )) {
	  if ( strstr(pCertFile, "staticXpkiCrt.pk12") != NULL) { 
            size_t len = strlen(pCertFile) + 1;
            char CertUri[len];
            char KeyUri[len];
	    uint8_t keyID = 42;
	    ERROR_LOG("%s: Size of pkey = %zu bytes\n", __FUNCTION__, sizeof(pkey));
	    memset( pkey, 0 , sizeof(pkey));
	    //pEngine = rdkcertselector_getEngine(certsel);
            curl_code = curl_easy_setopt(curl, CURLOPT_SSLENGINE, "pkcs11");
	    if ( curl_code != CURLE_OK ) return certselectorBadArgument;
            curl_code = curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "ENG");
            if ( curl_code != CURLE_OK ) return certselectorBadArgument;
            getCertUri( CertUri, keyID );  // modify URI for cert only, "pkcs11:id=%42;type=cert"
            if (CertUri[0] == '\0') return certselectorBadArgument;
	    ERROR_LOG(" %s: CertUri = %s \n",__FUNCTION__,CertUri);
            curl_code = curl_easy_setopt(curl, CURLOPT_SSLCERT, CertUri);
            if ( curl_code != CURLE_OK ) return certselectorBadArgument;
            getKeyUri( KeyUri,keyID );  // modify URI for key only, "pkcs11:id=%42;type=private"
            if (KeyUri[0] == '\0') return certselectorBadArgument;
	    ERROR_LOG(" %s:KeyUri = %s \n",__FUNCTION__,KeyUri);
	    curl_code = curl_easy_setopt(curl, CURLOPT_SSLKEY, KeyUri);
	    if ( curl_code != CURLE_OK ) return certselectorBadArgument;
	} else {
           curl_code = curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "P12");
           if ( curl_code != CURLE_OK ) return certselectorBadArgument;
           curl_code = curl_easy_setopt(curl, CURLOPT_SSLCERT, pCertFile);
           if ( curl_code != CURLE_OK ) return certselectorBadArgument;
           curl_code = curl_easy_setopt(curl, CURLOPT_KEYPASSWD, pPasswd);
           if ( curl_code != CURLE_OK ) return certselectorBadArgument;
	   pEngine= rdkcertselector_getEngine(certsel);
           if(pEngine != NULL){
              curl_code = curl_easy_setopt(curl, CURLOPT_SSLENGINE, pEngine);
           }else{
              curl_code = curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L);
           }
	   if ( curl_code != CURLE_OK ) return certselectorBadArgument;
       }
    // always verify peer
    curl_code = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    if ( curl_code != CURLE_OK ) return certselectorBadArgument;
    }
    return certselectorOk;
}

