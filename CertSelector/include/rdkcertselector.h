#ifndef __RDKCERTSELECTOR__
#define __RDKCERTSELECTOR__

/*
 * Copyright 2024 Comcast Cable Communications Management, LLC
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

#ifdef __cplusplus
extern "C" {
#endif


typedef enum {
    certselectorOk=0,
    certselectorGeneralFailure=1, // includes bad state transitions
    certselectorBadPointer=2,
    certselectorFileError=3,
    certselectorFileNotFound=4,
    certselectorBadArgument=5,
} rdkcertselectorStatus_t;

typedef enum {
    NO_RETRY=100,     /*If the cert succeeded or the connection failed not due to the cert */
    TRY_ANOTHER=101,  /*If the cert failed and another cert is available to try */
    RETRY_ERROR=102,  /*internal error */
}rdkcertselectorRetry_t;

#define DEFAULT_CONFIG NULL
#define DEFAULT_HROT NULL

// limit lengths of strings for object (does not include null terminator)
#ifdef GTEST_ENABLE
#undef PATH_MAX
#endif
#define PATH_MAX 128
#define PARAM_MAX 64
#define ENGINE_MAX 32
#define LIST_MAX 6

/* cert selector instance */
typedef struct rdkcertselector_s rdkcertselector_t;
typedef rdkcertselector_t *rdkcertselector_h;

/**
 * Constructs an instance of the rdkcertselector_t
 *     API will read the cert.cfg and hrot.properties to populate the object.
 *     Application must track the handle and invoke destroy it before exiting,
 * In @param appIdentity The application identity; could be empty string(optional).
 * Out @param engine The openssl engine/provider w.r.t Hrot support.
 * @return the global handle to the cert selector object.
 * NULL if the call fails.
**/
rdkcertselector_h rdkcertselector_new(const char *certsel_path, const char *hrotprop_path, const char *cert_group );

/**
 *  RDK Cert Selector destructor
 *  API will clear and free the resouces allocated for the cert selector object; also NULLs the pointer
*/
void rdkcertselector_free(rdkcertselector_h *thiscertsel );

/**
 *  Gets OpenSSL engine to be applied for the device.
 * In @param gHandle is the rdkcertselector_connect_t;
 * Return the char* pointer to engine, NULL on failure.
 *         If the provided `rdkcertselector_t gHandle` is null, the API will invoke the constructor.
**/
char *rdkcertselector_getEngine( rdkcertselector_h thiscertsel );

/**
 *  API for RDK Cert Selection operations.
 *  A cert file & it's passcode will be returned by the API on success.
 *  On each call API will check the following and return appropriate cert & it's credential.
 *     Requested Cert usage type.
 *     Availability of cert
 *     last status of the cert
 *     last cert index used
 *     static or opertational cert.
 *  For each call may wipe the previous passcode, before writing the new passcode.
 *  In @param connectHandle; cert instance object handle for the connection.
 *  In @param usgType; usage type MTLS/STATERED/D2D
 *  Out @param certFile; cert
 *  Out @param credData; cert credential; must wipe after each iteration.
 *  @return 0/certselectorOk for success, non-zero values for the failure.
**/
rdkcertselectorStatus_t rdkcertselector_getCert(rdkcertselector_h thiscertcel, char **cert_uri, char **cert_pass );


/**
 *  Sets status of MTLS connection using the cert.
 *  API will wipe the passcode for the cert used for connection.
 *  In @param connectHandle; cert instance object handle for the connection.
 *  In @param usgType; usage type MTLS/STATERED/D2D
 *  In @param connectStat; connection status using the cert.
 *  @return "rdkcertselectorRetry_t"; 0/NORETRY and 1/RETRY for retrying with next cert.
 *  if the cert used for connection is a staic fallabck cert, then API should return NORETRY.
 *  if the cert is an dynamic operational cert, and connection failed with cert/tls errors.
**/
rdkcertselectorRetry_t rdkcertselector_setCurlStatus(rdkcertselector_h thiscertsel, unsigned int curlStat, const char *logEndpoint );


#ifdef __cplusplus
}
#endif

#endif // __RDKCERTSELECTOR__

