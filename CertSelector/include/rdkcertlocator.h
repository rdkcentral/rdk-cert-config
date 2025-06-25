#ifndef __RDKCERTLOCATOR__
#define __RDKCERTLOCATOR__

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
    certlocatorOk=0,
    certlocatorGeneralFailure=1,
    certlocatorBadPointer=2,
    certlocatorFileError=3,
    certlocatorFileNotFound=4,
    certlocatorBadArgument=5,
} rdkcertlocatorStatus_t;

#define DEFAULT_CONFIG NULL
#define DEFAULT_HROT NULL

// limit lengths of strings for object (does not include null terminator)
#ifdef GTEST_ENABLE
#undef PATH_MAX
#endif
#define PATH_MAX 128
#define PARAM_MAX 64
#define ENGINE_MAX 32

/* cert locator instance */
typedef struct rdkcertlocator_s rdkcertlocator_t;
typedef rdkcertlocator_t *rdkcertlocator_h;

/**
 * Constructs an instance of the rdkcertlocator_t
 *     API will read the cert.cfg and hrot.properties to populate the object.
 *     Application must track the handle and invoke destroy it before exiting,
 * In @param appIdentity The application identity; could be empty string(optional).
 * Out @param engine The openssl engine/provider w.r.t Hrot support.
 * @return the global handle to the cert locator object.
 * NULL if the call fails.
**/
rdkcertlocator_h rdkcertlocator_new(const char *certsel_path, const char *hrotprop_path );

/**
 *  RDK Cert Locator destructor
 *  API will clear and free the resouces allocated for the cert locator object; also NULLs the pointer
*/
void rdkcertlocator_free(rdkcertlocator_h *thiscertloc );

/**
 *  Gets OpenSSL engine to be applied for the device.
 * In @param gHandle is the rdkcertlocator_t;
 * Return the char* pointer to engine, NULL on failure.
 *         If the provided `rdkcertlocator_t gHandle` is null, the API will invoke the constructor.
**/
char *rdkcertlocator_getEngine( rdkcertlocator_h thiscertloc );

/**
 *  API for RDK Cert Locator operations.
 *  A cert file & it's passcode will be returned by the API on success.
 *  On each call API will check the following and return appropriate cert & it's credential.
 *  For each call may wipe the previous passcode, before writing the new passcode.
 *  In @param connectHandle; cert instance object handle for the connection.
 *  In @param usgType; usage type MTLS/STATERED/D2D
 *  Out @param certFile; cert
 *  Out @param credData; cert credential; must wipe after each iteration.
 *  @return 0/certselectorOk for success, non-zero values for the failure.
**/
rdkcertlocatorStatus_t rdkcertlocator_locateCert(rdkcertlocator_h thiscertloc, const char *cert_ref, char **cert_uri, char **cert_pass );


#ifdef __cplusplus
}
#endif

#endif // __RDKCERTLOCATOR__

