#ifndef __RDKSETTLSCERT__
#define __RDKSETTLSCERT__
#include "rdkcertselector.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#ifdef __cplusplus
extern "C" {
#endif

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
#define CS_PATH_MAX 256
#define FILESCHEME "file://"
#define MAX_KEY_LEN 512
rdkcertselectorRetry_t rdkcertselector_setCurlStatus(rdkcertselector_h thiscertsel, unsigned int curlStat, const char *logEndpoint );


#ifdef __cplusplus
}
#endif

#endif // __RDKSETTLSCERT__

