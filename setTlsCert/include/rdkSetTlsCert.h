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

#define CS_PATH_MAX 256
#define FILESCHEME "file://"
#define MAX_KEY_LEN 512
rdkcertselectorStatus_t rdkcertselector_getCertForCurl( CURL *curl, rdkcertselector_h certsel );


#ifdef __cplusplus
}
#endif

#endif // __RDKSETTLSCERT__

