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

#ifndef __RDKCONFIG__
#define __RDKCONFIG__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RDKCONFIG_OK 0
#define RDKCONFIG_FAIL 1 // general failure

// rdkconfig_get - get credential by reference name, allocate space, fill buffer
// return new buffer and size of data (actual memory buffer may be larger)
// return value: RDKCONFIG_OK or RDKCONFIG_FAIL
int rdkconfig_get( uint8_t **sbuff, size_t *sbuffsz, const char *refname );

// rdkconfig_getStr - get credential by reference name, allocate space, fill buffer, add null terminator
// return new buffer and size of data including null terminator (actual memory buffer may be larger)
// (after retrieved credential will come a '\0', null terminator)
// return value: RDKCONFIG_OK or RDKCONFIG_FAIL
int rdkconfig_getStr( char **strbuff, size_t *strbuffsz, const char *refname );

// rdkconfig_set - store credential by reference name
// return value: RDKCONFIG_OK or RDKCONFIG_FAIL
// (for string data, the null terminator does not need to be included in sbuffsz as long as
//   it is retrieved using rdkconfig_getStr)
int rdkconfig_set( const char *refname, uint8_t *sbuff, size_t sbuffsz );

// rdkconfig_free - wipe and free buffer
int rdkconfig_free( uint8_t **sbuff, size_t sbuffsz );

// rdkconfig_freeStr - wipe and free string buffer
int rdkconfig_freeStr( char **strbuff, size_t strbuffsz );

#ifdef __cplusplus
}
#endif
#endif
