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

#define RDKCONFIG_OK 0
#define RDKCONFIG_FAIL 1

int rdkconfig_get( uint8_t **sbuff, size_t *sbuffsz, const char *refname );

int rdkconfig_set( const char *refname, uint8_t *sbuff, size_t sbuffsz );

int rdkconfig_free( uint8_t **sbuff, size_t sbuffsz );

int rdkconfig_freeStr( char **sbuff, size_t sbuffsz );

int rdkconfig_getStr( char **sbuff, size_t *sbuffsz, const char *refname );
#define memset_s( b,z1,v,z2 ) memset( b,v,z2)

