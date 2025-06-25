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

#include "mock.h"
#include <stdio.h>
static inline FILE *v_secure_popen( char *type, char *fmt, char *var ) {
  char cmd[500]; sprintf( cmd, fmt, var ); return popen( cmd, type ); }

static inline int v_secure_pclose( FILE *infp ) { return pclose( infp ); }
