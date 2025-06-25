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

#ifndef __UNIT_TEST_H__
#define __UNIT_TEST_H__

#include <assert.h>
#include <stdio.h> // for remove
#include <unistd.h> // for access

#define UT_INTCMP( a, x ) { \
  const long act=(long)(a), exp=(long)(x); \
  if ( act != exp ) { fprintf(stderr,"act:%ld != exp:%ld\n",(long)act,(long)exp); } \
  assert( act == exp ); }

#define UT_INTDIFF( a, x ) { \
  const long act=(long)(a), exp=(long)(x); \
  if ( act == exp ) { fprintf(stderr,"act:%ld == exp:%ld\n",(long)act,(long)exp); } \
  assert( act != exp ); }

#define UT_INT0( a ) UT_INTCMP( a, 0 )

#define UT_EXISTS( f ) UT_INT0( access( f, F_OK ) )
#define UT_DOESNTEXIST( f ) UT_INTDIFF( access( f, F_OK ), 0 )
#endif // __UNIT_TEST_H__


