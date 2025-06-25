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

#include "rdkcertselector.h"
#include "rdkcertlocator.h"
#include "unit_test.h"

#define CURLSUCCESS 0
#define CURLCERTERR 91 // Invalid SSL certificate status

int main( int argc, char *argv[] ) {
  UT_BEGIN( __FILE__ );
  rdkcertselector_h cs1 = rdkcertselector_new( "./ut/tst1certsel.cfg", "./ut/tst1hrot.properties", "TSTGRP1" );
  UT_NOTNULL( cs1 );
  rdkcertlocator_h cl1 = rdkcertlocator_new( "./ut/tst1certsel.cfg", "./ut/tst1hrot.properties" );
  UT_NOTNULL( cl1 );

  char *cert = NULL;
  char *pass = NULL;
  UT_INTCMP( rdkcertselector_getCert( cs1, &cert, &pass ), certselectorOk );
  UT_STRCMP( cert, "file://./ut/tst1first.tmp", PARAM_MAX );
  UT_STRCMP( pass, "pc1pass", PARAM_MAX );
  UT_INTCMP( rdkcertselector_setCurlStatus( cs1, CURLCERTERR, "https://mytest1.com" ), TRY_ANOTHER );
  UT_STRCMP( pass, "", PARAM_MAX );

  UT_INTCMP( rdkcertselector_getCert( cs1, &cert, &pass ), certselectorOk );
  UT_STRCMP( cert, "file://./ut/tst1second.tmp", PARAM_MAX );
  UT_STRCMP( pass, "pc2pass", PARAM_MAX );
  UT_INTCMP( rdkcertselector_setCurlStatus( cs1, CURLCERTERR, "https://mytest2.com" ), TRY_ANOTHER );
  UT_STRCMP( pass, "", PARAM_MAX );

  UT_INTCMP( rdkcertselector_getCert( cs1, &cert, &pass ), certselectorOk );
  UT_STRCMP( cert, "file://./ut/tst1third.tmp", PARAM_MAX );
  UT_STRCMP( pass, "pc3pass", PARAM_MAX );
  UT_INTCMP( rdkcertselector_setCurlStatus( cs1, CURLSUCCESS, "https://mytest3.com" ), NO_RETRY );
  UT_STRCMP( pass, "", PARAM_MAX );

  cert = pass = NULL;
  UT_INTCMP( rdkcertlocator_locateCert( cl1, "FRST", &cert, &pass ), certlocatorOk );
  UT_STRCMP( cert, "file://./ut/tst1first.tmp", PARAM_MAX );
  UT_STRCMP( pass, "pc1pass", PARAM_MAX );
  UT_INTCMP( rdkcertlocator_locateCert( cl1, "SCND", &cert, &pass ), certlocatorOk );
  UT_STRCMP( cert, "file://./ut/tst1second.tmp", PARAM_MAX );
  UT_STRCMP( pass, "pc2pass", PARAM_MAX );
  UT_INTCMP( rdkcertlocator_locateCert( cl1, "THRD", &cert, &pass ), certlocatorOk );
  UT_STRCMP( cert, "file://./ut/tst1third.tmp", PARAM_MAX );
  UT_STRCMP( pass, "pc3pass", PARAM_MAX );

  rdkcertselector_free( &cs1 );
  rdkcertlocator_free( &cl1 );

  UT_END( __FILE__ );
  return 0;
}

#include <string.h>
#include "rdkconfig.h"

// MOCKS
#define GETSZ 50
#define UTCRED1 "pc1"
#define UTCRED2 "pc2"
#define UTCRED3 "pc3"
#define UTCREDALPHA "pcalpha"
#define UTPASS1 UTCRED1 "pass"
#define UTPASS2 UTCRED2 "pass"
#define UTPASS3 UTCRED3 "pass"
#define UTPASSALPHA UTCREDALPHA "pass"

// rdkconfig_getStr - get string credential, allocate space, fill buffer
int rdkconfig_getStr( char **sbuff, size_t *sbuffsz, const char *refname ) { // MOCK
  int retval = RDKCONFIG_OK;
  char *membuff = malloc( GETSZ );
  if ( membuff == NULL ) {
    return RDKCONFIG_FAIL;
  }
  memset( membuff, '.', GETSZ );
  if ( strcmp( refname, UTCRED1 ) == 0 ) {
    strcpy( membuff, UTPASS1 );
  } else if ( strcmp( refname, UTCRED2 ) == 0 ) {
    strcpy( membuff, UTPASS2 );
    // passcode sometimes ends with \n and should be removed
    strcat( membuff, "\n" );
  } else if ( strcmp( refname, UTCRED3 ) == 0 ) {
    strcpy( membuff, UTPASS3 );
  } else if ( strcmp( refname, UTCREDALPHA ) == 0 ) {
    strcpy( membuff, UTPASSALPHA );
  } else {
    retval =  RDKCONFIG_FAIL;
  }
  if ( retval == RDKCONFIG_OK ) {
    *sbuff = membuff;
    *sbuffsz = strlen( membuff )+1; // add null terminator to buffer size
  } else {
    free( membuff );
  }
  return retval;
}

int rdkconfig_freeStr( char **sbuff, size_t sbuffsz ) { // MOCK
  free( *sbuff );
  *sbuff = NULL;
  return RDKCONFIG_OK;
}

