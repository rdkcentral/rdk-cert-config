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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rdkconfig.h"


// rdkconfig_get - get credential by reference name, allocate space, fill buffer
// return new buffer and size of data (actual memory buffer may be larger)
// return value: RDKCONFIG_OK or RDKCONFIG_FAIL
int rdkconfig_get( uint8_t **sbuff, size_t *sbuffsz, const char *refname ) {
	/* This is stub function, Needs implemetation */
        printf("rdkconfig_get not implemented yet\n");
	return RDKCONFIG_FAIL;
}

// rdkconfig_getStr - get credential by reference name, allocate space, fill buffer, add null terminator
// return new buffer and size of data including null terminator (actual memory buffer may be larger)
// (after retrieved credential will come a '\0', null terminator)
// return value: RDKCONFIG_OK or RDKCONFIG_FAIL
int rdkconfig_getStr( char **sbuff, size_t *sbuffsz, const char *refname ) {
	/* This is stub function, Needs implemetation */
	printf("rdkconfig_get not implemented yet\n");
	return RDKCONFIG_FAIL;
}

// rdkconfig_set - store credential by reference name
// return value: RDKCONFIG_OK or RDKCONFIG_FAIL
// (for string data, the null terminator does not need to be included in sbuffsz as long as
//   it is retrieved using rdkconfig_getStr)
int rdkconfig_set( const char *refname, uint8_t *sbuff, size_t sbuffsz ) {
	/* This is stub function, Needs implemetation */
        printf("rdkconfig_set not implemented yet\n");
	return RDKCONFIG_FAIL;
}

//memwipe - fix this to always wipe without getting optimized out
static void memwipe( volatile void *mem, size_t sz ) {
  memset( (void *)mem, 0, sz );
}

// rdkconfig_free - wipe and free buffer
int rdkconfig_free( uint8_t **sbuff, size_t sbuffsz ) {
	if ( sbuff == NULL ) 
		return RDKCONFIG_FAIL;
        if ( *sbuff == NULL ) {
                return RDKCONFIG_OK; // ok if pointer is null
        }
        memwipe(*sbuff, sbuffsz);
        free( *sbuff );
        *sbuff = NULL;
        return RDKCONFIG_OK;
}	
// rdkconfig_freeStr - wipe and free string buffer
int rdkconfig_freeStr( char **sbuff, size_t sbuffsz ) {
	return rdkconfig_free( (uint8_t **)sbuff, sbuffsz );
}

#ifdef UNIT_TESTS
static int utmain( int argc, char *argv[] );

int main( int argc, char *argv[] ) {
  return utmain( argc, argv );
}

#include "unit_test.h"

static int utmain( int argc, char *argv[] ) {

  fprintf( stderr, "\nUNIT TEST - rdkconfig\n" );
  const char *refname2="utstcreds";
  uint8_t *sbuffraw=NULL;
  char *strbuffraw=NULL;
  size_t sbuffrawsz=20;
  uint8_t *sbuffdec=NULL;
  char *strbuffdec=NULL;
  size_t sbuffdecsz=0;
  UT_INTCMP( rdkconfig_set( refname2, sbuffraw, sbuffrawsz ), RDKCONFIG_FAIL ); 
  UT_INTCMP( rdkconfig_get( &sbuffdec, &sbuffdecsz, refname2 ), RDKCONFIG_FAIL);
  UT_INTCMP( rdkconfig_getStr( &strbuffdec, &sbuffdecsz, refname2 ), RDKCONFIG_FAIL);
  UT_INTCMP( rdkconfig_free( &sbuffraw, sbuffrawsz ), RDKCONFIG_OK );
  UT_INTCMP( rdkconfig_freeStr( &strbuffraw, sbuffrawsz ), RDKCONFIG_OK );
  UT_INTCMP( rdkconfig_free( NULL, 0 ), RDKCONFIG_FAIL );
  fprintf( stderr, "UNIT TEST - rdkconfig - SUCCESS\n" );
  return 0;
}

#endif // UNIT_TEST
