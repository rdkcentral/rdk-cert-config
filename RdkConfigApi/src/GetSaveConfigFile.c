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
//#include <safe_mem_lib.h>
#include <string.h>
#include <stdint.h>
#include <libgen.h> // for basename
#include "rdkconfig.h"
#define CMD_GCF "GetConfigFile"
#define CMD_SCF "SaveConfigFile"
#define MAX_CREDPATH 64
#define MIN_CREDNAME 18 // 16 bytes + 1 prefix letter + 1 null term
#define CN_SWITCH "--cn"
#define MAX_CREDNAME 64
// getcredname - from RdkConfig.  Not exposed in header
char *getcredname( char *credname, unsigned int credname_sz, const char *refname );
static int GetConfigFile( const char *arg1, const char *arg2 );
static int SaveConfigFile( const char *refname );
// GetConfigFile/SaveConfigFile - cli for rdkconfig api
static int gcfmain( int argc, char *argv[] ) {
  const char *thiscmd = basename( argv[0]);
  if ( argc < 2 ) {
    fprintf( stderr, "%s: error, too few arguments (%d)\n", thiscmd, argc );
    return 1; // error
  }
  const char *cmd = CMD_GCF;
  if ( strcmp( thiscmd, cmd ) == 0 ) {
    return GetConfigFile( argv[1], argc>2?argv[2]:NULL) ;
  }
  cmd = CMD_SCF;
  if ( strcmp( thiscmd, cmd ) == 0 ) {
    return SaveConfigFile( argv[1] );
  }
  return 1; // general error
}
//
// GET CONFIG FILE
//
// GetConfigFile <refname>
// GetConfigFile <refname> stdout
// GetConfigFile --cn <credname>
static int GetConfigFile( const char *arg1, const char *arg2 ) {
  if ( arg1 == NULL ) return 1;
  char credname[MAX_CREDNAME+1];
  const char *cmd = CMD_GCF;
  const char *refname = NULL;
  int exitcd = 1; // default to error
  // check for credname switch
  if ( strcmp( arg1, CN_SWITCH ) == 0 ) {
    if ( arg2 == NULL ) {
      fprintf( stderr, "%s %s: error, too few arguments\n", cmd, CN_SWITCH );
      return 1; // error
    }
    refname = arg2;
    // lookup credname and display it if found
    if ( getcredname( credname, sizeof(credname), refname ) != NULL ) {
      fprintf( stderr, "%s->%s\n", refname, credname );
    } else {
      fprintf( stderr, "%s->?\n", refname );
    }
    exitcd = 0; // success
  } else {
    // get the credential
    uint8_t *membuff1 = NULL;
    size_t memsz = 0;
    // here first argument is refname, get the data
    refname = arg1;
    int retval = rdkconfig_get( &membuff1, &memsz, refname );
    if ( retval != RDKCONFIG_OK ) {
      fprintf( stderr, "%s: error, unable to get\n", cmd );
      return exitcd;
    }
    // check if output should go to stdout
    if ( arg2 != NULL && strcmp( arg2, "stdout" ) == 0 ) {
      refname = "/dev/stdout";
    }
    // write data
    FILE *wrfp = fopen( refname, "wb" );
    if ( wrfp != NULL ) {
      size_t wrsz = fwrite( membuff1, 1, memsz, wrfp );
      fclose( wrfp );
      if ( wrsz != memsz ) {
        fprintf( stderr, "%s: error, unable to write (%zu!=%zu)\n", cmd, wrsz, memsz );
      } else {
        exitcd = 0; // sucess
      }
    } else {
      fprintf( stderr, "%s: error, unable to open\n", cmd );
    }
    // free up the memory
    if ( rdkconfig_free( &membuff1, memsz ) != RDKCONFIG_OK ) {
      fprintf( stderr, "%s: mem error\n", cmd );
    }
  }
  return exitcd;
}
#define CREDSZ_LG 33000
//
// SAVE CONFIG FILE
//
// SaveConfigFile <refname>
static int SaveConfigFile( const char *refname ) {
  const char *cmd = CMD_SCF;
  if ( refname == NULL ) {
    fprintf( stderr, "%s: error, null argument\n", cmd );
    return 1;
  }
  int exitcd = 1; // default to error
  // open the plain file
  FILE *rdfp = fopen( refname, "rb" );
  if ( rdfp != NULL ) {
    // can't read size from stdin so just allocate large space
    uint8_t *membuff1 = calloc( CREDSZ_LG+1, 1 ); 
    if ( membuff1 != NULL ) {
      size_t rdsz = fread( membuff1, 1, CREDSZ_LG, rdfp );
      fclose( rdfp );
      // check for overflow
      if ( rdsz >= CREDSZ_LG ) {
        fprintf( stderr, "%s: error, unable to read\n", cmd );
      } else {
        // encrypt from memory buffer; write to credential in refname 
        int retval = rdkconfig_set( refname, membuff1, rdsz );
        if ( retval == RDKCONFIG_OK ) {
          exitcd = 0; // success
        } else {
          fprintf( stderr, "%s: error, unable to set\n", cmd );
        }
      }
      // always wipe and free buffer
      if ( rdkconfig_free( &membuff1, rdsz ) != RDKCONFIG_OK ) {
        fprintf( stderr, "%s: mem free error\n", cmd );
        // but this does create error exit code
      }
    } else {
      fprintf( stderr, "%s: mem error\n", cmd );
      fclose( rdfp );
    }
  } else {
    fprintf( stderr, "%s: error, unable to open %s\n", cmd, refname );
  }
  return exitcd;
}

//MOCK
#define UTCREDNAME "utstcredname1"
char *getcredname( char *credname, unsigned int credname_sz, const char *refname ) {
  strncpy( credname, UTCREDNAME, credname_sz ); // this doesn't do any overflow checking
  return credname;
}
#if ! defined(UNIT_TESTS)
// GetConfigFile/SaveConfigFile
int main( int argc, char *argv[] ) {
  return gcfmain( argc, argv );
}
#else
static int utmain( int argc, char *argv[] );
int main( int argc, char *argv[] ) {
  return utmain( argc, argv );
}

#include "unit_test.h"

static int runcnt_rdkconfig_get = 0; // number of successful runs
// rdkconfig_get( &membuff1, &memsz, refname ) -- MOCK
int rdkconfig_get( uint8_t **sbuff, size_t *sbuffsz, const char *refname ) {
fprintf(stderr,"rdkconfig_get mock\n");
  *sbuffsz = 40;
  *sbuff = calloc( 1, *sbuffsz );
  memset( *sbuff, 'g', (*sbuffsz)-1 );
  memcpy( *sbuff, refname, strlen(refname) );
  runcnt_rdkconfig_get++;
  return RDKCONFIG_OK;
}

static int runcnt_rdkconfig_set = 0; // number of successful runs
// rdkconfig_set( refname, membuff1, rdsz ) -- MOCK
int rdkconfig_set( const char *refname, uint8_t *sbuff, size_t sbuffsz ) {
fprintf(stderr,"rdkconfig_set mock\n");
  int retval = RDKCONFIG_OK;
  int indx;
  // not very efficient, but if any of these fail, then return fail
  for ( indx=0; indx<strlen(refname); indx++ ) {
    if ( sbuff[indx] != refname[indx] ) {
      retval = RDKCONFIG_FAIL;
    }
  }
  for ( ; indx<(sbuffsz-1); indx++ ) {
    if ( sbuff[indx] != 'g' ) {
      retval = RDKCONFIG_FAIL;
      break;
    }
  }
  if ( sbuff[indx] != '\0' ) retval = RDKCONFIG_FAIL;
  if ( retval == RDKCONFIG_OK ) runcnt_rdkconfig_set++;

  return retval;
}

// rdkconfig_free( &membuff1, memsz ) -- MOCK
int rdkconfig_free( uint8_t **sbuff, size_t sbuffsz ) {
  if ( sbuff == NULL ) return RDKCONFIG_FAIL;
  if ( *sbuff == NULL ) {
    return RDKCONFIG_OK; // ok if pointer is null
  }
  free( *sbuff );
  *sbuff = NULL;
  return RDKCONFIG_OK;
}

#define UTTSTFILE "utstfile1"

static int utmain( int argc, char *argv[] ) {

  fprintf( stderr, "\nUNIT TEST - GetSaveConfigFile BEGIN\n" );
  fprintf( stderr, "UNIT TEST - GetConfigFile argument tests -- expect errors\n" );

  UT_INTCMP( GetConfigFile( NULL, NULL ), RDKCONFIG_FAIL );
  UT_INTCMP( GetConfigFile( "--cn", NULL ), RDKCONFIG_FAIL );

  fprintf( stderr, "UNIT TEST - GetConfigFile\n" );
  UT_INTCMP( runcnt_rdkconfig_get, 0 );
  UT_INTCMP( GetConfigFile( "--cn", "utstcred" ), RDKCONFIG_OK );
  UT_DOESNTEXIST( UTTSTFILE );
  UT_INTCMP( GetConfigFile( UTTSTFILE, "stdout" ), RDKCONFIG_OK );
  UT_INTCMP( runcnt_rdkconfig_get, 1 );
  UT_DOESNTEXIST( UTTSTFILE );
  UT_INTCMP( GetConfigFile( UTTSTFILE, NULL ), RDKCONFIG_OK );
  UT_INTCMP( runcnt_rdkconfig_get, 2 );
  UT_EXISTS( UTTSTFILE );

  fprintf( stderr, "UNIT TEST - SaveConfigFile argument tests -- expect errors\n" );
  UT_INTCMP( SaveConfigFile( NULL ), RDKCONFIG_FAIL );

  fprintf( stderr, "UNIT TEST - SaveConfigFile\n" );
  UT_INTCMP( runcnt_rdkconfig_set, 0 );
  UT_INTCMP( SaveConfigFile( UTTSTFILE ), RDKCONFIG_OK );
  UT_INTCMP( runcnt_rdkconfig_set, 1 );

  fprintf( stderr, "UNIT TEST - GetSaveConfigFile - SUCCESS\n" );

  return 0;
}

#endif // UNIT_TESTS
