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

#if defined( UNIT_TESTS ) || defined( COMP_TESTS )
#define RT "./ut/"
#else
#define RT ""
#endif

#ifdef RDKLOGGER
    #include "rdk_debug.h"
    #define LOG_LIB "LOG.RDK.CERTSELECTOR"
    #define ERROR_LOG(...) RDK_LOG(RDK_LOG_ERROR, LOG_LIB, __VA_ARGS__)
    #define DEBUG_LOG(...) RDK_LOG(RDK_LOG_INFO, LOG_LIB, __VA_ARGS__)
    #define EXTRA_DEBUG_LOG(...) RDK_LOG(RDK_LOG_DEBUG, LOG_LIB, __VA_ARGS__)
#else
    #define RDK_LOG(a1, a2, args...) fprintf(stderr, args)
    #define RDK_LOG_INFO 0
    #define RDK_LOG_ERROR 0
    #define RDK_LOG_DEBUG 0
    #define LOG_LIB 0
    #define ERROR_LOG(...) RDK_LOG(RDK_LOG_ERROR, LOG_LIB, __VA_ARGS__)
    #define DEBUG_LOG(...) RDK_LOG(RDK_LOG_INFO, LOG_LIB, __VA_ARGS__)

    //switch the comment lines to enable/disable extra debug logging
    //#define EXTRA_DEBUG_LOG(...) RDK_LOG(RDK_LOG_DEBUG, LOG_LIB, __VA_ARGS__)
    #define EXTRA_DEBUG_LOG(...)
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <stdint.h>
#include <sys/stat.h>

#include "rdkcertlocator.h"
#ifdef GTEST_ENABLE
#include "../gtest/mock/mock.h"
#else
#include "rdkconfig.h"
#endif


// cert locator object
// internal states for managing the cert locator api
typedef struct rdkcertlocator_s {
  char certSelPath[PATH_MAX+1];
  char certUri[PATH_MAX+1];
  char certCredRef[PARAM_MAX+1];
  char certPass[PARAM_MAX+1];
  char hrotEngine[ENGINE_MAX+1];
  long reserved1;
} rdkcertlocator_t;

#define MAX_LINE_LENGTH 1024

#define CHK_RESERVED1 (0x12345678)

// default locations for config and properties files
#ifdef GTEST_ENABLE
#define DEFAULT_CONFIG_PATH  "./ut/etc/ssl/certsel/certsel.cfg"
#define DEFAULT_HROTPROP_PATH  "./ut/etc/ssl/certsel/hrot.properties"
#else
#define DEFAULT_CONFIG_PATH RT "/etc/ssl/certsel/certsel.cfg"
#define DEFAULT_HROTPROP_PATH RT "/etc/ssl/certsel/hrot.properties"
#endif

#define ENGINETAG "hrotengine="

static rdkcertlocatorStatus_t certloc_locateCert( rdkcertlocator_h thiscertloc, const char *certRef );
static void memwipe( volatile void *mem, size_t sz );
static int includesChar( const char *str, char ch1 );

/**
 * Constructs an instance of the rdkcertlocator_t
 *     API will read the cert.cfg and hrot.properties to populate the object.
 *     Application must track the handle and invoke destroy it before exiting,
 * In @param appIdentity The application identity; could be empty string(optional).
 * Out @param engine The openssl engine/provider w.r.t Hrot support.
 * @return the global handle to the cert locator object.
 * NULL if the call fails.
**/
rdkcertlocator_h rdkcertlocator_new(const char *certsel_path, const char *hrotprop_path ) {

  // check config path, either from argument or use default
  if ( certsel_path == DEFAULT_CONFIG ) certsel_path = DEFAULT_CONFIG_PATH;
  size_t paramlen = strlen( certsel_path );
  if ( paramlen >= PATH_MAX ) {
    ERROR_LOG( " %s:string size error, certSelPath (%zu)\n", __FUNCTION__, paramlen );
    return NULL;
  }

  // does config file exist
  struct stat fileStat;
  int statret = stat( certsel_path, &fileStat );
  if ( statret != 0 ) {  // file error
    ERROR_LOG( " %s:config file not found [%s]\n", __FUNCTION__, certsel_path );
    return NULL;
  }

  // allocate space for object
  rdkcertlocator_t *thiscertloc = (rdkcertlocator_t *)malloc( sizeof(rdkcertlocator_t) );
  if ( thiscertloc == NULL ) {
    ERROR_LOG( " %s:memory error\n", __FUNCTION__ );
    return NULL;
  }
  // used for integrity check
  thiscertloc->reserved1 = CHK_RESERVED1;

  // length checked above, just cpy
  strcpy( thiscertloc->certSelPath, certsel_path );

  // hardware root of trust properties file path from argument or use default
  if ( hrotprop_path == DEFAULT_HROT ) hrotprop_path = DEFAULT_HROTPROP_PATH;

  // open config file and look for cert group in first column
  thiscertloc->certUri[0] = '\0';
  thiscertloc->certCredRef[0] = '\0';
  thiscertloc->certPass[0] = '\0';
  thiscertloc->hrotEngine[0] = '\0';

  // get engine from hrot properties
  // grab the hrot engine
  char hrotline[MAX_LINE_LENGTH+2];
  hrotline[MAX_LINE_LENGTH+1]='1';

  FILE *hrotfp = fopen( hrotprop_path, "r" );
  if ( hrotfp == NULL) {
    DEBUG_LOG( " %s:hrot file not found [%s]\n", __FUNCTION__, hrotprop_path );
    // if no file, then no engine expected
  } else {

    // find the hrot tag, should probably be on the first line, but can be later
    while ( fgets( hrotline, sizeof(hrotline), hrotfp ) ) {

      // check if line from file was truncated
      if ( hrotline[MAX_LINE_LENGTH+1] != '1' ) {
        ERROR_LOG( " %s: hrot line too long\n", __FUNCTION__ );
        continue;
      } else {

        // remove terminal newline
        char *nl = strchr( hrotline, '\n' );
        if ( nl != NULL ) *nl = '\0';

        // compare first part of line for engine tag
        if ( strncmp( hrotline, ENGINETAG, sizeof(ENGINETAG)-1 ) == 0 ) {
          strncpy( thiscertloc->hrotEngine, (hrotline+sizeof(ENGINETAG)-1), sizeof(thiscertloc->hrotEngine) );
          thiscertloc->hrotEngine[ENGINE_MAX] = '\0'; // terminate if necessary to truncate
          EXTRA_DEBUG_LOG( " %s:hroteng[%s], hrotpath[%s]\n", __FUNCTION__, thiscertloc->hrotEngine, hrotprop_path );
          break;
        }
      } // end else line read ok
    } // end while

    fclose( hrotfp );
  } // end else

  return thiscertloc;
} // rdkcertlocator_new( )

/**
 *  RDK Cert Locator destructor
 *  API will clear and free the resouces allocated for the cert locator object; also NULLs the pointer
**/
void rdkcertlocator_free( rdkcertlocator_h *thiscertloc ) {
  if ( thiscertloc != NULL && *thiscertloc != NULL ) {
    if ( (*thiscertloc)->reserved1 != CHK_RESERVED1 ) {
      ERROR_LOG( " %s:WARNING: corrupted object [%lx]\n", __FUNCTION__, (*thiscertloc)->reserved1 );
    }
    memwipe( (*thiscertloc)->certPass, sizeof( (*thiscertloc)->certPass ) );
    memwipe( (*thiscertloc)->certCredRef, sizeof( (*thiscertloc)->certCredRef ) );
    (*thiscertloc)->reserved1 = 0;
    free( *thiscertloc );
    *thiscertloc = NULL;
  }
} // rdkcertlocator_free( )



/**
 *  Gets OpenSSL engine to be applied for the device.
 * In @param gHandle is the rdkcertlocator_t;
 * Return the char* pointer to engine, NULL on failure.
 *         If the provided `rdkcertlocator_t gHandle` is null, the API will invoke the constructor.
**/
char *rdkcertlocator_getEngine( rdkcertlocator_h thiscertloc ) {
  char *hroteng = NULL;
  if ( thiscertloc == NULL ) {
    ERROR_LOG( " %s:null argument\n", __FUNCTION__ );
    return NULL;
  }

  // use engine we already have or NULL if empty
  if ( thiscertloc->hrotEngine[0] != '\0' ) {
    hroteng = thiscertloc->hrotEngine;
  } else {
    hroteng = NULL;
  }
  return hroteng;

} // rdkcertlocator_getEngine( )


// to convert Uri to file path, skip past the "file://" scheme
// the scheme expects 3 slashes, but the third one is the root of the file path
// format expected is, for example, "file:///etc/ssl/certs/cert1.p12"
//   for testing, relative paths may be used: "file://./ut/etc/ssl/certs/cert1.p12"
//   which does not fit normal expectations of either 1 slash or 3 slashes

#define FILESCHEME "file://"

/**
 *  API for RDK Cert Locator operations.
 *  A cert file & it's passcode will be returned by the API on success.
 *  On each call API will check the following and return appropriate cert & it's credential.
 *     Requested Cert usage type.
 *     Availability of cert
 *     last status of the cert
 *     last cert index used
 *     static or opertational cert.
 *  For each call may wipe the previous passcode, before writing the new passcode.
 *  In @param connectHandle; cert instance object handle for the connection.
 *  In @param usgType; usage type MTLS/STATERED/D2D
 *  Out @param certFile; cert
 *  Out @param credData; cert credential; must wipe after each iteration.
 *  @return 0/certlocatorOk for success, non-zero values for the failure.
**/
rdkcertlocatorStatus_t rdkcertlocator_locateCert( rdkcertlocator_h thiscertloc, const char *certRef, char **certUri, char **certPass ) {

  if ( thiscertloc == NULL ) {
    ERROR_LOG( " %s:null argument\n", __FUNCTION__ );
    return certlocatorBadPointer;
  }
  if ( certRef == NULL || certUri == NULL || certPass == NULL ) {
    ERROR_LOG( " %s:null argument(s)\n", __FUNCTION__ );
    return certlocatorBadArgument;
  }

  // locateCert
  rdkcertlocatorStatus_t retval = certloc_locateCert( thiscertloc, certRef );

  if ( retval == certlocatorOk ) {
    // if cert file does not exist, return file error

    char *certFile = thiscertloc->certUri;
    // strip off uri scheme "file://"
    if ( strncmp( certFile, FILESCHEME, sizeof(FILESCHEME)-1 ) == 0 ) {
      certFile += (sizeof(FILESCHEME)-1);
    }

    // does file exist
    struct stat fileStat;
    int statret = stat( certFile, &fileStat );

    if ( statret != 0 ) {  // file error
      DEBUG_LOG( " %s:cert file not found [%s]\n", __FUNCTION__, certFile );
      retval = certlocatorFileNotFound;
    }
  }

  if ( retval == certlocatorOk ) {
    EXTRA_DEBUG_LOG( " %s:get passcode (%u)\n", __FUNCTION__, retval );
    // file exists and is not the same as bad (or was not marked as bad), so get the passcode and return them
    char *pc = NULL;
    size_t pcsz = 0;
    retval = certlocatorFileError; // look for cred file, error out if not found
    if ( rdkconfig_getStr( &pc, &pcsz, thiscertloc->certCredRef ) == RDKCONFIG_OK ) {
      if ( pc != NULL ) {
        // don't include any newline at end and don't add an additional null terminator
        if ( pc[pcsz-2] == '\n' ) {
          pc[pcsz-2] = '\0';
          --pcsz;
        }

        if ( pcsz < (sizeof(thiscertloc->certPass)-1) ) {
          memcpy( thiscertloc->certPass, pc, pcsz );
          thiscertloc->certPass[pcsz] = '\0'; // data coming in does not assume string so need to null terminate
          rdkconfig_freeStr( &pc, pcsz );
          retval = certlocatorOk; // found it
          EXTRA_DEBUG_LOG( " %s:got the passcode\n", __FUNCTION__ );
        } else {
          ERROR_LOG( " %s:pc did not fit (%zu)\n", __FUNCTION__, pcsz );
          rdkconfig_freeStr( &pc, pcsz );
        }
      } // pc not null
    } // rdkconfig_getStr ok
  } else {
    DEBUG_LOG( " %s:cert reference [%s] not found (%u)\n", __FUNCTION__, certRef, retval );
    return retval;
  } // end if cert ok so far

  // if cert and passcode ok
  if ( retval == certlocatorOk ) {
    *certUri = thiscertloc->certUri;
    *certPass = thiscertloc->certPass;

    EXTRA_DEBUG_LOG( " %s:returning [%s:%s]\n", __FUNCTION__, *certUri, "****" );
  } else {
    ERROR_LOG( " %s:credential reference [%s] not found (%u)\n", __FUNCTION__, thiscertloc->certCredRef, retval );
  }
  EXTRA_DEBUG_LOG( " %s:returning %d\n", __FUNCTION__, retval );
  return retval;
} // rdkcertlocator_locateCert( )



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// INTERNAL STATIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// fix this to always wipe without getting optimized out
static void memwipe( volatile void *mem, size_t sz ) {
  memset( (void *)mem, 0, sz );
}

#define DELIM_STR ","
#define DELIM_CHAR ','

// includesChars- check if a char string includes the char provided
// return 1(true) or 0(false)
static int includesChar( const char *str, char ch1 ) {
  if ( str == NULL ) return 0;
  while ( *str != '\0' ) {
    if ( *str == ch1 ) {
      return 1;
    }
    str++;
  }
  return 0;
} // includesChar( )


// locate cert based on info in the certloc instance
// use config file path to open file, search for the cert reference in the file
// update the certUri and certCredRef fields, which will be used by the api function
static rdkcertlocatorStatus_t certloc_locateCert( rdkcertlocator_h thiscertloc, const char *certRef ) {
  if ( thiscertloc == NULL ) {
    ERROR_LOG( " %s:null argument\n", __FUNCTION__ );
    return certlocatorBadPointer;
  }
  if ( certRef == NULL ) {
    ERROR_LOG( " %s:null argument\n", __FUNCTION__ );
    return certlocatorBadPointer;
  }
  if ( includesChar( certRef, DELIM_CHAR ) == 1 ) {
    ERROR_LOG( " %s:bad argument\n", __FUNCTION__ );
    return certlocatorBadArgument;
  }

  rdkcertlocatorStatus_t retval = certlocatorGeneralFailure;

  char *certSelCfg = thiscertloc->certSelPath;
  if ( certSelCfg[0] == '\0' ) {
    ERROR_LOG( " %s:argument error [%s]\n", __FUNCTION__, certSelCfg );
    return certlocatorBadArgument;
  }

  FILE *cfgfp = fopen( certSelCfg, "r" );
  if ( cfgfp == NULL) {
    ERROR_LOG( " %s:config file, %s, not found\n", __FUNCTION__, certSelCfg );
    return certlocatorFileNotFound;
  }

  size_t reflen = strnlen( certRef, PARAM_MAX );

  char cfgline[MAX_LINE_LENGTH+1];
  char *cfgfield = NULL;
  char *savetok1;

  // config file fields as follows:
  // <group>,<certref>,<type>,<uri>,<credref>

  // look for certref in field 2 and then on match store fields 4 and 5

  cfgline[MAX_LINE_LENGTH-1] = '\0'; // if this bytes gets overwritten, then line was too long

  while ( fgets( cfgline, sizeof(cfgline), cfgfp ) ) {

    // check if line from file was truncated
    if ( cfgline[MAX_LINE_LENGTH-1] != '\0' ) {
      ERROR_LOG( " %s: config line too long\n", __FUNCTION__ );
      retval = certlocatorFileError;
      break;
    }

    // remove terminal newline
    char *nl = strchr( cfgline, '\n' );
    if ( nl != NULL ) *nl = '\0';

    // look for cert ref in second field
    // do not allow unexpected whitespace

    cfgfield = strtok_r( cfgline, DELIM_STR, &savetok1 ); // 1st field is group
    if ( cfgfield != NULL ) {
      cfgfield = strtok_r( NULL, DELIM_STR, &savetok1 ); // 2nd field is cert ref
    }

    if ( cfgfield != NULL && strncmp( cfgfield, certRef, reflen+1 ) == 0 ) {

      // extract cert info

      // skip field 3=type
      cfgfield = strtok_r( NULL, DELIM_STR, &savetok1 ); // skip 3rd field

      if ( cfgfield == NULL ) {
        ERROR_LOG( " %s:missing field (3)\n", __FUNCTION__ );
        retval = certlocatorFileError;
        break;
      }

      // copy uri and cred reference fields into object
      // an error here is probably a corruption of the config file
      cfgfield = strtok_r( NULL, DELIM_STR, &savetok1 ); // 4th field is URI
      if ( cfgfield != NULL ) {
        size_t fieldlen = strlen( cfgfield );
        if ( fieldlen < (sizeof(thiscertloc->certUri)-1) ) {
          strcpy( thiscertloc->certUri, cfgfield );
          cfgfield = strtok_r( NULL, DELIM_STR, &savetok1 ); // 5th field is Cred reference
          if ( cfgfield != NULL ) {
            fieldlen = strlen( cfgfield );
            if ( fieldlen < (sizeof(thiscertloc->certCredRef)-1) ) {
              strcpy( thiscertloc->certCredRef, cfgfield );
            } else {
              cfgfield = NULL; // 5th field error
              thiscertloc->certUri[0] = '\0'; // 5th field failure so empty 4th
            }
          }
        } else {
          cfgfield = NULL; // 4th field error
        }
      }
      // check for error
      if ( cfgfield == NULL ) {
        ERROR_LOG( " %s:missing fields (4/5)\n", __FUNCTION__ );
        retval = certlocatorFileError;
        break;
      }

      // found one and saved the cert info
      retval = certlocatorOk;
      break;

    } // end if matches cert ref

  } // end while

  fclose( cfgfp );

  if ( retval == certlocatorGeneralFailure ) {
    EXTRA_DEBUG_LOG( " %s:match not found for %s\n", __FUNCTION__, certRef );
    retval = certlocatorFileNotFound;
  }

  return retval;
} // certloc_locateCert( rdkcertlocator_h thiscertloc, const char *certRef )


#if defined(UNIT_TESTS) || defined(GTEST_ENABLE)
#include "unit_test.h"

#define UTDIR "./ut"
#define CERTSEL_CFG UTDIR "/tst1certsel.cfg"
#define HROT_PROP UTDIR "/tst1hrot.properties"
#define HROT_PROP2 UTDIR "/tst2hrot.properties" // second line, ok
#define HROT_PROP_BAD UTDIR "/bad3hrot.properties" // bad format
#define HROT_PROP_LONG UTDIR "/long4hrot.properties" // long line
#define DEF_HROT_PROP UTDIR "/hrot.properties"

#define LONGPATH "/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789/123456789"

#define UTCERT1 UTDIR "/tst1first.tmp"
#define UTCERT2 UTDIR "/tst1second.tmp"
#define UTCERT3 UTDIR "/tst1third.tmp"
#define UTCERTALPHA UTDIR "/tst1alpha.tmp"

#define UTCRED1 "pc1"
#define UTCRED2 "pc2"
#define UTCRED3 "pc3"
#define UTCREDALPHA "pcalpha"

#define UTPASS1 UTCRED1 "pass"
#define UTPASS2 UTCRED2 "pass"
#define UTPASS3 UTCRED3 "pass"
#define UTPASSALPHA UTCREDALPHA "pass"

// MOCKS

// rdkconfig_getStr - get string credential, allocate space, fill buffer
int rdkconfig_getStr( char **sbuff, size_t *sbuffsz, const char *refname ) { // MOCK
  int retval = RDKCONFIG_OK;
  char *membuff = (char *)malloc( 50 );
  if ( membuff == NULL ) {
    return RDKCONFIG_FAIL;
  }
  if ( strcmp( refname, UTCRED1 ) == 0 ) {
    strcpy( (char *)membuff, UTPASS1 );
  } else if ( strcmp( refname, UTCRED2 ) == 0 ) {
    strcpy( (char *)membuff, UTPASS2 );
  } else if ( strcmp( refname, UTCRED3 ) == 0 ) {
    strcpy( (char *)membuff, UTPASS3 );
  } else if ( strcmp( refname, UTCREDALPHA ) == 0 ) {
    strcpy( (char *)membuff, UTPASSALPHA );
  } else {
    retval =  RDKCONFIG_FAIL;
  }
  if ( retval == RDKCONFIG_OK ) {
    *sbuff = membuff;
    *sbuffsz = strlen( (char *)membuff )+1; // sz includes null terminator
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


// used throughout tests
static const char *certsel_path = CERTSEL_CFG;
static const char *hrotprop_path = HROT_PROP;

// Unit test support functions

// unit tests for static int includesChar( const char *str, char ch1 )
static void ut_includesChar( void ) {
  UT_BEGIN( __FUNCTION__ );
  // no match
  UT_FALSE( includesChar( "123456", 0 ) );
  UT_FALSE( includesChar( "123456", 'x' ) );
  UT_FALSE( includesChar( "123456", '7' ) );
  // 1 match
  UT_TRUE( includesChar( "123456", '1' ) );
  UT_TRUE( includesChar( "123456", '4' ) );
  UT_TRUE( includesChar( "123456", '6' ) );
  // realistic uses
  UT_FALSE( includesChar( "REF1", DELIM_CHAR ) );
  UT_TRUE( includesChar( "REF1,REF2", DELIM_CHAR ) );

  UT_END( __FUNCTION__ );
} // static void ut_includesChar( void )


// initialize or reinitialize a certloc test object
static void ut_initcl( rdkcertlocator_t *tstcl ) {
  UT_NOTNULL( tstcl ); // memory error
  tstcl->reserved1 = CHK_RESERVED1;
  strncpy( tstcl->certSelPath, certsel_path, PATH_MAX );
  tstcl->certSelPath[ PATH_MAX-1 ] = '\0';
  tstcl->certUri[0] = tstcl->certCredRef[0] = tstcl->certPass[0] = '\0';
}

// allocate and initialize a certloc test object
// this is used until rdkcertlocator_new is fully tested
static rdkcertlocator_t *ut_newcl( void ) {
  rdkcertlocator_t *tstcl = (rdkcertlocator_t *)calloc( 1, sizeof(rdkcertlocator_t) );
  UT_NOTNULL( tstcl ); // memory error
  ut_initcl( tstcl );

  return tstcl;
}


static void ut_printcertloc( rdkcertlocator_h cl ) {
  fprintf( stderr, "*rdkcertloc_t:\n");
  fprintf( stderr, "* certSelPath[%s]\n", cl->certSelPath );
  fprintf( stderr, "* certUri[%s], certCredRef[%s], certPass[%s]\n", cl->certUri, cl->certCredRef, "*****" );
  fprintf( stderr, "* hrotEngine[%s], reserved1[%lx]\n", cl->hrotEngine, cl->reserved1 );
}

#ifndef GTEST_ENABLE
// Unit tests for functions

// unit tests for static rdkcertlocatorStatus_t certloc_locateCert( rdkcertlocator_h thiscertloc )
static void ut_certloc_locateCert( void ) {
  UT_BEGIN( __FUNCTION__ );

  // create certloc object for testing
  rdkcertlocator_h tstcl = ut_newcl( );
  UT_STRCMP( tstcl->certUri, "", PATH_MAX );
  UT_STRCMP( tstcl->certCredRef, "", PARAM_MAX );

  UT_LOG( "Expect 3 error messages for arguments" );
  UT_INTCMP( certloc_locateCert( NULL, "FRST" ), certlocatorBadPointer );
  tstcl->certSelPath[0] = '\0';
  UT_INTCMP( certloc_locateCert( tstcl, "FRST" ), certlocatorBadArgument );
  ut_initcl( tstcl );
  UT_INTCMP( certloc_locateCert( tstcl, NULL ), certlocatorBadPointer );
  UT_INTCMP( certloc_locateCert( tstcl, "FRST,SCND" ), certlocatorBadArgument );
  tstcl->certSelPath[0] = 'X';
  UT_INTCMP( certloc_locateCert( tstcl, "FRST" ), certlocatorFileNotFound );
  UT_LOG( "Expect 5 error messages for config file format" );
  ut_initcl( tstcl );
  strncpy( tstcl->certSelPath, UTDIR "/tst1toolong.cfg", PATH_MAX );
  UT_INTCMP( certloc_locateCert( tstcl, "FRST" ), certlocatorFileError );
  ut_initcl( tstcl );
  strncpy( tstcl->certSelPath, UTDIR "/tst1miss2.cfg", PATH_MAX );
  UT_INTCMP( certloc_locateCert( tstcl, "FRST" ), certlocatorFileNotFound );
  ut_initcl( tstcl );
  strncpy( tstcl->certSelPath, UTDIR "/tst1miss3.cfg", PATH_MAX );
  UT_INTCMP( certloc_locateCert( tstcl, "FRST" ), certlocatorFileError );
  ut_initcl( tstcl );
  strncpy( tstcl->certSelPath, UTDIR "/tst1miss4.cfg", PATH_MAX );
  UT_INTCMP( certloc_locateCert( tstcl, "FRST" ), certlocatorFileError );
  ut_initcl( tstcl );
  strncpy( tstcl->certSelPath, UTDIR "/tst1miss5.cfg", PATH_MAX );
  UT_INTCMP( certloc_locateCert( tstcl, "FRST" ), certlocatorFileError );
  // beyond max
  UT_LOG( "Expect 1 error messages for max" );
  ut_initcl( tstcl );
  UT_INTCMP( certloc_locateCert( tstcl, "MAX" ), certlocatorFileNotFound );

  UT_LOG( "Valid" );
  // find first
  ut_initcl( tstcl );
  UT_INTCMP( certloc_locateCert( tstcl, "FRST" ), certlocatorOk );
  UT_STRCMP( tstcl->certUri, FILESCHEME UTCERT1, PATH_MAX );
  UT_STRCMP( tstcl->certCredRef, "pc1", PARAM_MAX );

  // find second
  ut_initcl( tstcl );
  UT_INTCMP( certloc_locateCert( tstcl, "SCND" ), certlocatorOk );
  UT_STRCMP( tstcl->certUri, FILESCHEME UTCERT2, PATH_MAX );
  UT_STRCMP( tstcl->certCredRef, "pc2", PARAM_MAX );

  // find third
  ut_initcl( tstcl );
  UT_INTCMP( certloc_locateCert( tstcl, "THRD" ), certlocatorOk );
  UT_STRCMP( tstcl->certUri, "file://" UTCERT3, PATH_MAX );
  UT_STRCMP( tstcl->certCredRef, "pc3", PARAM_MAX );

  // can't find MISNG
  ut_initcl( tstcl );
  UT_INTCMP( certloc_locateCert( tstcl, "MISNG" ), certlocatorFileNotFound );

  free( tstcl );

  UT_END( __FUNCTION__ );
} // ut_certloc_locateCert( void )

// unit tests for void rdkcertlocator_free( rdkcertlocator_h **thiscertloc )
static void ut_certloc_free( void ) {
  UT_BEGIN( __FUNCTION__ );
  // the next call should not cause a fault
  rdkcertlocator_free( NULL );
#ifdef CHECK_MEM_WIPE
  rdkcertlocator_h tstclh = ut_newcl( );
  rdkcertlocator_h tstclh2 = tstclh; // used to check freed memory below
  UT_NOTNULL( tstclh );
  tstclh->certCredRef[0] = 'X';
  tstclh->certPass[0] = 'Y';
  rdkcertlocator_free( &tstclh );
  UT_NULL( tstclh );
  rdkcertlocator_free( &tstclh );  // second free is protected
  // make sure cred and pass were wiped
  // this creates a coverity error so once tested, it can be commented out
  UT_INTCMP( tstclh2->certCredRef[0], 0 ); // warning, this is looking into deallocated space
  UT_INTCMP( tstclh2->certPass[0], 0 ); // warning, this is looking into deallocated space
#endif // CHECK_MEM_WIPE
  UT_END( __FUNCTION__ );
}

// unit tests for rdkcertlocator_h rdkcertlocator_new(const char *certsel_path, const char *hrotprop_path, const char *cert_group )
static void ut_certloc_new( void ) {
  UT_BEGIN( __FUNCTION__ );

  DEBUG_LOG( "unit test setup: [%s] [%s]\n", certsel_path, hrotprop_path );

  rdkcertlocator_h tstcl1 = NULL, tstcl2 = NULL;

  // bad arguments
  UT_LOG( "Expect 2 error messages for arguments" );
  UT_NULL( rdkcertlocator_new( LONGPATH, DEFAULT_HROT ) );
  UT_NULL( rdkcertlocator_new( UTDIR "/doesnotexist.cfg", DEFAULT_HROT ) );

  UT_LOG( "valid" );
  UT_NOTNULL( tstcl1 = rdkcertlocator_new( NULL, NULL ) );
  rdkcertlocator_free( &tstcl1 );

  // 2 different instances
  UT_NOTNULL( tstcl1 = rdkcertlocator_new( DEFAULT_CONFIG, DEFAULT_HROT ) );
  UT_NOTNULL( tstcl2 = rdkcertlocator_new( certsel_path, hrotprop_path ) );

  ut_printcertloc( tstcl1 );
  UT_INTCMP( tstcl1->reserved1, CHK_RESERVED1 );
  UT_STRCMP( tstcl1->certSelPath, DEFAULT_CONFIG_PATH, PATH_MAX );
  UT_STRCMP( tstcl1->certUri, "", PATH_MAX );
  UT_STRCMP( tstcl1->certCredRef, "", PARAM_MAX );
  UT_STRCMP( tstcl1->certPass, "", PARAM_MAX );
  UT_STRCMP( tstcl1->hrotEngine, "e4tstdef", PARAM_MAX );

  ut_printcertloc( tstcl2 );
  UT_INTCMP( tstcl2->reserved1, CHK_RESERVED1 );
  UT_STRCMP( tstcl2->certSelPath, certsel_path, PATH_MAX );
  UT_STRCMP( tstcl2->certUri, "", PATH_MAX );
  UT_STRCMP( tstcl2->certCredRef, "", PARAM_MAX );
  UT_STRCMP( tstcl2->certPass, "", PARAM_MAX );
  UT_STRCMP( tstcl2->hrotEngine, "e4tst1", PARAM_MAX );

  rdkcertlocator_free( &tstcl1 );
  rdkcertlocator_free( &tstcl2 );

  UT_NOTNULL( tstcl2 = rdkcertlocator_new( certsel_path, HROT_PROP2 ) ); // on 2nd line
  UT_STRCMP( tstcl2->hrotEngine, "e4tst1", PARAM_MAX );
  rdkcertlocator_free( &tstcl2 );

  // valid new, but engine not set
  UT_NOTNULL( tstcl1 = rdkcertlocator_new( DEFAULT_CONFIG, UTDIR "/doesnotexist.prop" ) ); // if no file, then no engine
  UT_STRCMP( tstcl1->hrotEngine, "", PARAM_MAX );
  rdkcertlocator_free( &tstcl1 );
  UT_NOTNULL( tstcl1 = rdkcertlocator_new( certsel_path, HROT_PROP_BAD ) );
  UT_STRCMP( tstcl1->hrotEngine, "", PARAM_MAX );
  rdkcertlocator_free( &tstcl1 );
  UT_NOTNULL( tstcl1 = rdkcertlocator_new( certsel_path, HROT_PROP_LONG ) );
  UT_STRCMP( tstcl1->hrotEngine, "", PARAM_MAX );
  rdkcertlocator_free( &tstcl1 );

  UT_END( __FUNCTION__ );
} // ut_certloc_new( void )

// unit tests for char *rdkcertlocator_getEngine( rdkcertlocator_h thiscertloc )
static void ut_rdkcertlocator_getEngine( void ) {
  UT_BEGIN( __FUNCTION__ );
  UT_LOG( "Expect 4 error messages" );
  UT_NULL ( rdkcertlocator_getEngine( NULL ) );
  rdkcertlocator_h tstcl1 = NULL, tstcl2 = NULL;
  UT_NULL ( rdkcertlocator_getEngine( tstcl1 ) );
  tstcl1 = rdkcertlocator_new( certsel_path, hrotprop_path );
  UT_STRCMP( rdkcertlocator_getEngine( tstcl1 ), "e4tst1", ENGINE_MAX );

  rdkcertlocator_h badcl1 = rdkcertlocator_new( certsel_path, HROT_PROP_BAD ); // bad format in file
  UT_NULL( rdkcertlocator_getEngine( badcl1 ) );
  rdkcertlocator_free( &badcl1 );

  badcl1 = rdkcertlocator_new( certsel_path, "/etc/cert/missingfile" );
  UT_NULL( rdkcertlocator_getEngine( badcl1 ) );
  rdkcertlocator_free( &badcl1 );

  char *eng = rdkcertlocator_getEngine( tstcl1 );
  UT_NOTNULL( eng );
  UT_STRCMP( eng, "e4tst1", ENGINE_MAX );
  rdkcertlocator_free( &tstcl1 );

  tstcl1 = rdkcertlocator_new( certsel_path, DEFAULT_HROT );
  eng = rdkcertlocator_getEngine( tstcl1 );
  UT_STRCMP( eng, "e4tstdef", ENGINE_MAX );

  tstcl2 = rdkcertlocator_new( certsel_path, hrotprop_path );
  eng = rdkcertlocator_getEngine( tstcl2 );
  UT_STRCMP( eng, "e4tst1", ENGINE_MAX );

  rdkcertlocator_free( &tstcl1 );
  rdkcertlocator_free( &tstcl2 );
  UT_END( __FUNCTION__ );

} // end ut_rdkcertlocator_getEngine( void )


// unit tests for rdkcertlocator_locateCert( rdkcertlocator_h thiscertloc, const char *certRef, char **certUri, char **certPass ) {
static void ut_rdkcertlocator_locateCert( void ) {
  UT_BEGIN( __FUNCTION__ );

  UT_LOG( "Expect 6 error messages for arguments" );
  rdkcertlocator_h tstcl1 = NULL;
  char *certUri = NULL, *certPass = NULL;
  UT_INTCMP( rdkcertlocator_locateCert( NULL, "FRST", &certUri, &certPass ), certlocatorBadPointer );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "FRST", &certUri, &certPass ), certlocatorBadPointer );

  tstcl1 = rdkcertlocator_new( DEFAULT_CONFIG, DEFAULT_HROT );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "FRST", NULL, &certPass ), certlocatorBadArgument );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "FRST", &certUri, NULL ), certlocatorBadArgument );
  rdkcertlocator_free( &tstcl1 );

  // files in config do not exist, return error
  tstcl1 = rdkcertlocator_new( certsel_path, DEFAULT_HROT );
  UT_SYSTEM0( "mv " UTCERT1 " ./ut/tstXfirst.tmp" );  // cert missing
  UT_SYSTEM0( "mv " UTCERT2 " ./ut/tstXsecond.tmp" );  // cert missing
  UT_SYSTEM0( "mv " UTCERT3 " ./ut/tstXthird.tmp" );  // cert missing
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "FRST", &certUri, &certPass ), certlocatorFileNotFound );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "SCND", &certUri, &certPass ), certlocatorFileNotFound );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "THRD", &certUri, &certPass ), certlocatorFileNotFound );
  rdkcertlocator_free( &tstcl1 );

  UT_LOG( "some valid, some not" );
  // first and third missing, second found
  UT_SYSTEM0( "mv ./ut/tstXsecond.tmp " UTCERT2 );  // cert no longer missing
  tstcl1 = rdkcertlocator_new( certsel_path, DEFAULT_HROT );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "FRST", &certUri, &certPass ), certlocatorFileNotFound );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "SCND", &certUri, &certPass ), certlocatorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1second.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc2pass", PARAM_MAX );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "THRD", &certUri, &certPass ), certlocatorFileNotFound );

  // first missing, second and third found
  UT_SYSTEM0( "mv ./ut/tstXthird.tmp " UTCERT3 );  // cert no longer missing
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "FRST", &certUri, &certPass ), certlocatorFileNotFound );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "SCND", &certUri, &certPass ), certlocatorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1second.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc2pass", PARAM_MAX );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "THRD", &certUri, &certPass ), certlocatorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1third.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc3pass", PARAM_MAX );

  // all found
  UT_SYSTEM0( "mv ./ut/tstXfirst.tmp " UTCERT1 );  // cert no longer missing
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "FRST", &certUri, &certPass ), certlocatorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1first.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc1pass", PARAM_MAX );
  rdkcertlocator_free( &tstcl1 );

  UT_LOG( "Expect 1 error message for missing pc" );
  // cert found but pc not found
  tstcl1 = rdkcertlocator_new( certsel_path, DEFAULT_HROT );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "NOPC", &certUri, &certPass ), certlocatorFileError );
  rdkcertlocator_free( &tstcl1 );

  UT_LOG( "valid" );

  tstcl1 = rdkcertlocator_new( certsel_path, DEFAULT_HROT );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "FRST", &certUri, &certPass ), certlocatorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1first.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc1pass", PARAM_MAX );
  rdkcertlocator_free( &tstcl1 );

  tstcl1 = rdkcertlocator_new( certsel_path, DEFAULT_HROT );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "SCND", &certUri, &certPass ), certlocatorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1second.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc2pass", PARAM_MAX );
  rdkcertlocator_free( &tstcl1 );

  tstcl1 = rdkcertlocator_new(  certsel_path, DEFAULT_HROT );
  UT_INTCMP( rdkcertlocator_locateCert( tstcl1, "THRD", &certUri, &certPass ), certlocatorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1third.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc3pass", PARAM_MAX );
  rdkcertlocator_free( &tstcl1 );

  UT_END( __FUNCTION__ );
} // end ut_rdkcertlocator_locateCert( void )


int main( int argc, char *argv[] ) {

  UT_BEGIN( __FILE__ );

  // internal functions
  ut_includesChar( );
  ut_certloc_locateCert( );
  // api
  ut_certloc_free( );
  ut_certloc_new( );
  ut_rdkcertlocator_locateCert( );
  ut_rdkcertlocator_getEngine( );

  fprintf( stderr, "\n" );
  UT_END( __FILE__ );
}
#endif
#endif // UNIT_TESTS

