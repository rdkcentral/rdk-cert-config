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
#else
    #define RDK_LOG(a1, a2, args...) fprintf(stderr, args)
    #define RDK_LOG_INFO 0
    #define RDK_LOG_ERROR 0
    #define RDK_LOG_DEBUG 0
    #define LOG_LIB 0
#endif

#define ERROR_LOG(...) RDK_LOG(RDK_LOG_ERROR, LOG_LIB, __VA_ARGS__)
#define DEBUG_LOG(...) RDK_LOG(RDK_LOG_INFO, LOG_LIB, __VA_ARGS__)
#define EXTRA_DEBUG_LOG(...) RDK_LOG(RDK_LOG_DEBUG, LOG_LIB, __VA_ARGS__)

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <stdint.h>
#include <sys/stat.h>
#include <time.h>

#include "rdkcertselector.h"
#ifdef GTEST_ENABLE
#include "../gtest/mock/mock.h"
#else
#include "rdkconfig.h"
#endif

// cert selector object
// internal states for managing the cert selector api
typedef struct rdkcertselector_s {
  char certSelPath[PATH_MAX+1];
  char certGroup[PARAM_MAX+1];
  char certUri[PATH_MAX+1];
  char certCredRef[PARAM_MAX+1];
  char certPass[PARAM_MAX+1];
  char hrotEngine[ENGINE_MAX+1];
  uint16_t certIndx;
  uint16_t state;
  unsigned long certStat[LIST_MAX];  // 0 if ok, file date if cert found to be bad
  long reserved1;
} rdkcertselector_t;

// internal cert selector state
typedef enum {
    cssUnknown=200,
    cssReadyToGiveCert=201,
    cssReadyToCheckCert=202,
    cssNoCert=203,
} certselState_t;

#define MAX_LINE_LENGTH 1024

#define CHK_RESERVED1 (0x12345678)
#define CERTSTAT_NOTBAD 0          // NOTBAD means either ok, missing, or unknown

// default locations for config and properties files
#ifdef GTEST_ENABLE
#define DEFAULT_CONFIG_PATH  "./ut/etc/ssl/certsel/certsel.cfg"
#define DEFAULT_HROTPROP_PATH  "./ut/etc/ssl/certsel/hrot.properties"
#else
#define DEFAULT_CONFIG_PATH RT "/etc/ssl/certsel/certsel.cfg"
#define DEFAULT_HROTPROP_PATH RT "/etc/ssl/certsel/hrot.properties"
#endif

#define ENGINETAG "hrotengine="
#define DELIM_STR ","
#define DELIM_CHAR ','
#define GRPDELIM_STR "|"
#define GRPDELIM_CHAR '|'

#define CURLERR_LOCALCERT 58
#define CURLERR_NONCERT 1

static rdkcertselectorStatus_t certsel_findCert( rdkcertselector_h thiscertsel );
static rdkcertselectorStatus_t certsel_findNextCert( rdkcertselector_h thiscertsel );
static void memwipe( volatile void *mem, size_t sz );
static int includesChars( const char *str, char ch1, char ch2 );
static rdkcertselectorRetry_t certsel_chkCertError( int curlStat );
static unsigned long filetime( const char *fname );

/**
 * Constructs an instance of the rdkcertselector_t
 *     API will read the cert.cfg and hrot.properties to populate the object.
 *     Application must track the handle and invoke destroy it before exiting,
 * In @param appIdentity The application identity; could be empty string(optional).
 * Out @param engine The openssl engine/provider w.r.t Hrot support.
 * @return the global handle to the cert selector object.
 * NULL if the call fails.
**/
rdkcertselector_h rdkcertselector_new(const char *certsel_path, const char *hrotprop_path, const char *cert_group ) {

  // if no cert group given, return error
  if (( cert_group == NULL ) || ( *cert_group == '\0' )) {
    ERROR_LOG( " %s:bad cert_group pointer\n", __FUNCTION__ );
    return NULL;
  }
  // cert group cannot contain a "|" character or a ',' character
  if ( includesChars( cert_group, DELIM_CHAR, GRPDELIM_CHAR ) == 1 ) {
    ERROR_LOG( " %s:bad cert_group character [%s]\n", __FUNCTION__, cert_group );
    return NULL;
  }

  // allocate space for object
  rdkcertselector_t *thiscertsel = (rdkcertselector_t *)malloc( sizeof(rdkcertselector_t) );
  if ( thiscertsel == NULL ) {
    ERROR_LOG( " %s:memory error\n", __FUNCTION__ );
    return NULL;
  }

  // used for integrity check
  thiscertsel->reserved1 = CHK_RESERVED1;

  thiscertsel->state = cssUnknown;

  // copy in config path, either from argument or use default
  if ( certsel_path == DEFAULT_CONFIG ) certsel_path = DEFAULT_CONFIG_PATH;
  size_t paramlen = strlen( certsel_path );
  if ( paramlen >= sizeof(thiscertsel->certSelPath)-1 ) {
    ERROR_LOG( " %s:string size error, certSelPath (%zu)\n", __FUNCTION__, paramlen );
    free( thiscertsel );
    return NULL;
  }
  strcpy( thiscertsel->certSelPath, certsel_path );

  // hardware root of trust properties file path from argument or use default
  if ( hrotprop_path == DEFAULT_HROT ) hrotprop_path = DEFAULT_HROTPROP_PATH;

  // copy in cert group, but check size
  paramlen = strlen( cert_group );
  if ( paramlen >= sizeof(thiscertsel->certGroup)-1 ) {
    ERROR_LOG( " %s:string size error, cert_group (%zu)\n", __FUNCTION__, paramlen );
    free( thiscertsel );
    return NULL;
  }
  strcpy( thiscertsel->certGroup, cert_group );

  // open config file and look for cert group in first column
  thiscertsel->certIndx = 0;
  thiscertsel->certUri[0] = '\0';
  thiscertsel->certCredRef[0] = '\0';
  thiscertsel->certPass[0] = '\0';
  thiscertsel->hrotEngine[0] = '\0';
  memset( thiscertsel->certStat, 0, sizeof(thiscertsel->certStat) );

  // first look for a cert belonging to cert group, if not found then fail
  rdkcertselectorStatus_t certstat = certsel_findCert( thiscertsel );

  if ( certstat != certselectorOk ) {
    ERROR_LOG( " %s:cert not found for %s\n", __FUNCTION__, cert_group );
    free( thiscertsel );
    return NULL;
  }

  // get engine from hrot properties
  // grab the hrot engine
  char hrotline[MAX_LINE_LENGTH+2]; // one extra to check for trunctation
  hrotline[MAX_LINE_LENGTH]='1';
  FILE *hrotfp = fopen( hrotprop_path, "r" );
  if ( hrotfp == NULL) {
    ERROR_LOG( " %s:hrot file, %s, not found\n", __FUNCTION__, hrotprop_path );
    // if no file, then no engine expected
  } else {

    // find the hrot tag, should probably be on the first line
    while ( fgets( hrotline, sizeof(hrotline), hrotfp ) ) {

      // check if line from file was truncated
      if ( hrotline[MAX_LINE_LENGTH] != '1' ) {
        ERROR_LOG( " %s: hrot line too long\n", __FUNCTION__ );
        continue;
      } else {

        // remove terminal newline
        char *nl = strchr( hrotline, '\n' );
        if ( nl != NULL ) *nl = '\0';

        // compare first part of line for engine tag
        if ( strncmp( hrotline, ENGINETAG, sizeof(ENGINETAG)-1 ) == 0 ) {
          strncpy( thiscertsel->hrotEngine, (hrotline+sizeof(ENGINETAG)-1), sizeof(thiscertsel->hrotEngine)-1 );
          thiscertsel->hrotEngine[ENGINE_MAX] = '\0'; // terminate if necessary to truncate
          EXTRA_DEBUG_LOG( " %s:hroteng[%s], hrotpath[%s]\n", __FUNCTION__, thiscertsel->hrotEngine, hrotprop_path );
          break;
        }
      } // end else line read ok
    } // end while

    fclose( hrotfp );
  } // end else

  thiscertsel->state = cssReadyToGiveCert;
  return thiscertsel;
} // rdkcertselector_new( )

/**
 *  RDK Cert Selector destructor
 *  API will clear and free the resouces allocated for the cert selector object; also NULLs the pointer
**/
void rdkcertselector_free( rdkcertselector_h *thiscertsel ) {
  if ( thiscertsel != NULL && *thiscertsel != NULL ) {
    if ( (*thiscertsel)->reserved1 != CHK_RESERVED1 ) {
      ERROR_LOG( " %s:WARNING: corrupted object [%lx]\n", __FUNCTION__, (*thiscertsel)->reserved1 );
    }
    memwipe( (*thiscertsel)->certPass, sizeof( (*thiscertsel)->certPass ) );
    memwipe( (*thiscertsel)->certCredRef, sizeof( (*thiscertsel)->certCredRef ) );
    (*thiscertsel)->reserved1 = 0;
    free( *thiscertsel );
    *thiscertsel = NULL;
  }
} // rdkcertselector_free( )



/**
 *  Gets OpenSSL engine to be applied for the device.
 * In @param gHandle is the rdkcertselector_t;
 * Return the char* pointer to engine, NULL on failure.
 *         If the provided `rdkcertselector_t gHandle` is null, the API will invoke the constructor.
**/
char *rdkcertselector_getEngine( rdkcertselector_h thiscertsel ) {
  char *hroteng = NULL;
  if ( thiscertsel == NULL ) {
    ERROR_LOG( " %s:null argument\n", __FUNCTION__ );
    return NULL;
  }

  // use engine we already have or NULL if empty
  if ( thiscertsel->hrotEngine[0] != '\0' ) {
    hroteng = thiscertsel->hrotEngine;
  } else {
    hroteng = NULL;
  }
  return hroteng;

} // rdkcertselector_getEngine( )


// to convert Uri to file path, skip past the "file://" scheme
// the scheme expects 3 slashes, but the third one is the root of the file path
// format expected is, for example, "file:///etc/ssl/certsel/cert1.p12"
//   for testing, relative paths may be used: "file://./ut/etc/ssl/certsel/cert1.p12"
//   which does not fit normal expectations of either 1 slash or 3 slashes

#define FILESCHEME "file://"

/**
 *  API for RDK Cert Selection operations.
 *  A cert file & it's passcode will be returned by the API on success.
 *  On each call API will check the following and return appropriate cert & it's credential.
 *     Requested Cert usage type.
 *     Availability of cert
 *     last status of the cert
 *     last cert index used
 *     static or opertational cert.
 *  For each call may wipe the previous passcode, before writing the new passcode.
 *  In @param Handle; cert instance object handle for the connection.
 *  In @param usgType; usage type MTLS/STATERED/D2D
 *  Out @param certFile; cert
 *  Out @param credData; cert credential; must wipe after each iteration.
 *  @return 0/certselectorOk for success, non-zero values for the failure.
**/
rdkcertselectorStatus_t rdkcertselector_getCert( rdkcertselector_h thiscertsel, char **certUri, char **certPass ) {

  if ( thiscertsel == NULL ) {
    ERROR_LOG( " %s:null argument\n", __FUNCTION__ );
    return certselectorBadPointer;
  }
  if ( certUri == NULL || certPass == NULL ) {
    ERROR_LOG( " %s:null argument(s)\n", __FUNCTION__ );
    return certselectorBadArgument;
  }

  if ( thiscertsel->state != cssReadyToGiveCert ) {
    ERROR_LOG( " %s:unexpected state, %d!=%d\n", __FUNCTION__, thiscertsel->state, cssReadyToGiveCert );
    return certselectorGeneralFailure;
  }

  char *thisCertUri = thiscertsel->certUri;
  char *thisCertCredRef = thiscertsel->certCredRef;

  if ( thisCertUri[0] == '\0' || thisCertCredRef[0] == '\0' ) {
    ERROR_LOG( " %s:invalid argument(s) [%s|%s]\n", __FUNCTION__, thisCertUri, thisCertCredRef );
    return certselectorBadArgument;
  }

  rdkcertselectorStatus_t retval = certselectorGeneralFailure;
  rdkcertselectorStatus_t findval = certselectorGeneralFailure; // used when looking for next cert
  uint16_t certIndx = 0;

  // while checking certs in config file, break if cert found or if no more certs available
  //                                      continue if this cert is not ok and more certs available
  while ( thisCertUri[0] != '\0' ) {
    certIndx = thiscertsel->certIndx;
    char *certFile = thisCertUri;
    // strip off uri scheme "file://"
    if ( strncmp( certFile, FILESCHEME, sizeof(FILESCHEME)-1 ) == 0 ) {
      certFile += (sizeof(FILESCHEME)-1);
    }

    // get date from file
    struct stat fileStat;
    int statret = stat( certFile, &fileStat );

    if ( statret != 0 ) {  // file error
      DEBUG_LOG( " %s:cert file not found [%s]\n", __FUNCTION__, certFile );
      EXTRA_DEBUG_LOG( " %s:cert file not found, clear stat [%u], continue?\n", __FUNCTION__, certIndx );

      thiscertsel->certStat[certIndx] = CERTSTAT_NOTBAD; // file does not exist, clear certstat for if it appears again

      findval = certsel_findNextCert( thiscertsel );  // next cert
      if ( findval != certselectorOk ) {
        EXTRA_DEBUG_LOG( " %s:next cert not found (%u)\n", __FUNCTION__, findval );
        retval = certselectorFileNotFound;
        break; // give up
      }
      // next cert
      thisCertUri = thiscertsel->certUri;
      thisCertCredRef = thiscertsel->certCredRef;
      continue; // evaluate this next cert

    // end if file error
    // if file date is not the same as the "bad" date, try it again, break
    } else if ( thiscertsel->certStat[certIndx] != CERTSTAT_NOTBAD ) {

      // file exists, check time stamp
      time_t modTime = fileStat.st_mtime;
      EXTRA_DEBUG_LOG( " %s:cert file was bad[%s|%lu]\n", __FUNCTION__, certFile, (unsigned long)modTime );

      // file was bad, see if it has changed
      unsigned long badTime = thiscertsel->certStat[certIndx];
      if ( badTime == modTime ) {
        // file did not change, find next cert, continue
        EXTRA_DEBUG_LOG( " %s:cert file unchanged[%s|%lu]\n", __FUNCTION__, certFile, (unsigned long)modTime );

        retval = certsel_findNextCert( thiscertsel ); // next cert
        if ( retval != certselectorOk ) {
          EXTRA_DEBUG_LOG( " %s:next cert not found (%u)\n", __FUNCTION__, retval );
          retval = certselectorFileNotFound;
          break; // give up
        }

        thisCertUri = thiscertsel->certUri;
        thisCertCredRef = thiscertsel->certCredRef;
        EXTRA_DEBUG_LOG( " %s:next cert found (%s|%s), continuing\n", __FUNCTION__, thisCertUri, thisCertCredRef );
        continue;  // evaluate this next cert
      } else { // file was marked bad, but has changed

        // file did change, clear bad status and try it again
        certIndx = thiscertsel->certIndx;  // index may have changed
        EXTRA_DEBUG_LOG( " %s:cert file changed from [%s|%lu], clear stat [%u], breaking\n", __FUNCTION__, certFile, badTime, certIndx );
        thiscertsel->certStat[certIndx] = CERTSTAT_NOTBAD;  // cert status is unknown
      } // end else file changed
      thisCertUri = thiscertsel->certUri;
      thisCertCredRef = thiscertsel->certCredRef;
      retval = certselectorOk;
      // drop down and get passcode, then break;
    } else { // found the file that's not marked bad
      EXTRA_DEBUG_LOG( " %s:file not marked bad\n", __FUNCTION__ );
      retval = certselectorOk;
    }

    if ( retval == certselectorOk ) {
      EXTRA_DEBUG_LOG( " %s:get passcode (%u)\n", __FUNCTION__, retval );
      // file exists and is not the same as bad (or was not marked as bad), so get the passcode and return them
      char *pc = NULL;
      size_t pcsz = 0;
      retval = certselectorFileError; // look for cred file, error out if not found
      if ( rdkconfig_getStr( &pc, &pcsz, thisCertCredRef ) == RDKCONFIG_OK ) {
        if ( pc != NULL ) {
          // don't include any newline at end and don't add an additional null terminator
          if ( pc[pcsz-2] == '\n' ) {
            pc[pcsz-2] = '\0';
            --pcsz;
          }

          if ( pcsz < (sizeof(thiscertsel->certPass)-1) ) {
            memcpy( thiscertsel->certPass, pc, pcsz );
            thiscertsel->certPass[pcsz] = '\0';  // data coming in does not assume string so need to null terminate
            rdkconfig_freeStr( &pc, pcsz );
            retval = certselectorOk; // found it
            EXTRA_DEBUG_LOG( " %s:got the passcode\n", __FUNCTION__ );
            break; // found it, finish up
          } else {
            ERROR_LOG( " %s:pc did not fit (%zu)\n", __FUNCTION__, pcsz );
            rdkconfig_freeStr( &pc, pcsz );
          }
        } // pc not null
      } // if rdkconfig_get is ok

      DEBUG_LOG( " %s:credential reference not found (%u)\n", __FUNCTION__, retval );
      // could not retrieve the passcode, get next cert
      retval = certsel_findNextCert( thiscertsel );
      if ( retval != certselectorOk ) {
        EXTRA_DEBUG_LOG( " %s:next cert not found (%u)\n", __FUNCTION__, retval );
        retval = certselectorFileNotFound;
        break; // give up
      }
      // drop down and continue

    } // end if cert ok so far

    thisCertUri = thiscertsel->certUri;
    thisCertCredRef = thiscertsel->certCredRef;
    // continue;

  } // end while

  if ( retval == certselectorOk ) {
    *certUri = thiscertsel->certUri;
    *certPass = thiscertsel->certPass;
    thiscertsel->state = cssReadyToCheckCert;

    if ( thiscertsel->certStat[certIndx] != CERTSTAT_NOTBAD ) {
      ERROR_LOG( " %s:INTERNAL ERROR: current stat should not be %lu\n", __FUNCTION__,  thiscertsel->certStat[certIndx] );
    }
    EXTRA_DEBUG_LOG( " %s:returning [%s:%s] index [%u]\n", __FUNCTION__, thiscertsel->certUri, "*****", certIndx );
  }
  EXTRA_DEBUG_LOG( " %s:returning %d\n", __FUNCTION__, retval );
  return retval;
} // rdkcertselector_getCert( )


#define CURL_SUCCESS 0

/**
 *  Sets status of MTLS connection using the cert.
 *  API will wipe the passcode for the cert used for connection.
 *  In @param Handle; cert instance object handle for the connection.
 *  In @param usgType; usage type MTLS/STATERED/D2D
 *  In @param connectStat; connection status using the cert.
 *  @return "rdkcertselector_retry_t"; 0/NORETRY and 1/RETRY for retrying with next cert.
 *  if the cert used for connection is a staic fallabck cert, then API should return NORETRY.
 *  if the cert is an dynamic operational cert, and connection failed with cert/tls errors.
**/
rdkcertselectorRetry_t rdkcertselector_setCurlStatus( rdkcertselector_h thiscertsel, unsigned int curlStat, const char *logEndpoint ) {

  if ( thiscertsel == NULL ) {
    ERROR_LOG( " %s:null argument\n", __FUNCTION__ );
    return NO_RETRY;
  }

  if ( thiscertsel->state != cssReadyToCheckCert ) {
    ERROR_LOG( " %s:unexpected state, %d!=%d\n", __FUNCTION__, thiscertsel->state, cssReadyToCheckCert );
    return RETRY_ERROR;
  }

  // always wipe the password
  memwipe( thiscertsel->certPass, sizeof( thiscertsel->certPass ) );

  uint16_t certIndx = thiscertsel->certIndx;
  if ( certIndx >= LIST_MAX ) {
    ERROR_LOG( " %s:INTERNAL ERROR: certIndx [%u]\n", __FUNCTION__, certIndx );
    return RETRY_ERROR;
  }

  if ( curlStat == CURL_SUCCESS ) {

    //DEBUG_LOG( "curl SUCCESS [%s]\n", logEndpoint!=NULL?logEndpoint:"" );
    EXTRA_DEBUG_LOG( " %s:good status, indx [%u]\n", __FUNCTION__, certIndx );
    thiscertsel->certStat[certIndx] = CERTSTAT_NOTBAD;

    if ( certIndx != 0 ) {
      EXTRA_DEBUG_LOG( " %s:resetting indx, was [%u]\n", __FUNCTION__, certIndx );
      thiscertsel->certIndx = 0;

      // get info for first cert
      rdkcertselectorStatus_t certstat = certsel_findCert( thiscertsel );

      if ( certstat != certselectorOk ) {
        ERROR_LOG( " %s:INTERNAL ERROR: cert not found; RETRY_ERROR\n", __FUNCTION__ );
        thiscertsel->state = cssNoCert;
        return RETRY_ERROR;
      }
    }

    EXTRA_DEBUG_LOG( " %s:good status; NO_RETRY\n", __FUNCTION__ );
    thiscertsel->state = cssReadyToGiveCert;
    return NO_RETRY;

  } else if ( certsel_chkCertError( curlStat ) == TRY_ANOTHER ) {
    // cert error needs to be logged
    ERROR_LOG( "curl cert error (%u) [%s]\n", curlStat, logEndpoint!=NULL?logEndpoint:"" );
    EXTRA_DEBUG_LOG( " %s:curl cert error [%u]\n", __FUNCTION__, curlStat );

    char *certFile = thiscertsel->certUri;
    // strip off uri scheme "file://"
    if ( strncmp( certFile, FILESCHEME, sizeof(FILESCHEME)-1 ) == 0 ) {
      certFile += (sizeof(FILESCHEME)-1);
    }

    // mark stat with file date
    unsigned long modtime = filetime( certFile );
    thiscertsel->certStat[certIndx] = (modtime!=0) ? modtime : CERTSTAT_NOTBAD;

    // find next cert; need to know if another one is available or not
    rdkcertselectorStatus_t retval = certsel_findNextCert( thiscertsel );
    if ( retval != certselectorOk ) {
      // if no cert, reset indx to 0; set state to noCert; return no retry
      EXTRA_DEBUG_LOG( " %s:next cert not found; NO_RETRY\n", __FUNCTION__ );
      thiscertsel->certIndx = 0;
      thiscertsel->state = cssNoCert;
      return NO_RETRY;
    }

    // if next cert found, set state and try another
    EXTRA_DEBUG_LOG( " %s:cert found, TRY_ANOTHER\n", __FUNCTION__ );
    thiscertsel->state = cssReadyToGiveCert;
    return TRY_ANOTHER;

  } else {
    DEBUG_LOG( "curl error (%u) [%s]\n", curlStat, logEndpoint!=NULL?logEndpoint:"" );
    EXTRA_DEBUG_LOG( " %s:curl non-cert error [%u]; NO_RETRY\n", __FUNCTION__, curlStat );
    thiscertsel->state = cssReadyToGiveCert;
    return NO_RETRY;
  }

  return NO_RETRY;
} // rdkcertselector_setCurlStatus( )


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// INTERNAL STATIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// fix this to always wipe without getting optimized out
static void memwipe( volatile void *mem, size_t sz ) {
  memset( (void *)mem, 0, sz );
}

#define MAX_GRP_CNT 10  // can fit this many groups on one line of config file

// includesChars - check if a char string includes at least one of the two chars provided
// ch1 or ch2 can be zero so that only the other char is searched for
// return 1(true) or 0(false)
static int includesChars( const char *str, char ch1, char ch2 ) {
  if ( str == NULL ) return 0;
  while (*str != '\0' ) {
    if (*str == ch1 || *str == ch2) {
      return 1;
    }
    str++;
  }
  return 0;
} // includesChars( )

// find cert based on info in the certsel instance
// use config file path to open file, search for the certIndx'th instance of certGroup in the file
// update the certUri and certCredRef fields, which will be used by the get function
static rdkcertselectorStatus_t certsel_findCert( rdkcertselector_h thiscertsel ) {
  if ( thiscertsel == NULL ) {
    DEBUG_LOG( " %s:null argument\n", __FUNCTION__ );
    return certselectorBadPointer;
  }
  rdkcertselectorStatus_t retval = certselectorGeneralFailure;

  char *certSelCfg = thiscertsel->certSelPath;
  char *certGroup = thiscertsel->certGroup;
  if ( certSelCfg[0] == '\0' || certGroup[0] == '\0' ) {
    ERROR_LOG( " %s:argument error [%s|%s]\n", __FUNCTION__, certSelCfg, certGroup );
    return certselectorBadArgument;
  }
  size_t grplen = strnlen( certGroup, sizeof( thiscertsel->certGroup ) );

  // have we surpassed the max number of certs?
  uint16_t certIndx = thiscertsel->certIndx;
  if ( certIndx >= LIST_MAX ) {
    DEBUG_LOG( " %s:cert index beyond max (%d) for %s\n", __FUNCTION__, LIST_MAX, thiscertsel->certGroup );
    return certselectorFileNotFound;
  }

  FILE *cfgfp = fopen( certSelCfg, "r" );
  if ( cfgfp == NULL) {
    ERROR_LOG( " %s:config file, %s, not found\n", __FUNCTION__, certSelCfg );
    return certselectorFileNotFound;
  }

  uint16_t loopIndx = 0;
  char cfgline[MAX_LINE_LENGTH+1]; // one extra to check for trunctation
  char *cfgfield = NULL, *cfggrp = NULL;
  char *savetok_f, *savetok_g;

  // config file fields as follows:
  // <group>,<label>,<type>,<uri>,<credref>
  // look for group in field 1 and then on match store fields 4 and 5

  cfgline[MAX_LINE_LENGTH-1] = '\0'; // if this bytes gets overwritten, then line was too long

  while ( fgets( cfgline, sizeof(cfgline), cfgfp ) ) {

    // check if line from file was truncated
    if ( cfgline[MAX_LINE_LENGTH-1] != '\0' ) {
      ERROR_LOG( " %s: config line too long (%c)\n", __FUNCTION__, cfgline[MAX_LINE_LENGTH-1] );
      retval = certselectorFileError;
      break;
    }

    // remove terminal newline
    char *nl = strchr( cfgline, '\n' );
    if ( nl != NULL ) *nl = '\0';

    // look for cert group in first field
    // do not allow unexpected whitespace

    cfgfield = strtok_r( cfgline, DELIM_STR, &savetok_f ); // 1st field is group

    if ( cfgfield != NULL ) {
      // look for group in first field
      int maxcnt = MAX_GRP_CNT;
      while ( NULL != ( cfggrp = strtok_r( cfgfield, GRPDELIM_STR, &savetok_g ) ) ) {
        if ( strncmp( cfggrp, certGroup, grplen+1 ) == 0 ) {
          break;
        }
        if ( --maxcnt <= 0 ) {
          ERROR_LOG( " %s:get maxcnt reached\n", __FUNCTION__ );
          cfggrp = NULL;
          break;
        }
        cfgfield = NULL; // next strtok_r needs to continue on
      }
    }
    if ( cfggrp != NULL ) { // it will be null if it didn't match any
      // matches, is it correct index?
      if ( loopIndx == certIndx ) {

        // This looks like the right one, check format and extract cert info

        // skip fields 2=label and 3=type
        cfgfield = strtok_r( NULL, DELIM_STR, &savetok_f ); // skip 2nd field
        if ( cfgfield != NULL ) {
          cfgfield = strtok_r( NULL, DELIM_STR, &savetok_f ); // skip 3rd field
        }
        if ( cfgfield == NULL ) {
          ERROR_LOG( " %s:missing fields (2/3)\n", __FUNCTION__ );
          retval = certselectorFileError;
          break;
        }

        // copy uri and cred reference fields into object
        // an error here is probably a corruption of the config file
        cfgfield = strtok_r( NULL, DELIM_STR, &savetok_f ); // 4th field is URI
        if ( cfgfield != NULL ) {
          size_t fieldlen = strlen( cfgfield );
          if ( fieldlen < sizeof(thiscertsel->certUri)-1 ) {
            strcpy( thiscertsel->certUri, cfgfield );
            EXTRA_DEBUG_LOG( " %s: uri [%s]\n", __FUNCTION__, thiscertsel->certUri );
            cfgfield = strtok_r( NULL, DELIM_STR, &savetok_f ); // 5th field is Cred reference
            if ( cfgfield != NULL ) {
              fieldlen = strlen( cfgfield );
              if ( fieldlen < sizeof( thiscertsel->certCredRef)-1 ) {
                strcpy( thiscertsel->certCredRef, cfgfield );
                EXTRA_DEBUG_LOG( " %s: credref [%s]\n", __FUNCTION__, thiscertsel->certCredRef );
              } else {
                cfgfield = NULL; // 5th field error
                thiscertsel->certUri[0] = '\0';
              }
            }
          } else {
            cfgfield = NULL; // 4th field error
          }
        }
        // check for error
        if ( cfgfield == NULL ) {
          ERROR_LOG( " %s:missing fields (4/5)\n", __FUNCTION__ );
          retval = certselectorFileError;
          break;
        }

        // found one and saved the cert info
        retval = certselectorOk;
        break;
      } // if correct indx

      // correct group but not correct index so increment index and keep looking
      loopIndx++;
    } // end if matches group

  } // end while

  fclose( cfgfp );

  if ( retval == certselectorGeneralFailure ) {
    EXTRA_DEBUG_LOG( " %s:match not found for %s\n", __FUNCTION__, certGroup );
    retval = certselectorFileNotFound;
  }

  return retval;
} // certsel_findCert( rdkcertselector_h thiscertsel )

// find next cert based on info in the certsel instance
// increment index and clear previous uri and credref, then
// use config file path to open file, search for the certIndx'th instance of certGroup in the file
// update the certUri and certCredRef fields, which will be used by the get function
static rdkcertselectorStatus_t certsel_findNextCert( rdkcertselector_h thiscertsel ) {
  if ( thiscertsel == NULL ) {
    DEBUG_LOG( " %s:null argument\n", __FUNCTION__ );
    return certselectorBadPointer;
  }
  // next cert
  thiscertsel->certIndx++;
  thiscertsel->certUri[0] = '\0';
  thiscertsel->certCredRef[0] = '\0';

  // with index increment, find the cert
  return certsel_findCert( thiscertsel );
}


#define countof(array) (sizeof(array) / sizeof(array[0]))

static const int cert_errors[] = { 35,53,54,58,59,66,80,83,90,91 };
// 35 SSL connect error. The SSL handshaking failed
// 53 SSL crypto engine not found
// 54 Cannot set SSL crypto engine as default
// 58 Problem with the local certificate
// 59 Couldn't use specified SSL cipher
// 66 Failed to initialize SSL Engine
// 80 Failed to shut down the SSL connection
// 83 Issuer check failed
// 90 SSL public key does not matched pinned public key
// 91 Invalid SSL certificate status

// check curl return code for cert error
static rdkcertselectorRetry_t certsel_chkCertError( int curlStat ) {
  int indx;
  rdkcertselectorRetry_t retval = NO_RETRY;
  for ( indx=0; indx<countof(cert_errors); indx++ ) {
    if ( curlStat == cert_errors[indx] ) {
      retval = TRY_ANOTHER;
      break;
    } else if ( curlStat < cert_errors[indx] ) {
      break;
    }
  }
  return retval;
}

// get the file date in seconds since epoc or return 0 on error
static unsigned long filetime( const char *fname ) {
  unsigned long retval = 0;
  // get date from file
  struct stat fileStat;
  int statret = stat( fname, &fileStat );
  if ( statret == 0 ) {
    time_t modTime = fileStat.st_mtime;
    retval = (unsigned long)modTime;
  }
  return retval;
}


#if defined(UNIT_TESTS) || defined(GTEST_ENABLE)
#include "unit_test.h"

#define UTDIR "./ut"
#define CERTSEL_CFG UTDIR "/tst1certsel.cfg"
#define HROT_PROP UTDIR "/tst1hrot.properties"
#define HROT_PROP2 UTDIR "/tst2hrot.properties"
#define HROT_PROP_BAD UTDIR "/bad3hrot.properties" // bad format
#define HROT_PROP_LONG UTDIR "/long4hrot.properties" // long line
#define DEF_HROT_PROP UTDIR "/hrot.properties"

#define GRP1 "TSTGRP1"
#define GRP2 "TSTGRP2"
#define GRP3 "TSTGRP3"
#define GRP10 "TSTGRP10" // pc not found
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

#define GETSZ 50
// rdkconfig_getStr - get string credential, allocate space, fill buffer
int rdkconfig_getStr( char **sbuff, size_t *sbuffsz, const char *refname ) { // MOCK
  int retval = RDKCONFIG_OK;
  char *membuff = (char *)malloc( GETSZ );
  if ( membuff == NULL ) {
    return RDKCONFIG_FAIL;
  }
  memset( membuff, '.', GETSZ );
  if ( strcmp( refname, UTCRED1 ) == 0 ) {
    strcpy( membuff, UTPASS1 );
  } else if ( strcmp( refname, UTCRED2 ) == 0 ) {
    strcpy( membuff, UTPASS2 );
    // passcode sometimes ends with \n, test case where it should be removed
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
    *sbuffsz = strlen( (char *)membuff )+1; // buffer size includes null terminator    
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

// initialize or reinitialize a certsel test object
static void ut_initcs( rdkcertselector_t *tstcs ) {
  UT_NOTNULL( tstcs ); // memory error
  tstcs->reserved1 = CHK_RESERVED1;
  strncpy( tstcs->certSelPath, certsel_path, PATH_MAX );
  tstcs->certSelPath[ PATH_MAX-1 ] = '\0';
  strncpy( tstcs->certGroup, GRP1, PARAM_MAX );
  tstcs->certGroup[ PARAM_MAX-1 ] = '\0';
  tstcs->certIndx = 0;
  tstcs->certUri[0] = tstcs->certCredRef[0] = tstcs->certPass[0] = '\0';
  memset( tstcs->certStat, 0, sizeof(tstcs->certStat) );
}

// allocate and initialize a certsel test object
// this is used until rdkcertselector_new is fully tested
static rdkcertselector_t *ut_newcs( void ) {
  rdkcertselector_t *tstcs = (rdkcertselector_t *)calloc( 1, sizeof(rdkcertselector_t) );
  UT_NOTNULL( tstcs ); // memory error
  ut_initcs( tstcs );

  return tstcs;
}

static char statstr[PARAM_MAX] = "";
char *ut_statstr( rdkcertselector_h cs ) {
  sprintf( statstr, "%ld|%ld|%ld|%ld|%ld|%ld",
           cs->certStat[0],cs->certStat[1],cs->certStat[2],cs->certStat[3],cs->certStat[4],cs->certStat[5]);
  return statstr;
}

static void ut_printcertsel( rdkcertselector_h cs ) {
  fprintf( stderr, "*rdkcertsel_t:\n");
  fprintf( stderr, "* certSelPath[%s], certGroup[%s]\n", cs->certSelPath, cs->certGroup );
  fprintf( stderr, "* certUri[%s], certCredRef[%s], certPass[%s]\n", cs->certUri, cs->certCredRef, cs->certPass );
  fprintf( stderr, "* hrotEngine[%s],certIndx[%u], state[%u], certStat[%s], reserved1[%lx]\n",
                      cs->hrotEngine, cs->certIndx, cs->state, ut_statstr( cs ), cs->reserved1 );
}

// SEQUENCE TESTS
/*
sequence test cases
1. first goes bad; uses second
   next try skips first
2. second goes bad; uses first;
   then first goes bad; uses third
   next try skips first and second
3. first goes bad; uses second; then first restored then uses first
   next try uses first
4. first is missing and second goes bad; uses third; then second restored then uses second
   next try skips first
   then first restored then uses first
   next try uses first
*/
// ut_getThenSet - repeated sequence to test cert sel flow
// returns true(1) or false(0)
// call from UT_TST( ut_getThenSet( ... ) );
static int ut_getThenSet( rdkcertselector_h thiscertsel, unsigned int curlStat,
                              const char *expUri, const char *expPass, rdkcertselectorRetry_t expRetry ) {
  rdkcertselectorStatus_t csstat1;
  char *certUri, *certPass;
  csstat1 = rdkcertselector_getCert( thiscertsel, &certUri, &certPass );
  if ( csstat1 != certselectorOk ) {
    DEBUG_LOG( "%s:getCert return error (%d!=%d)j\n", __FUNCTION__, csstat1, certselectorOk );
    return 0;
  }
  if ( strcmp( certUri, expUri ) != 0 ) {
    DEBUG_LOG( "%s:getCert uri error (%s!=%s)j\n", __FUNCTION__, certUri, expUri );
    return 0;
  }
  if ( strcmp( certPass, expPass ) != 0 ) {
    DEBUG_LOG( "%s:getCert pass error (%s!=%s)j\n", __FUNCTION__, certPass, expPass );
    return 0;
  }
  char *eng = rdkcertselector_getEngine( thiscertsel );
  const char *engdef="e4tstdef";
  if ( eng!=NULL && strcmp( eng, engdef ) != 0 ) {
    DEBUG_LOG( "%s:getEngine error (%s!=%s)j\n", __FUNCTION__, eng, engdef );
    return 0;
  }
  rdkcertselectorRetry_t retry;
  retry = rdkcertselector_setCurlStatus( thiscertsel, curlStat, "https://getThenSet" );
  if ( thiscertsel->certPass[0] != '\0' && thiscertsel->certPass[1] != '\0' ) {
    DEBUG_LOG( "%s:setCurlStatus pass not wiped (%s)j\n", __FUNCTION__, certPass );
    return 0;
  }
  if ( retry != expRetry ) {
    DEBUG_LOG( "%s:getCurlStatus return error (%d!=%d)j\n", __FUNCTION__, retry, expRetry );
    return 0;
  }
  return 1; // results as expected
}
#ifndef GTEST_ENABLE
// unit tests for static rdkcertselectorRetry_t certsel_chkCertError( int curlStat );
// cert errors, see above: cert_errors[] = { 35,53,54,58,59,66,80,83,90,91 };
static void ut_certsel_chkCertError( void ) {
  UT_BEGIN( __FUNCTION__ );

  int code;
  UT_INTCMP( certsel_chkCertError( 0 ), NO_RETRY );
  for ( code=1; code<35; code++ ) {
    UT_INTCMP( certsel_chkCertError( code ), NO_RETRY );
  }
  UT_INTCMP( certsel_chkCertError( 35 ), TRY_ANOTHER );
  for ( code=36; code<53; code++ ) {
    UT_INTCMP( certsel_chkCertError( code ), NO_RETRY );
  }
  UT_INTCMP( certsel_chkCertError( 53 ), TRY_ANOTHER );
  UT_INTCMP( certsel_chkCertError( 54 ), TRY_ANOTHER );
  // ...
  UT_INTCMP( certsel_chkCertError( 58 ), TRY_ANOTHER );
  UT_INTCMP( certsel_chkCertError( 59 ), TRY_ANOTHER );
  UT_INTCMP( certsel_chkCertError( 66 ), TRY_ANOTHER );
  // ...
  UT_INTCMP( certsel_chkCertError( 80 ), TRY_ANOTHER );
  UT_INTCMP( certsel_chkCertError( 81 ), NO_RETRY );
  UT_INTCMP( certsel_chkCertError( 82 ), NO_RETRY );
  UT_INTCMP( certsel_chkCertError( 83 ), TRY_ANOTHER );
  for ( code=84; code<90; code++ ) {
    UT_INTCMP( certsel_chkCertError( code ), NO_RETRY );
  }
  UT_INTCMP( certsel_chkCertError( 90 ), TRY_ANOTHER );
  UT_INTCMP( certsel_chkCertError( 91 ), TRY_ANOTHER );
  for ( code=92; code<200; code++ ) {
    UT_INTCMP( certsel_chkCertError( code ), NO_RETRY );
  }
  UT_END( __FUNCTION__ );
}

// Unit tests for functions

// unit tests for static int includesChars( const char *str, char ch1, char ch2 )
static void ut_includesChars( void ) {
  UT_BEGIN( __FUNCTION__ );
  // no match
  UT_FALSE( includesChars( NULL, 0, 0 ) );
  UT_FALSE( includesChars( "123456", 0, 0 ) );
  UT_FALSE( includesChars( "123456", 'x', 0 ) );
  UT_FALSE( includesChars( "123456", 0, '7' ) );
  UT_FALSE( includesChars( "123456", 'x', '7' ) );
  // 1 match
  UT_TRUE( includesChars( "123456", '1', 0 ) );
  UT_TRUE( includesChars( "123456", 0, '1' ) );
  UT_TRUE( includesChars( "123456", '6', 0 ) );
  UT_TRUE( includesChars( "123456", 0, '6' ) );
  UT_TRUE( includesChars( "123456", '1', '7' ) );
  UT_TRUE( includesChars( "123456", '7', '1' ) );
  UT_TRUE( includesChars( "123456", '6', '7' ) );
  UT_TRUE( includesChars( "123456", 'x', '6' ) );
  // 2 match
  UT_TRUE( includesChars( "123456", '1', '2' ) );
  UT_TRUE( includesChars( "123456", '5', '6' ) );
  UT_TRUE( includesChars( "123456", '1', '6' ) );
  // realistic uses
  char *grp1 = "GRP1";
  char *grp2 = "GRP2";
  char *badgrp1 = "GRP1,GRP2";
  char *badgrp2 = "GRP1|GRP2";
  UT_FALSE( includesChars( grp1, ',', 0 ) );
  UT_FALSE( includesChars( grp1, 0, ',' ) );
  UT_FALSE( includesChars( grp1, ',', '|' ) );
  UT_FALSE( includesChars( grp2, '|', 0 ) );
  UT_FALSE( includesChars( grp2, 0, '|' ) );
  UT_FALSE( includesChars( grp2, ',', '|' ) );
  UT_TRUE( includesChars( badgrp1, ',', '|' ) );
  UT_TRUE( includesChars( badgrp2, ',', '|' ) );

  UT_END( __FUNCTION__ );
} // static void ut_includesChars( void )

// unit tests for static rdkcertselectorStatus_t certsel_findCert( rdkcertselector_h thiscertsel )
static void ut_certsel_findCert( void ) {
  UT_BEGIN( __FUNCTION__ );

  // create certsel object for testing
  rdkcertselector_h tstcs = ut_newcs( );
  UT_STRCMP( tstcs->certUri, "", PATH_MAX );
  UT_STRCMP( tstcs->certCredRef, "", PARAM_MAX );

  UT_LOG( "Expect 4 error messages for arguments" );
  UT_INTCMP( certsel_findCert( NULL ), certselectorBadPointer );
  tstcs->certSelPath[0] = '\0';
  UT_INTCMP( certsel_findCert( tstcs ), certselectorBadArgument );
  ut_initcs( tstcs );
  tstcs->certGroup[0] = '\0';
  UT_INTCMP( certsel_findCert( tstcs ), certselectorBadArgument );
  ut_initcs( tstcs );
  tstcs->certSelPath[0] = 'X';
  UT_INTCMP( certsel_findCert( tstcs ), certselectorFileNotFound );
  UT_LOG( "Expect 5 error messages for config file format" );
  ut_initcs( tstcs );
  strncpy( tstcs->certSelPath, UTDIR "/tst1toolong.cfg", PATH_MAX );
  UT_INTCMP( certsel_findCert( tstcs ), certselectorFileError );
  ut_initcs( tstcs );
  strncpy( tstcs->certSelPath, UTDIR "/tst1miss2.cfg", PATH_MAX );
  UT_INTCMP( certsel_findCert( tstcs ), certselectorFileError );
  ut_initcs( tstcs );
  strncpy( tstcs->certSelPath, UTDIR "/tst1miss3.cfg", PATH_MAX );
  UT_INTCMP( certsel_findCert( tstcs ), certselectorFileError );
  ut_initcs( tstcs );
  strncpy( tstcs->certSelPath, UTDIR "/tst1miss4.cfg", PATH_MAX );
  UT_INTCMP( certsel_findCert( tstcs ), certselectorFileError );
  ut_initcs( tstcs );
  strncpy( tstcs->certSelPath, UTDIR "/tst1miss5.cfg", PATH_MAX );
  UT_INTCMP( certsel_findCert( tstcs ), certselectorFileError );
  // beyond max
  UT_LOG( "Expect 1 error messages for max" );
  ut_initcs( tstcs );
  tstcs->certIndx = LIST_MAX;
  UT_INTCMP( certsel_findCert( tstcs ), certselectorFileNotFound );

  UT_LOG( "Valid" );
  // find index 0
  ut_initcs( tstcs );
  UT_INTCMP( certsel_findCert( tstcs ), certselectorOk );
  UT_STRCMP( tstcs->certUri, FILESCHEME UTCERT1, PATH_MAX );
  UT_STRCMP( tstcs->certCredRef, "pc1", PARAM_MAX );

  // find index 1
  ut_initcs( tstcs );
  tstcs->certIndx = 1;
  UT_INTCMP( certsel_findCert( tstcs ), certselectorOk );
  UT_STRCMP( tstcs->certUri, FILESCHEME UTCERT2, PATH_MAX );
  UT_STRCMP( tstcs->certCredRef, "pc2", PARAM_MAX );

  // find index 2
  ut_initcs( tstcs );
  tstcs->certIndx = 2;
  UT_INTCMP( certsel_findCert( tstcs ), certselectorOk );
  UT_STRCMP( tstcs->certUri, "file://" UTCERT3, PATH_MAX );
  UT_STRCMP( tstcs->certCredRef, "pc3", PARAM_MAX );

  // can't find index 3
  ut_initcs( tstcs );
  tstcs->certIndx = 3;
  UT_INTCMP( certsel_findCert( tstcs ), certselectorFileNotFound );

  free( tstcs );

  UT_END( __FUNCTION__ );
} // ut_certsel_findCert( void )

static void ut_certsel_findNextCert( void ) {
  UT_BEGIN( __FUNCTION__ );

  rdkcertselector_h tstcs = ut_newcs( );

  UT_LOG( "Expect 2 error messages for arguments" );
  UT_INTCMP( certsel_findNextCert( NULL ), certselectorBadPointer );

  ut_initcs( tstcs );
  tstcs->certIndx = LIST_MAX-1;
  UT_INTCMP( certsel_findNextCert( tstcs ), certselectorFileNotFound );
  tstcs->certIndx = 0;

  UT_LOG( "Valid" );
  // find index 1
  UT_INTCMP( certsel_findNextCert( tstcs ), certselectorOk );
  UT_STRCMP( tstcs->certUri, "file://" UTCERT2, PATH_MAX );
  UT_STRCMP( tstcs->certCredRef, "pc2", PARAM_MAX );

  // find index 2
  UT_INTCMP( certsel_findNextCert( tstcs ), certselectorOk );
  UT_STRCMP( tstcs->certUri, "file://" UTCERT3, PATH_MAX );
  UT_STRCMP( tstcs->certCredRef, "pc3", PARAM_MAX );

  // can't find index 3
  //UT_LOG( "Expect 1 error messages for not found" );
  UT_INTCMP( certsel_findNextCert( tstcs ), certselectorFileNotFound );
  UT_STRCMP( tstcs->certUri, "", PATH_MAX );
  UT_STRCMP( tstcs->certCredRef, "", PARAM_MAX );

  rdkcertselector_free( &tstcs );
  UT_END( __FUNCTION__ );
}

// unit tests for void rdkcertselector_free( rdkcertselector_h **thiscertsel )
static void ut_certsel_free( void ) {
  UT_BEGIN( __FUNCTION__ );
  // the next call should not cause a fault
  rdkcertselector_free( NULL );
#ifdef CHECK_MEM_WIPE
  rdkcertselector_h tstcsh = ut_newcs( );
  rdkcertselector_h tstcsh2 = tstcsh; // used to check freed memory below
  UT_NOTNULL( tstcsh );
  tstcsh->certCredRef[0] = 'X';
  tstcsh->certPass[0] = 'Y';
  rdkcertselector_free( &tstcsh );
  UT_NULL( tstcsh );
  rdkcertselector_free( &tstcsh );  // second free is protected
  // make sure cred and pass were wiped
  // this creates a coverity error so once tested, it can be commented out
  UT_INTCMP( tstcsh2->certCredRef[0], 0 ); // warning, this is looking into deallocated space
  UT_INTCMP( tstcsh2->certPass[0], 0 ); // warning, this is looking into deallocated space
#endif // CHECK_MEM_WIPE
  UT_END( __FUNCTION__ );
}

// unit tests for rdkcertselector_h rdkcertselector_new(const char *certsel_path, const char *hrotprop_path, const char *cert_group )
static void ut_certsel_new( void ) {
  UT_BEGIN( __FUNCTION__ );

  DEBUG_LOG( "unit test setup: [%s] [%s]\n", certsel_path, hrotprop_path );

  rdkcertselector_h tstcs1 = NULL, tstcs2 = NULL;

  // bad arguments
  UT_LOG( "Expect 7 error messages for group" );
  UT_NULL( rdkcertselector_new( NULL, NULL, NULL ) );
  UT_NULL( rdkcertselector_new( NULL, NULL, "" ) );
  UT_NULL( rdkcertselector_new( NULL, NULL, "GRP1,GRP2" ) );
  UT_NULL( rdkcertselector_new( NULL, NULL, "GRP1|GRP2" ) );
  UT_NULL( rdkcertselector_new( NULL, NULL, "NOTHING" ) );
  UT_NULL( rdkcertselector_new( "doesnotexist.cfg", NULL, GRP1 ) );
  UT_NULL( rdkcertselector_new( LONGPATH, NULL, GRP1 ) );

  UT_LOG( "valid" );
  UT_NOTNULL( tstcs1 = rdkcertselector_new( NULL, NULL, GRP1 ) );
  rdkcertselector_free( &tstcs1 );

  // 2 different instances
  UT_NOTNULL( tstcs1 = rdkcertselector_new( DEFAULT_CONFIG, DEFAULT_HROT, GRP1 ) );
  UT_NOTNULL( tstcs2 = rdkcertselector_new( certsel_path, hrotprop_path, GRP1 ) );

  ut_printcertsel( tstcs1 );
  UT_INTCMP( tstcs1->reserved1, CHK_RESERVED1 );
  UT_STRCMP( tstcs1->certSelPath, DEFAULT_CONFIG_PATH, PATH_MAX );
  UT_STRCMP( tstcs1->certUri, "file://./ut/etc/ssl/certsel/tst1def.tmp", PATH_MAX );
  UT_STRCMP( tstcs1->certCredRef, "./ut/etc/ssl/certsel/pcdef", PARAM_MAX );
  UT_STRCMP( tstcs1->certPass, "", PARAM_MAX );
  UT_STRCMP( tstcs1->hrotEngine, "e4tstdef", PARAM_MAX );
  UT_INTCMP( tstcs1->state, cssReadyToGiveCert );
  UT_STRCMP( ut_statstr( tstcs1 ), "0|0|0|0|0|0", PARAM_MAX );

  ut_printcertsel( tstcs2 );
  UT_INTCMP( tstcs2->reserved1, CHK_RESERVED1 );
  UT_STRCMP( tstcs2->certSelPath, certsel_path, PATH_MAX );
  UT_STRCMP( tstcs2->certUri, "file://" UTCERT1, PATH_MAX );
  UT_STRCMP( tstcs2->certCredRef, "pc1", PARAM_MAX );
  UT_STRCMP( tstcs2->certPass, "", PARAM_MAX );
  UT_STRCMP( tstcs2->hrotEngine, "e4tst1", PARAM_MAX );
  UT_INTCMP( tstcs2->state, cssReadyToGiveCert );
  UT_STRCMP( ut_statstr( tstcs2 ), "0|0|0|0|0|0", PARAM_MAX );

  rdkcertselector_free( &tstcs1 );
  rdkcertselector_free( &tstcs2 );

  UT_NOTNULL( tstcs2 = rdkcertselector_new( certsel_path, HROT_PROP2, GRP1 ) ); // on 2nd line
  UT_STRCMP( tstcs2->hrotEngine, "e4tst1", PARAM_MAX );
  rdkcertselector_free( &tstcs2 );

  // valid new, but engine not set
  UT_NOTNULL( tstcs1 = rdkcertselector_new( DEFAULT_CONFIG, UTDIR "/doesnotexist.cfg", GRP1 ) );
  UT_STRCMP( tstcs1->hrotEngine, "", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );

  UT_NOTNULL( tstcs1 = rdkcertselector_new( certsel_path, HROT_PROP_BAD, GRP1 ) );
  UT_STRCMP( tstcs1->hrotEngine, "", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );
  UT_NOTNULL( tstcs1 = rdkcertselector_new( certsel_path, HROT_PROP_LONG, GRP1 ) );
  UT_STRCMP( tstcs1->hrotEngine, "", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );

  UT_END( __FUNCTION__ );
} // ut_certsel_new( void )


// unit tests for char *rdkcertselector_getEngine( rdkcertselector_h thiscertsel )
static void ut_rdkcertselector_getEngine( void ) {
  UT_BEGIN( __FUNCTION__ );
  UT_LOG( "Expect 3 error messages" );
  UT_NULL ( rdkcertselector_getEngine( NULL ) );
  rdkcertselector_h tstcs1 = NULL, tstcs2 = NULL;
  UT_NULL ( rdkcertselector_getEngine( tstcs1 ) );
  tstcs1 = rdkcertselector_new( certsel_path, hrotprop_path, GRP1 );
  UT_STRCMP( rdkcertselector_getEngine( tstcs1 ), "e4tst1", ENGINE_MAX );

  rdkcertselector_h badcs1 = rdkcertselector_new( certsel_path, HROT_PROP_BAD, GRP1 );
  UT_NULL( rdkcertselector_getEngine( badcs1 ) );
  rdkcertselector_free( &badcs1 );

  badcs1 = rdkcertselector_new( certsel_path, "/etc/cert/missingfile", GRP1 );
  UT_NULL( rdkcertselector_getEngine( badcs1 ) );
  rdkcertselector_free( &badcs1 );

  char *eng = rdkcertselector_getEngine( tstcs1 );
  UT_NOTNULL( eng );
  UT_STRCMP( eng, "e4tst1", ENGINE_MAX );
  rdkcertselector_free( &tstcs1 );

  tstcs1 = rdkcertselector_new( certsel_path, DEFAULT_HROT, GRP1 );
  eng = rdkcertselector_getEngine( tstcs1 );
  UT_STRCMP( eng, "e4tstdef", ENGINE_MAX );

  tstcs2 = rdkcertselector_new( certsel_path, hrotprop_path, GRP1 );
  eng = rdkcertselector_getEngine( tstcs2 );
  UT_STRCMP( eng, "e4tst1", ENGINE_MAX );

  rdkcertselector_free( &tstcs1 );
  rdkcertselector_free( &tstcs2 );
  UT_END( __FUNCTION__ );

} // end ut_rdkcertselector_getEngine( void )


// unit tests for rdkcertselectorStatus_t rdkcertselector_getCert( rdkcertselector_h thiscertsel, const char **certUri, const char **certPass )
static void ut_rdkcertselector_getCert( void ) {
  UT_BEGIN( __FUNCTION__ );

  UT_LOG( "Expect 6 error messages for arguments" );
  rdkcertselector_h tstcs1 = NULL;
  char *certUri = NULL, *certPass = NULL;
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorBadPointer );

  tstcs1 = rdkcertselector_new( DEFAULT_CONFIG, DEFAULT_HROT, GRP1 );
  UT_INTCMP( rdkcertselector_getCert( tstcs1, NULL, &certPass ), certselectorBadArgument );
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, NULL ), certselectorBadArgument );

  uint16_t save_state = tstcs1->state;
  tstcs1->state = cssUnknown;
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorGeneralFailure );
  tstcs1->state = save_state;

  char save_uri0 = tstcs1->certUri[0];
  tstcs1->certUri[0] = '\0';
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorBadArgument );
  UT_INTCMP( tstcs1->state, cssReadyToGiveCert );
  tstcs1->state = save_state;
  tstcs1->certUri[0] = save_uri0;

  char save_ref0 = tstcs1->certCredRef[0];
  tstcs1->certCredRef[0] = '\0';
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorBadArgument );
  UT_INTCMP( tstcs1->state, cssReadyToGiveCert );
  tstcs1->state = save_state;
  tstcs1->certCredRef[0] = save_ref0;
  rdkcertselector_free( &tstcs1 );

  // files in config do not exist, return error
  tstcs1 = rdkcertselector_new( certsel_path, DEFAULT_HROT, GRP1 );
  UT_SYSTEM0( "mv " UTCERT1 " ./ut/tstXfirst.tmp" );  // cert missing
  UT_SYSTEM0( "mv " UTCERT2 " ./ut/tstXsecond.tmp" );  // cert missing
  UT_SYSTEM0( "mv " UTCERT3 " ./ut/tstXthird.tmp" );  // cert missing
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorFileNotFound );
  rdkcertselector_free( &tstcs1 );

  // first cert marked as bad, second and third missing
  UT_SYSTEM0( "mv ./ut/tstXfirst.tmp " UTCERT1 );  // cert no longer missing
  tstcs1 = rdkcertselector_new( certsel_path, DEFAULT_HROT, GRP1 );
  tstcs1->certStat[0] = filetime( UTCERT1 ); // marked as bad
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorFileNotFound );
  UT_INTCMP( tstcs1->state, cssReadyToGiveCert );
  UT_INTCMP( tstcs1->certStat[0], filetime( UTCERT1 ) );
  UT_NULL( certUri );
  UT_NULL( certPass );
  rdkcertselector_free( &tstcs1 );

  // first cert marked as bad; second cert marked as bad; third missing
  UT_SYSTEM0( "mv ./ut/tstXsecond.tmp " UTCERT2 );  // cert no longer missing
  tstcs1 = rdkcertselector_new( certsel_path, DEFAULT_HROT, GRP1 );
  tstcs1->certStat[0] = filetime( UTCERT1 ); // marked as bad
  tstcs1->certStat[1] = filetime( UTCERT2 ); // marked as bad
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorFileNotFound );
  UT_INTCMP( tstcs1->state, cssReadyToGiveCert );
  UT_NULL( certUri );
  UT_NULL( certPass );
  rdkcertselector_free( &tstcs1 );

  // first cert marked as bad; second cert marked as bad; third cert marked as bad
  UT_SYSTEM0( "mv ./ut/tstXthird.tmp " UTCERT3 );  // cert no longer missing
  tstcs1 = rdkcertselector_new( certsel_path, DEFAULT_HROT, GRP1 );
  tstcs1->certStat[0] = filetime( UTCERT1 ); // marked as bad
  tstcs1->certStat[1] = filetime( UTCERT2 ); // marked as bad
  tstcs1->certStat[2] = filetime( UTCERT3 ); // marked as bad
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorFileNotFound );
  UT_INTCMP( tstcs1->state, cssReadyToGiveCert );
  UT_NULL( certUri );
  UT_NULL( certPass );
  rdkcertselector_free( &tstcs1 );

  UT_LOG( "Expect 1 error message for missing pc" );
  // cert found but pc not found
  tstcs1 = rdkcertselector_new( certsel_path, DEFAULT_HROT, GRP10 );
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorFileNotFound );
  UT_INTCMP( tstcs1->state, cssReadyToGiveCert );
  UT_NULL( certUri );
  UT_NULL( certPass );
  rdkcertselector_free( &tstcs1 );

  UT_LOG( "valid" );
  // first good
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorOk );
  UT_INTCMP( tstcs1->state, cssReadyToCheckCert );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1first.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc1pass", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );

  // first bad; second good
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  tstcs1->certStat[0] = filetime( UTCERT1 ); // marked as bad
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorOk );
  UT_INTCMP( tstcs1->state, cssReadyToCheckCert );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1second.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc2pass", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );

  // first bad; second bad; third good
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  tstcs1->certStat[0] = filetime( UTCERT1 ); // marked as bad
  tstcs1->certStat[1] = filetime( UTCERT2 ); // marked as bad
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorOk );
  UT_INTCMP( tstcs1->state, cssReadyToCheckCert );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1third.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc3pass", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );

  // first missing; second good
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  UT_SYSTEM0( "mv " UTCERT1 " ./ut/tstXfirst.tmp" );  // cert missing
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorOk );
  UT_INTCMP( tstcs1->state, cssReadyToCheckCert );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1second.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc2pass", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );

  // first missing; second missing; third good
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  UT_SYSTEM0( "mv " UTCERT2 " ./ut/tstXsecond.tmp" );  // cert missing
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorOk );
  UT_INTCMP( tstcs1->state, cssReadyToCheckCert );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1third.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc3pass", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );

  UT_SYSTEM0( "mv ./ut/tstXfirst.tmp " UTCERT1 );  // cert no longer missing
  UT_SYSTEM0( "mv ./ut/tstXsecond.tmp " UTCERT2 );  // cert no longer missing

  // group 3 uses the third cert from group 1
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP3 );
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1third.tmp", PARAM_MAX );
  UT_NOTNULL( certPass );
  UT_STRCMP( certPass, "pc3pass", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );

  // up to 10 groups in the first field
  UT_LOG( "multi group" );
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, "A1" );
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1alpha.tmp", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, "A2" );
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1alpha.tmp", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, "A4" );
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1alpha.tmp", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, "A7" );
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1alpha.tmp", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, "A9" );
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1alpha.tmp", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, "A10" );
  UT_INTCMP( rdkcertselector_getCert( tstcs1, &certUri, &certPass ), certselectorOk );
  UT_NOTNULL( certUri );
  UT_STRCMP( certUri, "file://./ut/tst1alpha.tmp", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );

  UT_END( __FUNCTION__ );
} // end ut_rdkcertselector_getCert( void )

// unit tests for rdkcertselectorRetry_t rdkcertselector_setCurlStatus( rdkcertselector_h thiscertsel, unsigned int curlStat )
static void ut_rdkcertselector_setCurlStatus( void ) {
  UT_BEGIN( __FUNCTION__ );

  rdkcertselector_h tstcs1 = NULL;

  UT_LOG( "Expect 5 error messages for arguments" );
  UT_INTCMP( rdkcertselector_setCurlStatus( NULL, CURL_SUCCESS, NULL ), NO_RETRY );
  UT_INTCMP( rdkcertselector_setCurlStatus( tstcs1, CURL_SUCCESS, NULL ), NO_RETRY );

  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  UT_INTCMP( rdkcertselector_setCurlStatus( tstcs1, CURL_SUCCESS, "https://n/a" ), RETRY_ERROR ); // wrong state

  tstcs1->state = cssReadyToCheckCert;
  tstcs1->certIndx = 6;
  UT_INTCMP( rdkcertselector_setCurlStatus( tstcs1, CURL_SUCCESS, "https://bad.index" ), RETRY_ERROR ); // bad index
  rdkcertselector_free( &tstcs1 );

  // next test, 2 bad certs, trying 3rd cert, but it goes bad and there are no more
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  tstcs1->state = cssReadyToCheckCert;
  tstcs1->certIndx = 2;
  tstcs1->certStat[0] = filetime( UTCERT1 );
  tstcs1->certStat[1] = filetime( UTCERT2 );
  tstcs1->certPass[0] = 'P';
  UT_INTCMP( tstcs1->certStat[2], CERTSTAT_NOTBAD );
  UT_INTCMP( rdkcertselector_setCurlStatus( tstcs1, CURLERR_LOCALCERT, "https://third.goes.bad" ), NO_RETRY );
  UT_INTDIFF( tstcs1->certStat[2], CERTSTAT_NOTBAD );
  UT_INTCMP( tstcs1->certPass[0], 0 ); // password wiped
  UT_INTCMP( tstcs1->certIndx, 0 );
  UT_STRCMP( tstcs1->certUri, "", PATH_MAX );
  UT_STRCMP( tstcs1->certCredRef, "", PARAM_MAX );
  rdkcertselector_free( &tstcs1 );

  UT_LOG( "valid" );
  // good curl status, was using indx 2, reset to indx 0
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  tstcs1->state = cssReadyToCheckCert;
  tstcs1->certStat[0] = filetime( UTCERT1 );
  tstcs1->certStat[1] = filetime( UTCERT2 );
  tstcs1->certStat[2] = filetime( UTCERT3 );
  tstcs1->certIndx = 2;
  tstcs1->certUri[0] = 'U';
  tstcs1->certCredRef[0] = 'C';
  tstcs1->certPass[0] = 'P';
  UT_INTCMP( rdkcertselector_setCurlStatus( tstcs1, CURL_SUCCESS, "https://third.is.good" ), NO_RETRY );
  UT_INTCMP( tstcs1->certStat[2], CERTSTAT_NOTBAD );
  UT_INTCMP( tstcs1->certIndx, 0 );
  UT_STRCMP( tstcs1->certUri, FILESCHEME UTCERT1, PATH_MAX );
  UT_STRCMP( tstcs1->certCredRef, UTCRED1, PARAM_MAX );
  UT_INTCMP( tstcs1->certPass[0], 0 ); // password wiped
  UT_INTCMP( tstcs1->certPass[1], 0 );
  UT_INTCMP( tstcs1->state, cssReadyToGiveCert );
  rdkcertselector_free( &tstcs1 );

  // good status, was already on indx 0 which was bad, now good
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  tstcs1->state = cssReadyToCheckCert;
  tstcs1->certStat[0] = filetime( UTCERT1 );
  UT_INTCMP( rdkcertselector_setCurlStatus( tstcs1, CURL_SUCCESS, "https://first.now.good" ), NO_RETRY );
  UT_INTCMP( tstcs1->certStat[0], CERTSTAT_NOTBAD );
  UT_INTCMP( tstcs1->certIndx, 0 );
  UT_STRCMP( tstcs1->certUri, FILESCHEME UTCERT1, PATH_MAX );
  UT_STRCMP( tstcs1->certCredRef, UTCRED1, PARAM_MAX );
  UT_INTCMP( tstcs1->certPass[0], 0 ); // password wiped
  UT_INTCMP( tstcs1->certPass[1], 0 );
  UT_INTCMP( tstcs1->state, cssReadyToGiveCert );
  rdkcertselector_free( &tstcs1 );

  // using first cert, but it goes bad, next one to try is the second cert
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  tstcs1->state = cssReadyToCheckCert;
  tstcs1->certPass[0] = 'P';
  UT_INTCMP( tstcs1->certStat[0], CERTSTAT_NOTBAD );
  UT_INTCMP( rdkcertselector_setCurlStatus( tstcs1, CURLERR_LOCALCERT, "https://first.goes.bad" ), TRY_ANOTHER );
  UT_INTDIFF( tstcs1->certStat[0], CERTSTAT_NOTBAD );
  UT_INTCMP( tstcs1->certPass[0], 0 ); // password wiped
  UT_INTCMP( tstcs1->certIndx, 1 );
  UT_STRCMP( tstcs1->certUri, FILESCHEME UTCERT2, PATH_MAX );
  UT_STRCMP( tstcs1->certCredRef, UTCRED2, PARAM_MAX );
  rdkcertselector_free( &tstcs1 );

  // non cert error
  tstcs1 = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  tstcs1->state = cssReadyToCheckCert;
  tstcs1->certPass[0] = 'P';
  UT_INTCMP( tstcs1->certStat[0], CERTSTAT_NOTBAD );
  UT_INTCMP( rdkcertselector_setCurlStatus( tstcs1, CURLERR_NONCERT, "https://noncert.error" ), NO_RETRY );
  UT_INTCMP( tstcs1->certStat[0], CERTSTAT_NOTBAD );
  UT_INTCMP( tstcs1->certPass[0], 0 ); // password wiped
  UT_INTCMP( tstcs1->certIndx, 0 );
  UT_STRCMP( tstcs1->certUri, FILESCHEME UTCERT1, PATH_MAX );
  UT_STRCMP( tstcs1->certCredRef, UTCRED1, PARAM_MAX );
  rdkcertselector_free( &tstcs1 );

  UT_END( __FUNCTION__ );
}

// SEQUENCE TESTS
/*
sequence test cases
1. first goes bad; uses second
   next try skips first
2. second goes bad; uses first;
   then first goes bad; uses third
   next try skips first and second
3. first goes bad; uses second; then first restored then uses first
   next try uses first
4. first is missing and second goes bad; uses third; then second restored then uses second
   next try skips first
   then first restored then uses first
   next try uses first
*/
#if defined(UNIT_TESTS) || defined(GTEST_ENABLE)
// ut_getThenSet - repeated sequence to test cert sel flow
// returns true(1) or false(0)
// call from UT_TST( ut_getThenSet( ... ) );
static int ut_getThenSet( rdkcertselector_h thiscertsel, unsigned int curlStat,
                              const char *expUri, const char *expPass, rdkcertselectorRetry_t expRetry ) {

  rdkcertselectorStatus_t csstat1;
  char *certUri, *certPass;
  csstat1 = rdkcertselector_getCert( thiscertsel, &certUri, &certPass );
  if ( csstat1 != certselectorOk ) {
    DEBUG_LOG( "getCert return error (%d!=%d)j\n", csstat1, certselectorOk );
    return 0;
  }
  if ( strcmp( certUri, expUri ) != 0 ) {
    DEBUG_LOG( "getCert uri error (%s!=%s)j\n", certUri, expUri );
    return 0;
  }
  if ( strcmp( certPass, expPass ) != 0 ) {
    DEBUG_LOG( "getCert pass error (%s!=%s)j\n", certPass, expPass );
    return 0;
  }
  char *eng = rdkcertselector_getEngine( thiscertsel );
  const char *engdef="e4tstdef";
  if ( eng!=NULL && strcmp( eng, engdef ) != 0 ) {
    DEBUG_LOG( "getEngine error (%s!=%s)j\n", eng, engdef );
    return 0;
  }

  rdkcertselectorRetry_t retry;
  retry = rdkcertselector_setCurlStatus( thiscertsel, curlStat, "https://getThenSet" );
  if ( thiscertsel->certPass[0] != '\0' && thiscertsel->certPass[1] != '\0' ) {
    DEBUG_LOG( "setCurlStatus pass not wiped (%s)j\n", certPass );
    return 0;
  }
  if ( retry != expRetry ) {
    DEBUG_LOG( "getCurlStatus return error (%d!=%d)j\n", retry, expRetry );
    return 0;
  }
  return 1; // results as expected
}
#endif

// sequence 1 : 1) first goes bad, uses second
//              2) next try skips first
static void ut_rdkcertselector_seq1( void ) {
  UT_BEGIN( __FUNCTION__ );
  UT_LOG( "seq1 1) first goes bad, uses second 2) skips first, uses second" );

  rdkcertselector_h seq1cs = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );

  // 1) first goes bad, uses second
  UT_TST( ut_getThenSet( seq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER ) );
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );

  // 2) next try skips first
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );

  rdkcertselector_free( &seq1cs );
  UT_END( __FUNCTION__ );
} // ut_rdkcertselector_seq1( void )


// sequence 2 : second is bad; uses first;
//              then first goes bad; uses third
//              next try skips first and second
static void ut_rdkcertselector_seq2( void ) {
  UT_BEGIN( __FUNCTION__ );
  UT_LOG( "seq2 1) second is bad, uses first; 2) first goes bad, uses third; 3) skips first and second, uses third" );

  rdkcertselector_h seq1cs = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );

  // 1) second is already marked as bad, but first is ok
  seq1cs->certStat[1] = filetime( UTCERT2 );
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY ) );

  // 2) first goes bad, uses third
  UT_TST( ut_getThenSet( seq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER ) );
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT3, UTPASS3, NO_RETRY ) );

  // 3) skips first and second, uses third
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT3, UTPASS3, NO_RETRY ) );

  rdkcertselector_free( &seq1cs );
  UT_END( __FUNCTION__ );
} // ut_rdkcertselector_seq2( void )


// sequence 3 : 1) first goes bad, uses second
//              2) first renewed, uses first
//              3) next uses first
static void ut_rdkcertselector_seq3( void ) {
  UT_BEGIN( __FUNCTION__ );
  UT_LOG( "seq3 1) first goes bad, uses second 2) first renewed, uses first 3) uses first" );

  rdkcertselector_h seq1cs = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );

  // 1) first goes bad, uses second
  UT_TST( ut_getThenSet( seq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER ) );
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );

  // 2) first renewed, uses first
  sleep( 1 ); // delay so file time is "old"
  UT_SYSTEM0( "touch " UTCERT1 ); // first renewed
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY ) );

  // 3) uses first
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY ) );

  rdkcertselector_free( &seq1cs );
  UT_END( __FUNCTION__ );
} // ut_rdkcertselector_seq3( void )


// sequence 4 : 1) first is missing and second goes bad; uses third;
//              2) then second restored then uses second
//              3) next try skips first
//              4) then first restored then uses first
//              5) next try uses first
static void ut_rdkcertselector_seq4( void ) {
  UT_BEGIN( __FUNCTION__ );
  UT_LOG( "seq4 1) first missing, second goes bad, uses third 2) second renewed, uses second" );
  UT_LOG( "     3) uses second; 4) first restored, uses first; 5) uses first" );

  rdkcertselector_h seq1cs = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );

  // 1) first missing, second goes bad, uses third
  UT_FORCE_RM( UTCERT1 );

  UT_TST( ut_getThenSet( seq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT2, UTPASS2, TRY_ANOTHER ) );
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT3, UTPASS3, NO_RETRY ) );

  // 2) second restored, use second
  UT_SYSTEM0( "touch " UTCERT2 );
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );

  // 3) next try skips first, uses second
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );

  // 4) then first restored then uses first
  UT_SYSTEM0( "touch " UTCERT1 );
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY ) );

  // 5) next try uses first
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY ) );
  rdkcertselector_free( &seq1cs );

  UT_END( __FUNCTION__ );
} // ut_rdkcertselector_seq4( void )


// sequence 5 : 1) first goes bad; uses second
//              2) use second again
//              3) next network error (56)
//              4) network restored, uses second, twice
static void ut_rdkcertselector_seq5( void ) {
  UT_BEGIN( __FUNCTION__ );
  UT_LOG( "seq5 1) first goes bad, uses second 2) use second again 3) network error" );
  UT_LOG( "     4) network restored, uses second" );

  rdkcertselector_h seq1cs = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );

  // 1) first goes bad, uses second
  UT_TST( ut_getThenSet( seq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER ) );
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );

  // 2) use second again
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );

  // 3) network error
  UT_TST( ut_getThenSet( seq1cs, CURLERR_NONCERT, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
  sleep( 1 );
  UT_TST( ut_getThenSet( seq1cs, CURLERR_NONCERT, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
  sleep( 1 );

  // 4) network restored; use second twice
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
  UT_TST( ut_getThenSet( seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );

  UT_END( __FUNCTION__ );
} // ut_rdkcertselector_seq5( void )


// sequence dualseq1 : two instances
//              obj1 first goes bad, uses second
//              obj2 uses first
static void ut_rdkcertselector_dualseq1( void ) {
  UT_BEGIN( __FUNCTION__ );

  UT_LOG( "dualseq1 instance 1, group 1 1) first goes bad, use second 2) skip first, use second" );
  UT_LOG( "dualseq1 instance 2, group 2 1) use first 2) use first" );
  rdkcertselector_h dseq1cs = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  rdkcertselector_h dseq2cs = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP2 );

  // 1) obj1 first goes bad, uses second
  UT_TST( ut_getThenSet( dseq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER ) );
  UT_TST( ut_getThenSet( dseq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
  // 2) obj1 still uses second
  UT_TST( ut_getThenSet( dseq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
  // 3) obj2 use first
  UT_TST( ut_getThenSet( dseq2cs, CURL_SUCCESS, FILESCHEME UTCERTALPHA, UTPASSALPHA, NO_RETRY ) );
  // 4) obj2 use first
  UT_TST( ut_getThenSet( dseq2cs, CURL_SUCCESS, FILESCHEME UTCERTALPHA, UTPASSALPHA, NO_RETRY ) );
  // 5) obj1 still uses second
  UT_TST( ut_getThenSet( dseq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
  // 6) obj2 still uses first
  UT_TST( ut_getThenSet( dseq2cs, CURL_SUCCESS, FILESCHEME UTCERTALPHA, UTPASSALPHA, NO_RETRY ) );

  rdkcertselector_free( &dseq1cs );
  rdkcertselector_free( &dseq2cs );

  UT_END( __FUNCTION__ );
} // ut_rdkcertselector_dualseq1( void )




// bad sequence 1 : 1) first goes bad, uses second
//              2) next try skips first
static void ut_rdkcertselector_badseq1( void ) {
  UT_BEGIN( __FUNCTION__ );

  UT_LOG( "badseq1 1) double get; 2) double set" );
  rdkcertselector_h badseq1cs = rdkcertselector_new(  certsel_path, DEFAULT_HROT, GRP1 );
  char *certUri = NULL, *certPass = NULL;
  // 1) double get
  UT_INTCMP( rdkcertselector_getCert( badseq1cs, &certUri, &certPass ), certselectorOk );
  UT_STRCMP( certUri, FILESCHEME UTCERT1, PATH_MAX );
  UT_STRCMP( certPass, UTPASS1, PARAM_MAX );

  UT_INTCMP( rdkcertselector_getCert( badseq1cs, &certUri, &certPass ), certselectorGeneralFailure );

  UT_INTCMP( rdkcertselector_setCurlStatus( badseq1cs, CURL_SUCCESS, "https://badseq1.double.get.set.works" ), NO_RETRY );
  UT_STRCMP( certPass, "", PARAM_MAX );

  UT_INTCMP( rdkcertselector_getCert( badseq1cs, &certUri, &certPass ), certselectorOk );
  UT_STRCMP( certUri, FILESCHEME UTCERT1, PATH_MAX );
  UT_STRCMP( certPass, UTPASS1, PARAM_MAX );
  // 2) double set
  UT_INTCMP( rdkcertselector_setCurlStatus( badseq1cs, CURL_SUCCESS, "https://badseq1.first.set" ), NO_RETRY );
  UT_STRCMP( certPass, "", PARAM_MAX );

  UT_INTCMP( rdkcertselector_setCurlStatus( badseq1cs, CURL_SUCCESS, "https://badseq1.second.set.error" ), RETRY_ERROR );

  UT_INTCMP( rdkcertselector_getCert( badseq1cs, &certUri, &certPass ), certselectorOk );
  UT_STRCMP( certUri, FILESCHEME UTCERT1, PATH_MAX );
  UT_STRCMP( certPass, UTPASS1, PARAM_MAX );

  UT_INTCMP( rdkcertselector_setCurlStatus( badseq1cs, CURL_SUCCESS, "https://badseq1.set.recovers" ), NO_RETRY );
  UT_STRCMP( certPass, "", PARAM_MAX );

  rdkcertselector_free( &badseq1cs );
  // 3) double free ok since it nulls pointer
  rdkcertselector_free( &badseq1cs );

  UT_END( __FUNCTION__ );
}  // end t_rdkcertselector_badseq1( void )



int main( int argc, char *argv[] ) {

  UT_BEGIN( __FILE__ );

  // internal functions
  ut_certsel_chkCertError( );
  ut_includesChars( );
  ut_certsel_findCert( );
  ut_certsel_findNextCert( );
  // api
  ut_certsel_free( );
  ut_certsel_new( );
  ut_rdkcertselector_getCert( );
  ut_rdkcertselector_setCurlStatus( );
  ut_rdkcertselector_getEngine( );
  // sequence tests
  ut_rdkcertselector_seq1( );
  ut_rdkcertselector_seq2( );
  ut_rdkcertselector_seq3( );
  ut_rdkcertselector_seq4( );
  ut_rdkcertselector_seq5( );
  ut_rdkcertselector_dualseq1( );
  ut_rdkcertselector_badseq1( );

  fprintf( stderr, "\n" );
  UT_END( __FILE__ );
}
#endif
#endif // UNIT_TESTS

