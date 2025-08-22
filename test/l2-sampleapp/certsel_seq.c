/*
 * Copyright 2025 Comcast Cable Communications Management, LLC
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

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include <sys/stat.h>
#include "include/l2_tst.h"
#include "include/rdkcertselector.h"
#include "include/unit_test.h"

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

typedef struct rdkcertselector_s rdkcertselector_t;
typedef rdkcertselector_t *rdkcertselector_h;
static const char *certsel_path = CERTSEL_CFG;
int certGetAndSet(rdkcertselector_h , unsigned int , const char * , const char *, rdkcertselectorRetry_t );

int run_seq1cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq1cs = rdkcertselector_new(  certsel_path, L2_HROTPROP, GRP1 );
        L2_NOTNULL(seq1cs , "Cert selector initialization failed for sequence 1\n");
        //first goes bad, uses second
        L2_TST(certGetAndSet(seq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER ));
        L2_TST(certGetAndSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ));
        //next try skips first
        L2_TST(certGetAndSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
        rdkcertselector_free( &seq1cs );
        L2_NULL(seq1cs , "Cert selector memory free failed for sequence 1\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

int run_seq2cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq2cs = (rdkcertselector_h)rdkcertselector_new(  certsel_path, L2_HROTPROP, GRP1 );
        L2_NOTNULL(seq2cs , "Cert selector initialization failed for sequence 2\n");
        //second is already marked as bad, but first is ok
        seq2cs->certStat[1] = get_file_timestamp( UTCERT2 );  //need to enable
        L2_TST( certGetAndSet( seq2cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY ) );
        //first goes bad, uses third
        L2_TST( certGetAndSet( seq2cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER ) );
        L2_TST( certGetAndSet( seq2cs, CURL_SUCCESS, FILESCHEME UTCERT3, UTPASS3, NO_RETRY ) );
        //skips first and second, uses third
        L2_TST( certGetAndSet( seq2cs, CURL_SUCCESS, FILESCHEME UTCERT3, UTPASS3, NO_RETRY ) );
        rdkcertselector_free( &seq2cs );
        L2_NULL(seq2cs , "Cert selector memory free failed for sequence 2\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

int run_seq3cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq3cs = rdkcertselector_new(  certsel_path, L2_HROTPROP, GRP1 );
        L2_NOTNULL(seq3cs , "Cert selector initialization failed for sequence 3\n");
        //first goes bad, uses second
        L2_TST( certGetAndSet( seq3cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER ) );
        L2_TST( certGetAndSet( seq3cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
        //first renewed, uses first
        sleep( 1 ); // delay so file time is "old"
        UT_SYSTEM0( "touch " UTCERT1 ); // first renewed
        L2_TST( certGetAndSet( seq3cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY ) );
        //uses first
        L2_TST( certGetAndSet( seq3cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY ) );
        rdkcertselector_free( &seq3cs );
        L2_NULL(seq3cs , "Cert selector memory free failed for sequence 3\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

int run_seq4cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq4cs = rdkcertselector_new(  certsel_path, L2_HROTPROP, GRP1 );
        L2_NOTNULL(seq4cs , "Cert selector initialization failed for sequence 4\n");
        // 1) first missing, second goes bad, uses third
        UT_FORCE_RM( UTCERT1 );
        L2_TST( certGetAndSet( seq4cs, CURLERR_LOCALCERT, FILESCHEME UTCERT2, UTPASS2, TRY_ANOTHER ) );
        L2_TST( certGetAndSet( seq4cs, CURL_SUCCESS, FILESCHEME UTCERT3, UTPASS3, NO_RETRY ) );
        // 2) second restored, use second
        UT_SYSTEM0( "touch " UTCERT2 );
        L2_TST( certGetAndSet( seq4cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
        // 3) next try skips first, uses second
        L2_TST( certGetAndSet( seq4cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
        // 4) then first restored then uses first
        UT_SYSTEM0( "touch " UTCERT1 );
        L2_TST( certGetAndSet( seq4cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY ) );
        // 5) next try uses first
        L2_TST( certGetAndSet( seq4cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY ) );
        rdkcertselector_free( &seq4cs );
        L2_NULL(seq4cs , "Cert selector memory free failed for sequence 4\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

int run_seq5cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq5cs = rdkcertselector_new(  certsel_path, L2_HROTPROP, GRP1 );
        L2_NOTNULL(seq5cs , "Cert selector initialization failed for sequence 5\n");

        L2_TST( certGetAndSet( seq5cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER ) );
        L2_TST( certGetAndSet( seq5cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );

        // 2) use second again
        L2_TST( certGetAndSet( seq5cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );

        // 3) network error
        L2_TST( certGetAndSet( seq5cs, CURLERR_NONCERT, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
        sleep( 1 );
        L2_TST( certGetAndSet( seq5cs, CURLERR_NONCERT, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
        sleep( 1 );

        // 4) network restored; use second twice
        L2_TST( certGetAndSet( seq5cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
        L2_TST( certGetAndSet( seq5cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );

        rdkcertselector_free( &seq5cs );
        L2_NULL(seq5cs , "Cert selector memory free failed for sequence 5\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

int run_seq6cs()
{	
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h seq6cs = rdkcertselector_new(  certsel_path, L2_HROTPROP, GRP1 );
        L2_NOTNULL(seq6cs , "Cert selector initialization failed for sequence 6\n");

        L2_TST(certGetAndSet(seq6cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER ));
        L2_TST(certGetAndSet(seq6cs, CURLERR_LOCALCERT, FILESCHEME UTCERT2, UTPASS2, TRY_ANOTHER ));
        L2_TST(certGetAndSet(seq6cs, CURL_SUCCESS, FILESCHEME UTCERT3, UTPASS3, NO_RETRY ));

        sleep( 1 );
        UT_SYSTEM0( "touch " UTCERT1 ); //first renewed				
        L2_TST(certGetAndSet( seq6cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY ) );

        rdkcertselector_free( &seq6cs );
        L2_NULL(seq6cs , "Cert selector memory free failed for sequence 6\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;


}
int run_dualseq1cs()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h dseq1cs = rdkcertselector_new(  certsel_path, L2_HROTPROP, GRP1 );
        L2_NOTNULL(dseq1cs , "Cert selector initialization failed for dual sequence 1\n");
        rdkcertselector_h dseq2cs = rdkcertselector_new(  certsel_path, L2_HROTPROP, GRP2 );
        L2_NOTNULL(dseq2cs , "Cert selector initialization failed for dual sequence 2\n");
        // 1) obj1 first goes bad, uses second
        L2_TST( certGetAndSet( dseq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER ) );
        L2_TST( certGetAndSet( dseq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
        // 2) obj1 still uses second
        L2_TST( certGetAndSet( dseq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
        // 3) obj2 use first
        L2_TST( certGetAndSet( dseq2cs, CURL_SUCCESS, FILESCHEME UTCERTALPHA, UTPASSALPHA, NO_RETRY ) );
        // 4) obj2 use first
        L2_TST( certGetAndSet( dseq2cs, CURL_SUCCESS, FILESCHEME UTCERTALPHA, UTPASSALPHA, NO_RETRY ) );
        // 5) obj1 still uses second
        L2_TST( certGetAndSet( dseq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY ) );
        // 6) obj2 still uses first
        L2_TST( certGetAndSet( dseq2cs, CURL_SUCCESS, FILESCHEME UTCERTALPHA, UTPASSALPHA, NO_RETRY ) );
        rdkcertselector_free( &dseq1cs );
        L2_NULL(dseq1cs , "Cert selector memory free failed for dual sequence 1\n");
        rdkcertselector_free( &dseq2cs );
        L2_NULL(dseq2cs , "Cert selector memory free failed for dual sequence 2\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;
}

int run_badseq1()
{
        DEBUG_LOG("%s : Entry\n", __FUNCTION__);
        rdkcertselector_h badseq1cs = rdkcertselector_new(  certsel_path, L2_HROTPROP, GRP1 );
        L2_NOTNULL(badseq1cs , "Cert selector initialization failed for bad sequence 1\n");
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
        L2_NULL(badseq1cs , "Cert selector memory free failed for bad sequence 1\n");
        // 3) double free ok since it nulls pointer
        rdkcertselector_free( &badseq1cs );
        L2_NULL(badseq1cs , "Cert selector memory free failed during double free 2\n");
        DEBUG_LOG("%s : End\n", __FUNCTION__);
        return L2_SUCCESS;

}
int certGetAndSet(rdkcertselector_h thiscertsel, unsigned int curlStat, const char *expUri, const char *expPass, rdkcertselectorRetry_t expRetry )
{
        rdkcertselectorStatus_t csstat1;
        char *certUri, *certPass;
        DEBUG_LOG("%s Entry\n", __FUNCTION__);
        csstat1 = rdkcertselector_getCert( thiscertsel, &certUri, &certPass );
        if ( csstat1 != certselectorOk ) {
                ERROR_LOG( "getCert return error (%d!=%d)j\n", csstat1, certselectorOk );
                return L2_FAIL;
        }
        printf(" %s certUri : %s , certPass : %s expUri : %s expPass: %s\n", __FUNCTION__, certUri, certPass, expUri, expPass);
        if ( strcmp( certUri, expUri ) != 0 ) {
                ERROR_LOG( "getCert uri error (%s!=%s)j\n", certUri, expUri );
                return L2_FAIL;
        }
        if ( strcmp( certPass, expPass ) != 0 ) {
                ERROR_LOG( "getCert pass error (%s!=%s)j\n", certPass, expPass );
                return L2_FAIL;
        }
        char *eng = rdkcertselector_getEngine( thiscertsel );
        const char *engdef="e4tstdef";
        if ( eng!=NULL && strcmp( eng, engdef ) != 0 ) {
                ERROR_LOG( "getEngine error (%s!=%s)j\n", eng, engdef );
                return L2_FAIL;
        }

        rdkcertselectorRetry_t retry;
        retry = rdkcertselector_setCurlStatus( thiscertsel, curlStat, "https://getThenSet" );
        if ( thiscertsel->certPass[0] != '\0' && thiscertsel->certPass[1] != '\0' ) {
                ERROR_LOG( "setCurlStatus pass not wiped (%s)j\n", certPass );
                return L2_FAIL;
        }
        if ( retry != expRetry ) {
                ERROR_LOG( "getCurlStatus return error (%d!=%d)j\n", retry, expRetry );
                return L2_FAIL;
        }
        DEBUG_LOG("%s End\n", __FUNCTION__);
        return L2_SUCCESS; // results as expected
}

// get the file date in seconds since epoc or return 0 on error
unsigned long get_file_timestamp( const char *fname ) {
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
