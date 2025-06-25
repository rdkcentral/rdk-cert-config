#ifndef __UNIT_TEST_H__
#define __UNIT_TEST_H__

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

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // for access()

// logging
#define UT_BEGIN( a ) fprintf( stderr, "** BEGIN UNIT TEST %s **\n", (a) )
#define UT_END( a ) fprintf( stderr, "** END UNIT TEST %s SUCCESS **\n", (a) )
#define UT_LOG( a ) fprintf( stderr, "*** UT: %s ***\n", (a) )

// basic tests
#define UT_TST( a ) { \
  long tst=(long)(a); \
  if ( tst==0 ) { fprintf(stderr,"act:%ld\n",tst); } \
  assert( tst!=0 ); }

#define UT_NULL( a ) { \
  void *ptr=(a); \
  if ( ptr!=NULL ) { fprintf(stderr,"not null:%p\n",ptr); } \
  assert( ptr==NULL ); }

#define UT_NOTNULL( a ) { \
  void *ptr=(a); \
  if ( ptr==NULL ) { fprintf(stderr,"null\n"); } \
  assert( ptr!=NULL ); }

// integer tests
#define UT_INTCMP( a, x ) { \
  const long act=(long)(a), exp=(long)(x); \
  if ( act != exp ) { fprintf(stderr,"act:%ld != exp:%ld\n",act,exp); } \
  assert( act == exp ); }

#define UT_INT0( a ) UT_INTCMP( a, 0 )

#define UT_TRUE( a ) UT_INTDIFF( a, 0 )
#define UT_FALSE( a ) UT_INTCMP( a, 0 )

#define UT_INTDIFF( a, x ) { \
  const long act=(long)(a), exp=(long)(x); \
  if ( act == exp ) { fprintf(stderr,"act:%ld == exp:%ld\n",act,exp); } \
  assert( act != exp ); }

// string tests
#define UT_STRCMP( s, x, z ) { \
  const char *str=(s), *exp=(x); \
  size_t _sz=(size_t)(z); \
  if ( strncmp( str, exp, _sz ) != 0 ) { fprintf(stderr,"str:%s\nexp:%s\n",str,exp); }\
  assert( strncmp( str, exp, _sz ) == 0 ); }

#define UT_STRDIFF( s, x, z ) { \
  const char *str=(s), *exp=(x); \
  size_t _sz=(size_t)(z); \
  if ( strncmp( str, exp, _sz ) == 0 ) { fprintf(stderr,"str:%s\nexp:%s\n",str,exp); }\
  assert( strncmp( str, exp, _sz ) != 0 ); }

// memory tests
#define UT_MEMCMP( mem1, mem2, z ) { \
  const uint8_t *m1=(uint8_t *)(mem1), *m2=(uint8_t *)(mem2); \
  size_t _sz=(size_t)(z); \
  if ( memcmp( m1, m2, _sz ) != 0 ) { int indx__LINE__; for (indx__LINE__=0;indx__LINE__<(_sz-3);indx__LINE__++) { if ( m1[indx__LINE__]!=m2[indx__LINE__] ) {fprintf(stderr,"[%d]m1:%x %x %x %x, m2:%x %x %x %x\n",indx__LINE__,m1[indx__LINE__],m1[indx__LINE__+1],m1[indx__LINE__+2],m1[indx__LINE__+3],m2[indx__LINE__],m2[indx__LINE__+1],m2[indx__LINE__+2],m2[indx__LINE__+3] ); break; } } }  \
  assert( memcmp( m1, m2, _sz ) == 0 ); }

#define UT_MEMDIFF( mem1, mem2, z ) { \
  const uint8_t *m1=(uint8_t *)(mem1), *m2=(uint8_t *)(mem2); \
  size_t _sz=(size_t)(z); \
  if ( memcmp( m1, m2, _sz ) == 0 ) { int indx__LINE__; for (indx__LINE__=0;indx__LINE__<(_sz-3);indx__LINE__++) { if ( m1[indx__LINE__]!=m2[indx__LINE__] ) {fprintf(stderr,"[%d]m1:%x %x %x %x, m2:%x %x %x %x\n",indx__LINE__,m1[indx__LINE__],m1[indx__LINE__+1],m1[indx__LINE__+2],m1[indx__LINE__+3],m2[indx__LINE__],m2[indx__LINE__+1],m2[indx__LINE__+2],m2[indx__LINE__+3] ); break; } } }  \
  assert( memcmp( m1, m2, _sz ) != 0 ); }

// system commands for test setup, etc
#define UT_SYSTEM0( cmd )  UT_INTCMP( system( cmd ), 0 )
#define UT_SYSTEM_FAILCODE( cmd, ret )  { fprintf(stderr,"system: %s\n", cmd ); UT_INTCMP( system( cmd ), ret ); }
#define UT_SYSTEM_FAIL( cmd )  { fprintf(stderr,"system: %s\n", cmd ); UT_INTDIFF( system( cmd ), 0 ); }

#define UT_CMPSTRFILE( litstr, file ) { UT_SYSTEM0( "echo \"" litstr "\" | diff - " file );}
#define UT_RM( f ) UT_INT0( remove( f ) )
#define UT_FORCE_RM( f ) {UT_INTDIFF( remove( f ), -99);}
#define UT_EXISTS( f ) UT_INT0( access( f, F_OK ) )
#define UT_DOESNTEXIST( f ) UT_INTDIFF( access( f, F_OK ), 0 )

#define UT_EXIT( ) { fprintf(stderr,"Early UT exit.\n"); assert(0); }

// MOCK SUPPORT
// see below for usage
#define MOK_DEFAULT_RETURN( typ, func, val ) \
            static const typ default_return_ ##func = val;\
            static typ return_ ##func = val
#define MOK_SET_RETURN( func, val ) { return_ ##func = val; }
#define MOK_RESET_RETURN( func )    { return_ ##func = default_return_ ##func; }
#define MOK_RETURN( func )          return_ ##func

/* MOCK Support Usage
 // myfunc1 calls external othersub2, so mock othersub2
 // modify return values of othersub2 to test myfunc1

 MOK_DEFAULT_RETURN( int, othersub2, 1 );
 int othersub2( int a, int b ) { // mock
   return MOK_RETURN( othersub2 );
 }
 ...
 int myfunc1( int first, int second ) {
   int val = 0;
   val = othersub2( first, second );
   if ( val == 1 ) {
     val += 20;
   } else {
     val += 50;
   }
   return val;
 }

 ut_myfunc1( void ) {
   UT_INTCMP( myfunc1( 1, 1 ), 21 );
   MOK_SET_RETURN( othersub2, 0 );
   UT_INTCMP( myfunc1( 1, 1 ), 50 );
   MOK_SET_RETURN( othersub2, 2 );
   UT_INTCMP( myfunc1( 1, 1 ), 52 );
   MOK_RESET_RETURN( othersub2 );
   UT_INTCMP( myfunc1( 1, 1 ), 21 );
 }
*/

#endif // __UNIT_TEST_H__

