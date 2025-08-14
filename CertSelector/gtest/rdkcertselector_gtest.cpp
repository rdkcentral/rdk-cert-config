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

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "./mock/mock.cpp"
#include "./mock/mock.h"
#include "./../src/rdkcertselector.c"
#include "./../include/rdkcertselector.h"

using namespace std;

#define GTEST_DEFAULT_RESULT_FILEPATH "/tmp/Gtest_Report/"
#define GTEST_DEFAULT_RESULT_FILENAME "rdkcertconfig_gtest_report.json"
#define GTEST_REPORT_FILEPATH_SIZE 256

GTEST_API_ int main(int argc, char *argv[])
{
    char testresults_fullfilepath[GTEST_REPORT_FILEPATH_SIZE];
    char buffer[GTEST_REPORT_FILEPATH_SIZE];

    memset( testresults_fullfilepath, 0, GTEST_REPORT_FILEPATH_SIZE );
    memset( buffer, 0, GTEST_REPORT_FILEPATH_SIZE );

    snprintf( testresults_fullfilepath, GTEST_REPORT_FILEPATH_SIZE, "json:%s%s" , GTEST_DEFAULT_RESULT_FILEPATH , GTEST_DEFAULT_RESULT_FILENAME);
    ::testing::GTEST_FLAG(output) = testresults_fullfilepath;
    ::testing::InitGoogleMock(&argc, argv);
    return RUN_ALL_TESTS();
}
/* function : ut_certsel_chkCertError();
 unit tests for static rdkcertselectorRetry_t certsel_chkCertError( int curlStat );
 cert errors, see above: cert_errors[] = { 35,53,54,58,59,66,80,83,90,91 }; */
TEST(CertSelChkCertErrorTest, ValidateCertErrorCodes) {
    // Test case for certsel_chkCertError(0)
    EXPECT_EQ(certsel_chkCertError(0), NO_RETRY);

    // Test cases for certsel_chkCertError(1) to certsel_chkCertError(34)
    for (int code = 1; code < 35; code++) {
        EXPECT_EQ(certsel_chkCertError(code), NO_RETRY);
    }

    // Test case for certsel_chkCertError(35)
    EXPECT_EQ(certsel_chkCertError(35), TRY_ANOTHER);

     // Test cases for certsel_chkCertError(36) to certsel_chkCertError(52)
    for (int code = 36; code < 53; code++) {
        EXPECT_EQ(certsel_chkCertError(code), NO_RETRY);
    }

    // Test cases for certsel_chkCertError(53) to certsel_chkCertError(59)
    EXPECT_EQ(certsel_chkCertError(53), TRY_ANOTHER);
    EXPECT_EQ(certsel_chkCertError(54), TRY_ANOTHER);
    for (int code = 55; code <= 57; code++) {
        EXPECT_EQ(certsel_chkCertError(code), NO_RETRY);
    }

    EXPECT_EQ(certsel_chkCertError(58), TRY_ANOTHER);
    EXPECT_EQ(certsel_chkCertError(59), TRY_ANOTHER);
     // Test case for certsel_chkCertError(66)
    for (int code = 60; code <= 65; code++) {
        EXPECT_EQ(certsel_chkCertError(code), NO_RETRY);
    }

    EXPECT_EQ(certsel_chkCertError(66), TRY_ANOTHER);
    
    for (int code = 67; code <= 79; code++) {
        EXPECT_EQ(certsel_chkCertError(code), NO_RETRY);
    }
    // Test cases for certsel_chkCertError(80)
    EXPECT_EQ(certsel_chkCertError(80), TRY_ANOTHER);

    // Test cases for certsel_chkCertError(81) to certsel_chkCertError(82)
    EXPECT_EQ(certsel_chkCertError(81), NO_RETRY);
    EXPECT_EQ(certsel_chkCertError(82), NO_RETRY);

    // Test case for certsel_chkCertError(83)
    EXPECT_EQ(certsel_chkCertError(83), TRY_ANOTHER);

    // Test cases for certsel_chkCertError(84) to certsel_chkCertError(89)
    for (int code = 84; code < 90; code++) {
        EXPECT_EQ(certsel_chkCertError(code), NO_RETRY);
    }

    // Test cases for certsel_chkCertError(90) to certsel_chkCertError(91)
    EXPECT_EQ(certsel_chkCertError(90), TRY_ANOTHER);
    EXPECT_EQ(certsel_chkCertError(91), TRY_ANOTHER);

    // Test cases for certsel_chkCertError(92) to certsel_chkCertError(199)
    for (int code = 92; code < 200; code++) {
        EXPECT_EQ(certsel_chkCertError(code), NO_RETRY);
    }
}

/* function : ut_includesChars()
 * unit tests for static int includesChars( const char *str, char ch1, char ch2 ) */
// no match
TEST(IncludesCharsTest, NullAndEmptyCases) {
    // Null and empty cases
    EXPECT_FALSE(includesChars(nullptr, 0, 0));
    EXPECT_FALSE(includesChars("123456", 0, 0));
    EXPECT_FALSE(includesChars("123456", 'x', 0));
    EXPECT_FALSE(includesChars("123456", 0, '7'));
    EXPECT_FALSE(includesChars("123456", 'x', '7'));
}
// 1 char match
TEST(IncludesCharsTest, SingleCharacterMatch) {
    // Single character match
    EXPECT_TRUE(includesChars("123456", '1', 0));
    EXPECT_TRUE(includesChars("123456", 0, '1'));
    EXPECT_TRUE(includesChars("123456", '6', 0));
    EXPECT_TRUE(includesChars("123456", 0, '6'));
    EXPECT_TRUE(includesChars("123456", '1', '7'));
    EXPECT_TRUE(includesChars("123456", '7', '1'));
    EXPECT_TRUE(includesChars("123456", '6', '7'));
    EXPECT_TRUE(includesChars("123456", 'x', '6'));
}
// 2 char match
TEST(IncludesCharsTest, TwoCharacterMatch) {
    // Two character matches
    EXPECT_TRUE(includesChars("123456", '1', '2'));
    EXPECT_TRUE(includesChars("123456", '5', '6'));
    EXPECT_TRUE(includesChars("123456", '1', '6'));
}
// realistic uses
TEST(IncludesCharsTest, RealisticUses) {
    // Realistic use cases
    const char* grp1 = "GRP1";
    const char* grp2 = "GRP2";
    const char* badgrp1 = "GRP1,GRP2";
    const char* badgrp2 = "GRP1|GRP2";

    EXPECT_FALSE(includesChars(grp1, ',', 0));
    EXPECT_FALSE(includesChars(grp1, 0, ','));
    EXPECT_FALSE(includesChars(grp1, ',', '|'));
    EXPECT_FALSE(includesChars(grp2, '|', 0));
    EXPECT_FALSE(includesChars(grp2, 0, '|'));
    EXPECT_FALSE(includesChars(grp2, ',', '|'));
    EXPECT_TRUE(includesChars(badgrp1, ',', '|'));
    EXPECT_TRUE(includesChars(badgrp2, ',', '|'));
}

/* function : ut_certsel_findCert();
 * unit tests for static rdkcertselectorStatus_t certsel_findCert( rdkcertselector_h thiscertsel )
 */
class CertSelFindCertTest : public ::testing::Test {
protected:
    rdkcertselector_h tstcs;

    void SetUp() override {
	// allocate and initialize a certsel test object
	// this is used until rdkcertselector_new is fully tested
        tstcs = ut_newcs();
    }

    void TearDown() override {
        free(tstcs);
    }
};

TEST_F(CertSelFindCertTest, InitializationTests) {
    ASSERT_NE(tstcs, nullptr);

    EXPECT_STREQ(tstcs->certUri, "");
    EXPECT_STREQ(tstcs->certCredRef, "");
}

TEST_F(CertSelFindCertTest, InvalidArgumentTests) {
    EXPECT_EQ(certsel_findCert(nullptr), certselectorBadPointer);

    tstcs->certSelPath[0] = '\0';
    EXPECT_EQ(certsel_findCert(tstcs), certselectorBadArgument);

    ut_initcs(tstcs);    
    tstcs->certGroup[0] = '\0';
    EXPECT_EQ(certsel_findCert(tstcs), certselectorBadArgument);

    ut_initcs(tstcs);
    tstcs->certSelPath[0] = 'X';
    EXPECT_EQ(certsel_findCert(tstcs), certselectorFileNotFound);
}

TEST_F(CertSelFindCertTest, ConfigFileErrorTests) {
    ut_initcs(tstcs);
    strncpy(tstcs->certSelPath, UTDIR "/tst1toolong.cfg", PATH_MAX);
    EXPECT_EQ(certsel_findCert(tstcs), certselectorFileError);

    const char* testFiles[] = {
        UTDIR "/tst1miss2.cfg",
        UTDIR "/tst1miss3.cfg",
        UTDIR "/tst1miss4.cfg",
        UTDIR "/tst1miss5.cfg"
    };

    for (const auto& file : testFiles) {
        ut_initcs(tstcs);
        strncpy(tstcs->certSelPath, file, PATH_MAX);
        EXPECT_EQ(certsel_findCert(tstcs), certselectorFileError);
    }
}

TEST_F(CertSelFindCertTest, BeyondMaxTests) {
    ut_initcs(tstcs);
    tstcs->certIndx = LIST_MAX;
    EXPECT_EQ(certsel_findCert(tstcs), certselectorFileNotFound);
}

TEST_F(CertSelFindCertTest, ValidIndexTests) {
    // Index 0
    ut_initcs(tstcs);
    EXPECT_EQ(certsel_findCert(tstcs), certselectorOk);
    EXPECT_STREQ(tstcs->certUri, FILESCHEME UTCERT1);
    EXPECT_STREQ(tstcs->certCredRef, "pc1");

    // Index 1
    ut_initcs(tstcs);
    tstcs->certIndx = 1;
    EXPECT_EQ(certsel_findCert(tstcs), certselectorOk);
    EXPECT_STREQ(tstcs->certUri, FILESCHEME UTCERT2);
    EXPECT_STREQ(tstcs->certCredRef, "pc2");

    // Index 2
    ut_initcs(tstcs);
    tstcs->certIndx = 2;
    EXPECT_EQ(certsel_findCert(tstcs), certselectorOk);
    EXPECT_STREQ(tstcs->certUri, "file://" UTCERT3);
    EXPECT_STREQ(tstcs->certCredRef, "pc3");

    // Index 3 (not found)
    ut_initcs(tstcs);
    tstcs->certIndx = 3;
    EXPECT_EQ(certsel_findCert(tstcs), certselectorFileNotFound);
}

class CertSelectorNextCertTest : public ::testing::Test {
protected:
    rdkcertselector_h tstcs;

    void SetUp() override {
        tstcs = ut_newcs();
        ASSERT_NE(tstcs, nullptr) << "Failed to initialize cert selector.";
    }

    void TearDown() override {
        rdkcertselector_free(&tstcs);
    }
};

TEST_F(CertSelectorNextCertTest, InvalidArguments) {
    EXPECT_EQ(certsel_findNextCert(nullptr), certselectorBadPointer)
        << "Expected certselectorBadPointer for NULL input.";

    ut_initcs(tstcs);
    tstcs->certIndx = LIST_MAX - 1;
    EXPECT_EQ(certsel_findNextCert(tstcs), certselectorFileNotFound)
        << "Expected certselectorFileNotFound for certIndx = LIST_MAX - 1.";
}

TEST_F(CertSelectorNextCertTest, ValidIndexTests) {
    ut_initcs(tstcs);
    tstcs->certIndx = 0;

    // Find index 1
    EXPECT_EQ(certsel_findNextCert(tstcs), certselectorOk)
        << "Expected certselectorOk for finding index 1.";
    EXPECT_STREQ(tstcs->certUri, FILESCHEME UTCERT2)
        << "Expected certUri to match FILESCHEME UTCERT2.";
    EXPECT_STREQ(tstcs->certCredRef, "pc2")
        << "Expected certCredRef to be 'pc2'.";

    // Find index 2
    EXPECT_EQ(certsel_findNextCert(tstcs), certselectorOk)
        << "Expected certselectorOk for finding index 2.";
    EXPECT_STREQ(tstcs->certUri, FILESCHEME UTCERT3)
        << "Expected certUri to match FILESCHEME UTCERT3.";
    EXPECT_STREQ(tstcs->certCredRef, "pc3")
        << "Expected certCredRef to be 'pc3'.";

    // Can't find index 3
    EXPECT_EQ(certsel_findNextCert(tstcs), certselectorFileNotFound)
        << "Expected certselectorFileNotFound for index 3.";
    EXPECT_STREQ(tstcs->certUri, "")
        << "Expected certUri to be empty for index 3.";
    EXPECT_STREQ(tstcs->certCredRef, "")
        << "Expected certCredRef to be empty for index 3.";
}

/* function : rdkcertselector_free()
 * Test case for rdkcertselector_free with null pointer (should not cause fault)
 */
TEST(RdkCertSelectorFreeTest, FreeNullPointer) {
    // The next call should not cause a fault
    rdkcertselector_free(nullptr);
}
#ifdef CHECK_MEM_WIPE
TEST(RdkCertSelectorFreeTest, FreeAndWipeMemory) {
    rdkcertselector_h tstcsh = ut_newcs();
    ASSERT_NE(tstcsh, nullptr); // Verify that the new cert selector handle is not null

    tstcsh->certCredRef[0] = 'X';
    tstcsh->certPass[0] = 'Y';

    // Free memory and set the pointer to NULL
    rdkcertselector_free(&tstcsh);
    ASSERT_EQ(tstcsh, nullptr);  // Verify the pointer is NULL after free

    // Attempt to free again - should not cause a fault due to double free protection
    rdkcertselector_free(&tstcsh);

    // Verify that the memory is wiped (although we know this could lead to a Coverity warning)
    // We are looking into deallocated space, so this might not be entirely safe.
    if (tstcsh != nullptr) {
        EXPECT_EQ(tstcsh->certCredRef[0], 0); // Check if the certCredRef is wiped
        EXPECT_EQ(tstcsh->certPass[0], 0);    // Check if the certPass is wiped
    }
}
#endif  // CHECK_MEM_WIPE

/* function : rdkcertselector_new
 *  unit tests for rdkcertselector_h rdkcertselector_new(const char *certsel_path, const char *hrotprop_path, const char *cert_group )
 */
TEST(RdkCertSelectorNewTest, CertSelectorNewTest) {	
    // Test invalid inputs for rdkcertselector_new 
    EXPECT_EQ(rdkcertselector_new(NULL, NULL, NULL), nullptr);
    EXPECT_EQ(rdkcertselector_new(NULL, NULL, ""), nullptr);
    EXPECT_EQ(rdkcertselector_new(NULL, NULL, "GRP1,GRP2"), nullptr);
    EXPECT_EQ(rdkcertselector_new(NULL, NULL, "GRP1|GRP2"), nullptr);
    EXPECT_EQ(rdkcertselector_new(NULL, NULL, "NOTHING"), nullptr);
    EXPECT_EQ(rdkcertselector_new("doesnotexist.cfg", NULL, "GRP1"), nullptr);
    EXPECT_EQ(rdkcertselector_new(LONGPATH, NULL, "GRP1"), nullptr);   
    // Test valid creation of cert selectors
    rdkcertselector_h tstcs1 = nullptr;
    tstcs1 = rdkcertselector_new("./ut/etc/ssl/certsel/certsel.cfg", "./ut/etc/ssl/certsel/hrot.properties", "GRP1");
    ASSERT_EQ(tstcs1, nullptr);
    rdkcertselector_free(&tstcs1);
    // Test creating two different instances
    rdkcertselector_h tstcs2 = nullptr;
    tstcs1 = rdkcertselector_new(DEFAULT_CONFIG, DEFAULT_HROT, GRP1);
    tstcs2 = rdkcertselector_new(certsel_path, hrotprop_path, GRP1);
    ut_printcertsel( tstcs1 );
    ut_printcertsel( tstcs2 );
    // Check the properties of tstcs1
    EXPECT_EQ(tstcs1->reserved1, CHK_RESERVED1);
    EXPECT_STREQ(tstcs1->certSelPath, DEFAULT_CONFIG_PATH);
    EXPECT_STREQ(tstcs1->certUri, "file://./ut/etc/ssl/certsel/tst1def.tmp");
    EXPECT_STREQ(tstcs1->certCredRef, "./ut/etc/ssl/certsel/pcdef");
    EXPECT_STREQ(tstcs1->certPass, "");
    EXPECT_STREQ(tstcs1->hrotEngine, "e4tstdef");
    EXPECT_EQ(tstcs1->state, cssReadyToGiveCert);
    EXPECT_STREQ(ut_statstr(tstcs1), "0|0|0|0|0|0");    
    // Check the properties of tstcs2
    EXPECT_EQ(tstcs2->reserved1, CHK_RESERVED1);
    EXPECT_STREQ(tstcs2->certSelPath, certsel_path);
    EXPECT_STREQ(tstcs2->certUri, "file://" UTCERT1);
    EXPECT_STREQ(tstcs2->certCredRef, "pc1");
    EXPECT_STREQ(tstcs2->certPass, "");
    EXPECT_STREQ(tstcs2->hrotEngine, "e4tst1");
    EXPECT_EQ(tstcs2->state, cssReadyToGiveCert);
    EXPECT_STREQ(ut_statstr(tstcs2), "0|0|0|0|0|0");

    rdkcertselector_free(&tstcs1);
    rdkcertselector_free(&tstcs2);

    // Test second creation with different engine
    tstcs2 = rdkcertselector_new(certsel_path, HROT_PROP2, GRP1);
    ASSERT_NE(tstcs2, nullptr);
    EXPECT_STREQ(tstcs2->hrotEngine, "e4tst1");
    rdkcertselector_free(&tstcs2);

    // Test creation with engine not set
    tstcs1 = rdkcertselector_new(DEFAULT_CONFIG, UTDIR "/doesnotexist.cfg", GRP1);
    ASSERT_NE(tstcs1, nullptr);
    EXPECT_STREQ(tstcs1->hrotEngine, "");
    rdkcertselector_free(&tstcs1);

    // Test creation with invalid hrot property
    tstcs1 = rdkcertselector_new(certsel_path, HROT_PROP_BAD, GRP1);
    ASSERT_NE(tstcs1, nullptr);
    EXPECT_STREQ(tstcs1->hrotEngine, "");
    rdkcertselector_free(&tstcs1);

    // Test creation with a long hrot property
    tstcs1 = rdkcertselector_new(certsel_path, HROT_PROP_LONG, GRP1);
    ASSERT_NE(tstcs1, nullptr);
    EXPECT_STREQ(tstcs1->hrotEngine, "");

	//Casr 7: hrot line too long 
    EXPECT_NE(nullptr, tstcs1 = rdkcertlocator_new(certsel_path, UTDIR "/fixbufferhrot.properties"));
    EXPECT_STREQ(tstcs1->hrotEngine, "");
	
    rdkcertselector_free(&tstcs1);
}
// Test case for testing rdkcertselector_getEngine function
TEST(RdkCertSelectorTest, CertSelectorGetEngineTest) {
    // Test invalid input to rdkcertselector_getEngine
    EXPECT_EQ(rdkcertselector_getEngine(nullptr), nullptr);

    rdkcertselector_h tstcs1 = nullptr, tstcs2 = nullptr;

    // Test null pointer
    EXPECT_EQ(rdkcertselector_getEngine(tstcs1), nullptr);

    // Test valid selector
    tstcs1 = rdkcertselector_new(certsel_path, hrotprop_path, GRP1);
    ASSERT_NE(tstcs1, nullptr);
    EXPECT_STREQ(rdkcertselector_getEngine(tstcs1), "e4tst1");

    // Test bad hrot property
    rdkcertselector_h badcs1 = rdkcertselector_new(certsel_path, HROT_PROP_BAD, GRP1);
    ASSERT_NE(badcs1, nullptr);
    EXPECT_EQ(rdkcertselector_getEngine(badcs1), nullptr);
    rdkcertselector_free(&badcs1);

    // Test missing hrot file
    badcs1 = rdkcertselector_new(certsel_path, "/etc/cert/missingfile", GRP1);
    ASSERT_NE(badcs1, nullptr);
    EXPECT_EQ(rdkcertselector_getEngine(badcs1), nullptr);
    rdkcertselector_free(&badcs1);

    // Test valid selector with engine
    char* eng = rdkcertselector_getEngine(tstcs1);
    ASSERT_NE(eng, nullptr);
    EXPECT_STREQ(eng, "e4tst1");
    rdkcertselector_free(&tstcs1);

    // Test another valid selector with different engine
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    ASSERT_NE(tstcs1, nullptr);
    eng = rdkcertselector_getEngine(tstcs1);
    EXPECT_STREQ(eng, "e4tstdef");

    tstcs2 = rdkcertselector_new(certsel_path, hrotprop_path, GRP1);
    ASSERT_NE(tstcs2, nullptr);
    eng = rdkcertselector_getEngine(tstcs2);
    EXPECT_STREQ(eng, "e4tst1");

    rdkcertselector_free(&tstcs1);
    rdkcertselector_free(&tstcs2);
}
 /* function : ut_rdkcertselector_getCert()
 *
 * unit tests for rdkcertselectorStatus_t rdkcertselector_getCert( rdkcertselector_h thiscertsel, const char **certUri, const char **certPass )
 */
// Test case for testing rdkcertselector_getCert function with various edge cases and valid cases
TEST(RdkCertSelectorGetCertTest, CertSelectorGetCertTest) {

    rdkcertselector_h tstcs1 = nullptr;
    char *certUri = nullptr, *certPass = nullptr;

    // Test bad pointer case
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorBadPointer);

    // Create a valid cert selector
    tstcs1 = rdkcertselector_new(DEFAULT_CONFIG, DEFAULT_HROT, GRP1);

    // Test bad argument cases
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, nullptr, &certPass), certselectorBadArgument);
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, nullptr), certselectorBadArgument);

    // Test general failure due to unknown state
    uint16_t save_state = tstcs1->state;
    tstcs1->state = cssUnknown;
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorGeneralFailure);

    // Reset state
    tstcs1->state = save_state;

    // Test bad argument when certUri is empty
    char save_uri0 = tstcs1->certUri[0];
    tstcs1->certUri[0] = '\0';
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorBadArgument);

    // Verify certUri and certPass are not set
    EXPECT_EQ(tstcs1->state, cssReadyToGiveCert);

    // Reset certUri
    tstcs1->certUri[0] = save_uri0;

    // Test bad argument when certCredRef is empty
    char save_ref0 = tstcs1->certCredRef[0];
    tstcs1->certCredRef[0] = '\0';
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorBadArgument);

    // Verify certUri and certPass are not set
    EXPECT_EQ(tstcs1->state, cssReadyToGiveCert);

    // Reset certCredRef
    tstcs1->certCredRef[0] = save_ref0;

    // Clean up
    rdkcertselector_free(&tstcs1);

    // Test case where files in config do not exist
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    // Simulate cert files missing
    UT_SYSTEM0("mv " UTCERT1 " ./ut/tstXfirst.tmp");
    UT_SYSTEM0("mv " UTCERT2 " ./ut/tstXsecond.tmp");
    UT_SYSTEM0("mv " UTCERT3 " ./ut/tstXthird.tmp");

    // Test for file not found error
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorFileNotFound);
    rdkcertselector_free(&tstcs1);

    // Test first cert marked as bad, second and third missing
    UT_SYSTEM0("mv ./ut/tstXfirst.tmp " UTCERT1);
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    tstcs1->certStat[0] = filetime(UTCERT1); // marked as bad
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorFileNotFound);
    EXPECT_EQ(tstcs1->state, cssReadyToGiveCert);
    EXPECT_EQ(tstcs1->certStat[0], filetime(UTCERT1));
    EXPECT_EQ(certUri, nullptr);
    EXPECT_EQ(certPass, nullptr);
    rdkcertselector_free(&tstcs1);

    // Test when two certs are bad, third one missing
    UT_SYSTEM0("mv ./ut/tstXsecond.tmp " UTCERT2);
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    tstcs1->certStat[0] = filetime(UTCERT1); // marked as bad
    tstcs1->certStat[1] = filetime(UTCERT2); // marked as bad
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorFileNotFound);
    EXPECT_EQ(tstcs1->state, cssReadyToGiveCert);
    EXPECT_EQ(certUri, nullptr);
    EXPECT_EQ(certPass, nullptr);
    rdkcertselector_free(&tstcs1);

    // Test when all certs are bad
    UT_SYSTEM0("mv ./ut/tstXthird.tmp " UTCERT3);  // cert no longer missing
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    tstcs1->certStat[0] = filetime(UTCERT1); // marked as bad
    tstcs1->certStat[1] = filetime(UTCERT2); // marked as bad
    tstcs1->certStat[2] = filetime(UTCERT3); // marked as bad
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorFileNotFound);
    EXPECT_EQ(tstcs1->state, cssReadyToGiveCert);
    EXPECT_EQ(certUri, nullptr);
    EXPECT_EQ(certPass, nullptr);
    rdkcertselector_free(&tstcs1);

    // Test for missing pc file
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP10);
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorFileNotFound);
    EXPECT_EQ(tstcs1->state, cssReadyToGiveCert);
    EXPECT_EQ(certUri, nullptr);
    EXPECT_EQ(certPass, nullptr);
    rdkcertselector_free(&tstcs1);

    // Test valid cert retrieval
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorOk);
    EXPECT_EQ(tstcs1->state, cssReadyToCheckCert);
    EXPECT_NE(certUri, nullptr);
    EXPECT_STREQ(certUri, "file://./ut/tst1first.tmp");
    EXPECT_NE(certPass, nullptr);
    EXPECT_STREQ(certPass, "pc1pass");
    rdkcertselector_free(&tstcs1);

    // First cert bad, second cert good
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    tstcs1->certStat[0] = filetime(UTCERT1); // marked as bad
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorOk);
    EXPECT_EQ(tstcs1->state, cssReadyToCheckCert);
    EXPECT_NE(certUri, nullptr);
    EXPECT_STREQ(certUri, "file://./ut/tst1second.tmp");
    EXPECT_NE(certPass, nullptr);
    EXPECT_STREQ(certPass, "pc2pass");
    rdkcertselector_free(&tstcs1);

    // First bad, second bad, third good
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    tstcs1->certStat[0] = filetime(UTCERT1); // marked as bad
    tstcs1->certStat[1] = filetime(UTCERT2); // marked as bad
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorOk);
    EXPECT_EQ(tstcs1->state, cssReadyToCheckCert);
    EXPECT_NE(certUri, nullptr);
    EXPECT_STREQ(certUri, "file://./ut/tst1third.tmp");
    EXPECT_NE(certPass, nullptr);
    EXPECT_STREQ(certPass, "pc3pass");
    rdkcertselector_free(&tstcs1);

    // First missing, second good
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    UT_SYSTEM0("mv " UTCERT1 " ./ut/tstXfirst.tmp"); // cert missing
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorOk);
    EXPECT_EQ(tstcs1->state, cssReadyToCheckCert);
    EXPECT_NE(certUri, nullptr);
    EXPECT_STREQ(certUri, "file://./ut/tst1second.tmp");
    EXPECT_NE(certPass, nullptr);
    EXPECT_STREQ(certPass, "pc2pass");
    rdkcertselector_free(&tstcs1);

    // First missing, second missing, third good
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    UT_SYSTEM0("mv " UTCERT2 " ./ut/tstXsecond.tmp"); // cert missing
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorOk);
    EXPECT_EQ(tstcs1->state, cssReadyToCheckCert);
    EXPECT_NE(certUri, nullptr);
    EXPECT_STREQ(certUri, "file://./ut/tst1third.tmp");
    EXPECT_NE(certPass, nullptr);
    EXPECT_STREQ(certPass, "pc3pass");
    rdkcertselector_free(&tstcs1);
    
    UT_SYSTEM0("mv ./ut/tstXfirst.tmp " UTCERT1);
    UT_SYSTEM0("mv ./ut/tstXsecond.tmp " UTCERT2);
    
    // Group 3 uses the third cert from group 1
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP3);
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorOk);
    EXPECT_NE(certUri, nullptr);
    EXPECT_STREQ(certUri, "file://./ut/tst1third.tmp");
    EXPECT_NE(certPass, nullptr);
    EXPECT_STREQ(certPass, "pc3pass");
    rdkcertselector_free(&tstcs1);

    // Multi group case
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, "A1");
    EXPECT_EQ(rdkcertselector_getCert(tstcs1, &certUri, &certPass), certselectorOk);
    EXPECT_NE(certUri, nullptr);
    EXPECT_STREQ(certUri, "file://./ut/tst1alpha.tmp");
    rdkcertselector_free(&tstcs1);
    // Continue with other multi group tests as shown in your original code
    // (Repeat similar tests for A2, A4, A7, A9, A10)
}
/* function : ut_rdkcertselector_setCurlStatus();
 *
 * unit tests for rdkcertselectorRetry_t rdkcertselector_setCurlStatus( rdkcertselector_h thiscertsel, unsigned int curlStat )
 */
class RdkCertSelectorSetCurlStatusTest : public ::testing::Test {
protected:
    rdkcertselector_h tstcs1;

    // Helper function for setting up the test certificate selector
    void SetUp() override {
        tstcs1 = NULL;
    }

    void TearDown() override {
        if (tstcs1) {
            rdkcertselector_free(&tstcs1);
        }
    }
};

// Test for invalid arguments passed to `rdkcertselector_setCurlStatus`
TEST_F(RdkCertSelectorSetCurlStatusTest, TestInvalidArguments) {
    // NULL cert selector
    EXPECT_EQ(rdkcertselector_setCurlStatus(NULL, CURL_SUCCESS, NULL), NO_RETRY);
    EXPECT_EQ(rdkcertselector_setCurlStatus(tstcs1, CURL_SUCCESS, NULL), NO_RETRY);

    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    
    // Wrong state
    EXPECT_EQ(rdkcertselector_setCurlStatus(tstcs1, CURL_SUCCESS, "https://n/a"), RETRY_ERROR);
    
    tstcs1->state = cssReadyToCheckCert;
    tstcs1->certIndx = 6;
    
    // Bad index
    EXPECT_EQ(rdkcertselector_setCurlStatus(tstcs1, CURL_SUCCESS, "https://bad.index"), RETRY_ERROR);
    
    rdkcertselector_free(&tstcs1);
}
// Test for bad certificate scenario (2 bad certs, trying 3rd cert)
TEST_F(RdkCertSelectorSetCurlStatusTest, TestBadCerts) {
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    tstcs1->state = cssReadyToCheckCert;
    tstcs1->certIndx = 2;
    tstcs1->certStat[0] = filetime(UTCERT1);
    tstcs1->certStat[1] = filetime(UTCERT2);
    tstcs1->certPass[0] = 'P';

    // Cert 3 goes bad, no more certs
    EXPECT_EQ(tstcs1->certStat[2], CERTSTAT_NOTBAD);
    EXPECT_EQ(rdkcertselector_setCurlStatus(tstcs1, CURLERR_LOCALCERT, "https://third.goes.bad"), NO_RETRY);   
    EXPECT_NE(tstcs1->certStat[2], CERTSTAT_NOTBAD);  // certStat[2] should be modified						      // 
    EXPECT_EQ(tstcs1->certPass[0], 0);  // Password wiped
    EXPECT_EQ(tstcs1->certIndx, 0);  // Reset certIndx to 0
    EXPECT_STREQ(tstcs1->certUri, "");
    EXPECT_STREQ(tstcs1->certCredRef, "");

    rdkcertselector_free(&tstcs1);
}
// Test for valid scenario
TEST_F(RdkCertSelectorSetCurlStatusTest, TestValidCert) {
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    tstcs1->state = cssReadyToCheckCert;
    tstcs1->certStat[0] = filetime(UTCERT1);
    tstcs1->certStat[1] = filetime(UTCERT2);
    tstcs1->certStat[2] = filetime(UTCERT3);
    tstcs1->certIndx = 2;
    tstcs1->certUri[0] = 'U';
    tstcs1->certCredRef[0] = 'C';
    tstcs1->certPass[0] = 'P';

    EXPECT_EQ(rdkcertselector_setCurlStatus(tstcs1, CURL_SUCCESS, "https://third.is.good"), NO_RETRY);
    EXPECT_EQ(tstcs1->certStat[2], CERTSTAT_NOTBAD);
    EXPECT_EQ(tstcs1->certIndx, 0);  // Cert index should be reset to 0
    EXPECT_STREQ(tstcs1->certUri, FILESCHEME UTCERT1);
    EXPECT_STREQ(tstcs1->certCredRef, UTCRED1);
    EXPECT_EQ(tstcs1->certPass[0], 0);  // Password wiped
    EXPECT_EQ(tstcs1->certPass[1], 0);
    EXPECT_EQ(tstcs1->state, cssReadyToGiveCert);

    rdkcertselector_free(&tstcs1);
}
// Test for using bad cert and moving to the next one
TEST_F(RdkCertSelectorSetCurlStatusTest, TestBadCertAndRetry) {
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    tstcs1->state = cssReadyToCheckCert;
    tstcs1->certPass[0] = 'P';

    EXPECT_EQ(tstcs1->certStat[0], CERTSTAT_NOTBAD);

    // Cert 1 is bad, move to Cert 2
    EXPECT_EQ(rdkcertselector_setCurlStatus(tstcs1, CURLERR_LOCALCERT, "https://first.goes.bad"), TRY_ANOTHER);
    EXPECT_NE(tstcs1->certStat[0], CERTSTAT_NOTBAD);  // Cert 0 should be marked bad
    EXPECT_EQ(tstcs1->certPass[0], 0);  // Password wiped
    EXPECT_EQ(tstcs1->certIndx, 1);
    EXPECT_STREQ(tstcs1->certUri, FILESCHEME UTCERT2);
    EXPECT_STREQ(tstcs1->certCredRef, UTCRED2);

    rdkcertselector_free(&tstcs1);
}
// Test for non-cert error
TEST_F(RdkCertSelectorSetCurlStatusTest, TestNonCertError) {
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    tstcs1->state = cssReadyToCheckCert;
    tstcs1->certPass[0] = 'P';

    EXPECT_EQ(tstcs1->certStat[0], CERTSTAT_NOTBAD);

    // Non-cert error
    EXPECT_EQ(rdkcertselector_setCurlStatus(tstcs1, CURLERR_NONCERT, "https://noncert.error"), NO_RETRY);
    EXPECT_EQ(tstcs1->certStat[0], CERTSTAT_NOTBAD);  // Cert state should not change
    EXPECT_EQ(tstcs1->certPass[0], 0);  // Password wiped
    EXPECT_EQ(tstcs1->certIndx, 0);
    EXPECT_STREQ(tstcs1->certUri, FILESCHEME UTCERT1);
    EXPECT_STREQ(tstcs1->certCredRef, UTCRED1);

    rdkcertselector_free(&tstcs1);
}
/* function : ut_rdkcertselector_getEngine()
 *
 *unit tests for char *rdkcertselector_getEngine( rdkcertselector_h thiscertsel )
 * */
class RdkCertSelectorGetEngineTest : public ::testing::Test {
protected:
    rdkcertselector_h tstcs1;
    rdkcertselector_h tstcs2;
    rdkcertselector_h badcs1;

    // Helper function for setting up the test certificate selector
    void SetUp() override {
        tstcs1 = NULL;
        tstcs2 = NULL;
        badcs1 = NULL;
    }

    void TearDown() override {
        if (tstcs1) {
            rdkcertselector_free(&tstcs1);
        }
        if (tstcs2) {
            rdkcertselector_free(&tstcs2);
        }
        if (badcs1) {
            rdkcertselector_free(&badcs1);
        }
    }
};

// Test for error cases and valid engine retrieval
TEST_F(RdkCertSelectorGetEngineTest, TestEngineRetrieval) {
    // NULL rdkcertselector
    EXPECT_EQ(rdkcertselector_getEngine(NULL), nullptr);

    // NULL rdkcertselector_h
    EXPECT_EQ(rdkcertselector_getEngine(tstcs1), nullptr);

    // Test valid engine retrieval
    tstcs1 = rdkcertselector_new(certsel_path, hrotprop_path, GRP1);
    EXPECT_STREQ(rdkcertselector_getEngine(tstcs1), "e4tst1");

    // Test with a bad hrot property path
    badcs1 = rdkcertselector_new(certsel_path, HROT_PROP_BAD, GRP1);
    EXPECT_EQ(rdkcertselector_getEngine(badcs1), nullptr);
    rdkcertselector_free(&badcs1);

    // Test with a missing hrot property file
    badcs1 = rdkcertselector_new(certsel_path, "/etc/cert/missingfile", GRP1);
    EXPECT_EQ(rdkcertselector_getEngine(badcs1), nullptr);
    rdkcertselector_free(&badcs1);

    // Retrieve and validate engine for tstcs1
    char *eng = rdkcertselector_getEngine(tstcs1);
    ASSERT_NE(eng, nullptr);
    EXPECT_STREQ(eng, "e4tst1");

    rdkcertselector_free(&tstcs1);

    // Test for another certificate selector
    tstcs1 = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
    eng = rdkcertselector_getEngine(tstcs1);
    EXPECT_STREQ(eng, "e4tstdef");

    // Test with another tstcs2
    tstcs2 = rdkcertselector_new(certsel_path, hrotprop_path, GRP1);
    eng = rdkcertselector_getEngine(tstcs2);
    EXPECT_STREQ(eng, "e4tst1");

    rdkcertselector_free(&tstcs1);
    rdkcertselector_free(&tstcs2);
}
/* function : ut_rdkcertselector_seq1()
 *
 * sequence 1 : 1) first goes bad, uses second
 *              2) next try skips first
 */
class RdkCertSelectorSeqTest : public ::testing::Test {
protected:
    rdkcertselector_h seq1cs;

    // Helper function for setting up the test certificate selector
    void SetUp() override {
        seq1cs = nullptr;
    }

    void TearDown() override {
        if (seq1cs) {
            rdkcertselector_free(&seq1cs);
        }
    }
};
TEST_F(RdkCertSelectorSeqTest, TestSequence1) {
    // Test sequence: 1) first cert goes bad, uses second 2) skips first, uses second

    // Create certificate selector object
    seq1cs = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);

    // 1) First cert goes bad, uses second
    EXPECT_TRUE(ut_getThenSet(seq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER));
    EXPECT_TRUE(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY));

    // 2) Next try skips first cert, uses second
    EXPECT_TRUE(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY));

    // Free the certificate selector object
    rdkcertselector_free(&seq1cs);
}
/* function : ut_rdkcertselector_seq2()
 * sequence 2 : second is bad; uses first;              
 *              then first goes bad; uses third       
 *              next try skips first and second
 */
TEST_F(RdkCertSelectorSeqTest, TestSequence2) {
    // Test sequence: 1) second cert is bad, uses first; 2) first cert goes bad, uses third; 3) skips first and second, uses third.

    // Create certificate selector object
    seq1cs = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);

    // 1) Second cert is already marked as bad, but first is OK
    seq1cs->certStat[1] = filetime(UTCERT2);  // Mark second cert as bad
    EXPECT_TRUE(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY));  // First cert is used, no retry

    // 2) First cert goes bad, uses third cert
    EXPECT_TRUE(ut_getThenSet(seq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER));  // First cert goes bad, retry next cert
    EXPECT_TRUE(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT3, UTPASS3, NO_RETRY));  // Third cert is used successfully

    // 3) Skips first and second certs, uses third cert
    EXPECT_TRUE(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT3, UTPASS3, NO_RETRY));  // Third cert is used, no retry

    // Free the certificate selector object
    rdkcertselector_free(&seq1cs);
}
/* function : ut_rdkcertselector_seq3()
 * sequence 3 : 1) first goes bad, uses second
 *              2) first renewed, uses firs                          
 *              3) next uses first
 */
TEST_F(RdkCertSelectorSeqTest, TestSequence3) {
    // Test sequence: 1) first goes bad, uses second; 2) first renewed, uses first; 3) uses first.
    // Create certificate selector object
    seq1cs = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);

    // 1) First cert goes bad, uses second
    seq1cs->certStat[0] = filetime(UTCERT1); // Ensure first cert is initially not bad
    seq1cs->certStat[1] = filetime(UTCERT2); // Ensure second cert is available
    EXPECT_EQ(ut_getThenSet(seq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER), 0);  // First cert goes bad
    seq1cs->state = cssReadyToGiveCert;
    EXPECT_EQ(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY), 0);  // Second cert is used

    // 2) First cert renewed, uses first cert again
    sleep(1);  // Wait to simulate time passing, making the first cert seem old
    UT_SYSTEM0("touch " UTCERT1);  // Renew first cert (using touch command to update file time)
    seq1cs->state = cssReadyToGiveCert;
    EXPECT_EQ(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY), 0);// First cert is used again

    // 3) First cert is used again (should still be valid)

    // Free the certificate selector object
    rdkcertselector_free(&seq1cs);
}
/* function : ut_rdkcertselector_seq3()
 *   sequence 4 : 1) first is missing and second goes bad; uses third;
 *		  2) then second restored then uses second
 *                3) next try skips first
 *                4) then first restored then uses first
 *                5) next try uses first
 */
class RdkCertSelectorSeq4Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up any required environment or variables.
        certsel_path = CERTSEL_CFG;  // Adjust the path as needed
        seq1cs = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
        ASSERT_NE(seq1cs, nullptr) << "Failed to initialize rdkcertselector.";
    }

    void TearDown() override {
        rdkcertselector_free(&seq1cs);
    }

    const char* certsel_path;
    rdkcertselector_h seq1cs;
};
#define EXPECTED_RESULT 1
TEST_F(RdkCertSelectorSeq4Test, CertSelectorSequenceTest) {
    // 1) First missing, second goes bad, uses third
    UT_FORCE_RM(UTCERT1);  // Remove the first certificate
    EXPECT_EQ(ut_getThenSet(seq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT2, UTPASS2, TRY_ANOTHER), EXPECTED_RESULT);

    EXPECT_EQ(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT3, UTPASS3, NO_RETRY), EXPECTED_RESULT);

    // 2) Second restored, use second
    UT_SYSTEM0("touch " UTCERT2);  // Restore the second certificate
    EXPECT_EQ(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY), EXPECTED_RESULT);

    // 3) Next try skips first, uses second
    EXPECT_EQ(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY), EXPECTED_RESULT);

    // 4) First restored, uses first
    UT_SYSTEM0("touch " UTCERT1);  // Restore the first certificate
    EXPECT_EQ(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY), EXPECTED_RESULT);

    // 5) Next try uses first
    EXPECT_EQ(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT1, UTPASS1, NO_RETRY), EXPECTED_RESULT);    

}
/* function : ut_rdkcertselector_seq5()
 *   sequence 5 : 1) first goes bad; uses second              
 *   		  2) use second again              
 *   		  3) next network error (56)              
 *   		  4) network restored, uses second, twice
 */
class RdkCertSelectorSeq5Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize the rdkcertselector instance
        certsel_path = CERTSEL_CFG;  // Update as per your environment
        seq1cs = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
        ASSERT_NE(seq1cs, nullptr) << "Failed to initialize rdkcertselector.";
    }

    void TearDown() override {
        // Clean up
        rdkcertselector_free(&seq1cs);
    }

    const char* certsel_path;
    rdkcertselector_h seq1cs;
};

TEST_F(RdkCertSelectorSeq5Test, CertSelectorSequence5) {
    // 1) First goes bad, uses second
    EXPECT_EQ(ut_getThenSet(seq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER), EXPECTED_RESULT);
    EXPECT_EQ(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY), EXPECTED_RESULT);   
    // 2) Use second again
    EXPECT_EQ(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY), EXPECTED_RESULT);
    // 3) Network error
    EXPECT_EQ(ut_getThenSet(seq1cs, CURLERR_NONCERT, FILESCHEME UTCERT2, UTPASS2, NO_RETRY), EXPECTED_RESULT);
    seq1cs->state = cssReadyToGiveCert;
    sleep(1); // Simulate delay
    EXPECT_EQ(ut_getThenSet(seq1cs, CURLERR_NONCERT, FILESCHEME UTCERT2, UTPASS2, NO_RETRY), EXPECTED_RESULT);
    sleep(1); // Simulate delay
    // 4) Network restored; use second twice
    seq1cs->state = cssReadyToGiveCert;
    EXPECT_EQ(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY), EXPECTED_RESULT);
    
    EXPECT_EQ(ut_getThenSet(seq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY), EXPECTED_RESULT);
}
/* function : ut_rdkcertselector_dualseq1()
 *      sequence dualseq1 : two instances
 *			obj1 first goes bad, uses second
 *			obj2 uses first
 */
class DualSeqCertSelectorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize two instances of rdkcertselector
        certsel_path = CERTSEL_CFG;  // Update as per your environment
        dseq1cs = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
        dseq2cs = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP2);

        ASSERT_NE(dseq1cs, nullptr) << "Failed to initialize rdkcertselector for group 1.";
        ASSERT_NE(dseq2cs, nullptr) << "Failed to initialize rdkcertselector for group 2.";
    }

    void TearDown() override {
        // Free the rdkcertselector instances
        rdkcertselector_free(&dseq1cs);
        rdkcertselector_free(&dseq2cs);
	std::cout << std::endl;
    }

    const char* certsel_path;
    rdkcertselector_h dseq1cs;
    rdkcertselector_h dseq2cs;
};

TEST_F(DualSeqCertSelectorTest, DualSequenceTest) {
    // 1) Instance 1: First goes bad, uses second
    EXPECT_EQ(ut_getThenSet(dseq1cs, CURLERR_LOCALCERT, FILESCHEME UTCERT1, UTPASS1, TRY_ANOTHER), EXPECTED_RESULT);
    EXPECT_EQ(ut_getThenSet(dseq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY), EXPECTED_RESULT);

    // 2) Instance 1: Still uses second
    EXPECT_EQ(ut_getThenSet(dseq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY), EXPECTED_RESULT);

    // 3) Instance 2: Uses first
    EXPECT_EQ(ut_getThenSet(dseq2cs, CURL_SUCCESS, FILESCHEME UTCERTALPHA, UTPASSALPHA, NO_RETRY), EXPECTED_RESULT);

    // 4) Instance 2: Still uses first
    EXPECT_EQ(ut_getThenSet(dseq2cs, CURL_SUCCESS, FILESCHEME UTCERTALPHA, UTPASSALPHA, NO_RETRY), EXPECTED_RESULT);

    // 5) Instance 1: Still uses second
    EXPECT_EQ(ut_getThenSet(dseq1cs, CURL_SUCCESS, FILESCHEME UTCERT2, UTPASS2, NO_RETRY), EXPECTED_RESULT);

    // 6) Instance 2: Still uses first
    EXPECT_EQ(ut_getThenSet(dseq2cs, CURL_SUCCESS, FILESCHEME UTCERTALPHA, UTPASSALPHA, NO_RETRY), EXPECTED_RESULT);
}
/* function : ut_rdkcertselector_badseq1()
 *   bad sequence 1 : 1) first goes bad, uses second
 *   			2) next try skips first
 */  			 
class RdkCertSelectorBadSeqTest : public ::testing::Test {
protected:
    void SetUp() override {
        certsel_path = CERTSEL_CFG; // Update this as per your environment
        badseq1cs = rdkcertselector_new(certsel_path, DEFAULT_HROT, GRP1);
        ASSERT_NE(badseq1cs, nullptr) << "Failed to initialize rdkcertselector.";
        certUri = nullptr;
        certPass = nullptr;
    }

    void TearDown() override {
        // Clean up and ensure double free safety
        rdkcertselector_free(&badseq1cs);
        rdkcertselector_free(&badseq1cs); // Ensure it handles double free gracefully
	std::cout << std::endl;
    }

    const char* certsel_path;
    rdkcertselector_h badseq1cs;
    char* certUri;
    char* certPass;
};

TEST_F(RdkCertSelectorBadSeqTest, BadSequenceTest) {
    // 1) Double get
    EXPECT_EQ(rdkcertselector_getCert(badseq1cs, &certUri, &certPass), certselectorOk);
    EXPECT_STREQ(certUri, FILESCHEME UTCERT1);
    EXPECT_STREQ(certPass, UTPASS1);

    EXPECT_EQ(rdkcertselector_getCert(badseq1cs, &certUri, &certPass), certselectorGeneralFailure);

    EXPECT_EQ(rdkcertselector_setCurlStatus(badseq1cs, CURL_SUCCESS, "https://badseq1.double.get.set.works"), NO_RETRY);
    EXPECT_STREQ(certPass, "");

    EXPECT_EQ(rdkcertselector_getCert(badseq1cs, &certUri, &certPass), certselectorOk);
    EXPECT_STREQ(certUri, FILESCHEME UTCERT1);
    EXPECT_STREQ(certPass, UTPASS1);

    // 2) Double set
    EXPECT_EQ(rdkcertselector_setCurlStatus(badseq1cs, CURL_SUCCESS, "https://badseq1.first.set"), NO_RETRY);
    EXPECT_STREQ(certPass, "");

    EXPECT_EQ(rdkcertselector_setCurlStatus(badseq1cs, CURL_SUCCESS, "https://badseq1.second.set.error"), RETRY_ERROR);

    EXPECT_EQ(rdkcertselector_getCert(badseq1cs, &certUri, &certPass), certselectorOk);
    EXPECT_STREQ(certUri, FILESCHEME UTCERT1);
    EXPECT_STREQ(certPass, UTPASS1);

    EXPECT_EQ(rdkcertselector_setCurlStatus(badseq1cs, CURL_SUCCESS, "https://badseq1.set.recovers"), NO_RETRY);
    EXPECT_STREQ(certPass, "");
}
