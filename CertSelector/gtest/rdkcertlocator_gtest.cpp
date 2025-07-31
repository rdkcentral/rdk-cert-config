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
#include "./../include/rdkcertlocator.h"
#include "./../src/rdkcertlocator.c"

using namespace std;
rdkcertlocator_t *ut_newcl( void );
#define GTEST_DEFAULT_RESULT_FILEPATH "/tmp/Gtest_Report/"
#define GTEST_DEFAULT_RESULT_FILENAME "rdkcertlocator_gtest_report.json"
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
class CertLocatorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Initialize tstcl
    tstcl = ut_newcl();
  }

  void TearDown() override {
    free(tstcl);
  }

  rdkcertlocator_h tstcl;
};
TEST_F(CertLocatorTest, EmptyArguments) {
  EXPECT_STREQ(tstcl->certUri, "");
  EXPECT_STREQ(tstcl->certCredRef, "");
  EXPECT_EQ(certloc_locateCert(NULL, "FRST"), certlocatorBadPointer);
  tstcl->certSelPath[0] = '\0';
  EXPECT_EQ(certloc_locateCert(tstcl, "FRST"), certlocatorBadArgument);
  ut_initcl(tstcl);
  EXPECT_EQ(certloc_locateCert(tstcl, NULL), certlocatorBadPointer);
  EXPECT_EQ(certloc_locateCert(tstcl, "FRST,SCND"), certlocatorBadArgument);
}

TEST_F(CertLocatorTest, ConfigFileFormatErrors) {
  tstcl->certSelPath[0] = 'X'; 
  EXPECT_EQ(certloc_locateCert(tstcl, "FRST"), certlocatorFileNotFound); 
  ut_initcl(tstcl); 
  strncpy(tstcl->certSelPath, UTDIR "/tst1toolong.cfg", PATH_MAX); 
  EXPECT_EQ(certloc_locateCert(tstcl, "FRST"), certlocatorFileError); 
  ut_initcl(tstcl); 
  strncpy(tstcl->certSelPath, UTDIR "/tst1miss2.cfg", PATH_MAX); 
  EXPECT_EQ(certloc_locateCert(tstcl, "FRST"), certlocatorFileNotFound); 
  ut_initcl(tstcl); 
  strncpy(tstcl->certSelPath, UTDIR "/tst1miss3.cfg", PATH_MAX); 
  EXPECT_EQ(certloc_locateCert(tstcl, "FRST"), certlocatorFileError); 
  ut_initcl(tstcl); 
  strncpy(tstcl->certSelPath, UTDIR "/tst1miss4.cfg", PATH_MAX); 
  EXPECT_EQ(certloc_locateCert(tstcl, "FRST"), certlocatorFileError); 
  ut_initcl(tstcl); 
  strncpy(tstcl->certSelPath, UTDIR "/tst1miss5.cfg", PATH_MAX); 
  EXPECT_EQ(certloc_locateCert(tstcl, "FRST"), certlocatorFileError); 
}

TEST_F(CertLocatorTest, MaxError) {
  ut_initcl(tstcl);
  EXPECT_EQ(certloc_locateCert(tstcl, "MAX"), certlocatorFileNotFound);
}

TEST_F(CertLocatorTest, ValidCases) {
  ut_initcl(tstcl);
  EXPECT_EQ(certloc_locateCert(tstcl, "FRST"), certlocatorOk);
  EXPECT_STREQ(tstcl->certUri, FILESCHEME UTCERT1);
  EXPECT_STREQ(tstcl->certCredRef, "pc1");

  ut_initcl(tstcl);
  EXPECT_EQ(certloc_locateCert(tstcl, "SCND"), certlocatorOk);
  EXPECT_STREQ(tstcl->certUri, FILESCHEME UTCERT2);
  EXPECT_STREQ(tstcl->certCredRef, "pc2");

  ut_initcl(tstcl);
  EXPECT_EQ(certloc_locateCert(tstcl, "THRD"), certlocatorOk);
  EXPECT_STREQ(tstcl->certUri, "file://" UTCERT3);
  EXPECT_STREQ(tstcl->certCredRef, "pc3");

  ut_initcl(tstcl);
  EXPECT_EQ(certloc_locateCert(tstcl, "MISNG"), certlocatorFileNotFound);
}

class CertLocatorNewTest : public ::testing::Test {
};

TEST_F(CertLocatorNewTest, BadArguments) {
  EXPECT_EQ(rdkcertlocator_new(LONGPATH, DEFAULT_HROT), nullptr);
  EXPECT_EQ(rdkcertlocator_new(UTDIR "/doesnotexist.cfg", DEFAULT_HROT), nullptr);
}

TEST_F(CertLocatorNewTest, ValidCases) {
  rdkcertlocator_h tstcl1 = nullptr;
  rdkcertlocator_h tstcl2 = nullptr;

  // Case 1: Valid with NULL arguments
  EXPECT_NE(nullptr, tstcl1 = rdkcertlocator_new(NULL, NULL));  
  rdkcertlocator_free(&tstcl1);

  // Case 2: Two different instances
  EXPECT_NE(nullptr, tstcl1 = rdkcertlocator_new(DEFAULT_CONFIG, DEFAULT_HROT));
  EXPECT_NE(nullptr, tstcl2 = rdkcertlocator_new(certsel_path, hrotprop_path));

  ut_printcertloc( tstcl1 );
  EXPECT_EQ(tstcl1->reserved1, CHK_RESERVED1);
  EXPECT_STREQ(tstcl1->certSelPath, DEFAULT_CONFIG_PATH);
  EXPECT_STREQ( tstcl1->certUri, "");
  EXPECT_STREQ( tstcl1->certCredRef, "");
  EXPECT_STREQ( tstcl1->certPass, "");
  EXPECT_STREQ( tstcl1->hrotEngine, "e4tstdef");

  ut_printcertloc( tstcl2 );
  EXPECT_EQ( tstcl2->reserved1, CHK_RESERVED1 );
  EXPECT_STREQ( tstcl2->certSelPath, certsel_path);
  EXPECT_STREQ( tstcl2->certUri, "");
  EXPECT_STREQ( tstcl2->certCredRef, "");
  EXPECT_STREQ( tstcl2->certPass, "");
  EXPECT_STREQ( tstcl2->hrotEngine, "e4tst1");
  rdkcertlocator_free(&tstcl1);
  rdkcertlocator_free(&tstcl2);

  // Case 3: Second instance with different hrot
  EXPECT_NE(nullptr, tstcl2 = rdkcertlocator_new(certsel_path, HROT_PROP2));
  EXPECT_STREQ(tstcl2->hrotEngine, "e4tst1");
  rdkcertlocator_free(&tstcl2);

  // Case 4: Valid new, but engine not set (if no hrot file)
  EXPECT_NE(nullptr, tstcl1 = rdkcertlocator_new(DEFAULT_CONFIG, UTDIR "/doesnotexist.prop"));
  EXPECT_STREQ(tstcl1->hrotEngine, "");
  rdkcertlocator_free(&tstcl1);

  // Case 5: Valid new, but engine not set (if hrot file is bad)
  EXPECT_NE(nullptr, tstcl1 = rdkcertlocator_new(certsel_path, HROT_PROP_BAD));
  EXPECT_STREQ(tstcl1->hrotEngine, "");
  rdkcertlocator_free(&tstcl1);

  // Case 6: Valid new, but engine not set (if hrot file is too long)
  EXPECT_NE(nullptr, tstcl1 = rdkcertlocator_new(certsel_path, HROT_PROP_LONG));
  EXPECT_STREQ(tstcl1->hrotEngine, "");
  rdkcertlocator_free(&tstcl1);
}

class CertLocateCertTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Ensure initial state (e.g., clean up any temporary files)
  }

  void TearDown() override {
    // Clean up any temporary files created during the test
  }
};

TEST_F(CertLocateCertTest, BadArguments) {
  char *certUri = NULL;
  char *certPass = NULL;

  EXPECT_EQ(rdkcertlocator_locateCert(NULL, "FRST", &certUri, &certPass), certlocatorBadPointer);
  rdkcertlocator_h tstcl1 = NULL;
  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "FRST", &certUri, &certPass), certlocatorBadPointer);

  tstcl1 = rdkcertlocator_new(DEFAULT_CONFIG, DEFAULT_HROT);
  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "FRST", NULL, &certPass), certlocatorBadArgument);
  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "FRST", &certUri, NULL), certlocatorBadArgument);
  rdkcertlocator_free(&tstcl1);
}

TEST_F(CertLocateCertTest, FilesNotExist) {
  rdkcertlocator_h tstcl1 = rdkcertlocator_new(certsel_path, DEFAULT_HROT);

  UT_SYSTEM0("mv " UTCERT1 " ./ut/tstXfirst.tmp");
  UT_SYSTEM0("mv " UTCERT2 " ./ut/tstXsecond.tmp");
  UT_SYSTEM0("mv " UTCERT3 " ./ut/tstXthird.tmp");

  char *certUri = NULL;
  char *certPass = NULL;

  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "FRST", &certUri, &certPass), certlocatorFileNotFound);
  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "SCND", &certUri, &certPass), certlocatorFileNotFound);
  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "THRD", &certUri, &certPass), certlocatorFileNotFound);

  rdkcertlocator_free(&tstcl1);
}

TEST_F(CertLocateCertTest, SomeValidSomeNot) {
  rdkcertlocator_h tstcl1 = rdkcertlocator_new(certsel_path, DEFAULT_HROT);

  UT_SYSTEM0("mv ./ut/tstXsecond.tmp " UTCERT2);

  char *certUri = NULL;
  char *certPass = NULL;

  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "FRST", &certUri, &certPass), certlocatorFileNotFound);
  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "SCND", &certUri, &certPass), certlocatorOk);  
  EXPECT_NE(certUri, nullptr);  
  EXPECT_STREQ(certUri, "file://./ut/tst1second.tmp");
  EXPECT_NE(certPass, nullptr);
  EXPECT_STREQ(certPass, "pc2pass");
  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "THRD", &certUri, &certPass), certlocatorFileNotFound);

  rdkcertlocator_free(&tstcl1);
}

TEST_F(CertLocateCertTest, FirstMissingSecondAndThirdFound) {
  rdkcertlocator_h tstcl1 = rdkcertlocator_new(certsel_path, DEFAULT_HROT);

  UT_SYSTEM0("mv ./ut/tstXthird.tmp " UTCERT3);

  char *certUri = NULL;
  char *certPass = NULL;

  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "FRST", &certUri, &certPass), certlocatorFileNotFound);
  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "SCND", &certUri, &certPass), certlocatorOk);
  EXPECT_NE(certUri, nullptr);
  EXPECT_STREQ(certUri, "file://./ut/tst1second.tmp");
  EXPECT_NE(certPass, nullptr);
  EXPECT_STREQ(certPass, "pc2pass");
  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "THRD", &certUri, &certPass), certlocatorOk);
  EXPECT_NE(certUri, nullptr);
  EXPECT_STREQ(certUri, "file://./ut/tst1third.tmp");
  EXPECT_NE(certPass, nullptr);
  EXPECT_STREQ(certPass, "pc3pass");

  rdkcertlocator_free(&tstcl1);
}

TEST_F(CertLocateCertTest, AllFound) {
  rdkcertlocator_h tstcl1 = rdkcertlocator_new(certsel_path, DEFAULT_HROT);

  UT_SYSTEM0("mv ./ut/tstXfirst.tmp " UTCERT1);

  char *certUri = NULL;
  char *certPass = NULL;

  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "FRST", &certUri, &certPass), certlocatorOk);
  EXPECT_NE(certUri, nullptr);
  EXPECT_STREQ(certUri, "file://./ut/tst1first.tmp");
  EXPECT_NE(certPass, nullptr);
  EXPECT_STREQ(certPass, "pc1pass");

  rdkcertlocator_free(&tstcl1);
}

TEST_F(CertLocateCertTest, CertFoundPcNotFound) {
  rdkcertlocator_h tstcl1 = rdkcertlocator_new(certsel_path, DEFAULT_HROT);

  char *certUri = NULL;
  char *certPass = NULL;

  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "NOPC", &certUri, &certPass), certlocatorFileError);
  rdkcertlocator_free(&tstcl1);
}

TEST_F(CertLocateCertTest, ValidCases) {
  rdkcertlocator_h tstcl1 = rdkcertlocator_new(certsel_path, DEFAULT_HROT);

  char *certUri = NULL;
  char *certPass = NULL;

  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "FRST", &certUri, &certPass), certlocatorOk);
  EXPECT_NE(certUri, nullptr);
  EXPECT_STREQ(certUri, "file://./ut/tst1first.tmp");
  EXPECT_NE(certPass, nullptr);
  EXPECT_STREQ(certPass, "pc1pass");

  rdkcertlocator_free(&tstcl1);

  tstcl1 = rdkcertlocator_new(certsel_path, DEFAULT_HROT);

  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "SCND", &certUri, &certPass), certlocatorOk);
  EXPECT_NE(certUri, nullptr);
  EXPECT_STREQ(certUri, "file://./ut/tst1second.tmp");
  EXPECT_NE(certPass, nullptr);
  EXPECT_STREQ(certPass, "pc2pass");

  rdkcertlocator_free(&tstcl1);

  tstcl1 = rdkcertlocator_new(certsel_path, DEFAULT_HROT);

  EXPECT_EQ(rdkcertlocator_locateCert(tstcl1, "THRD", &certUri, &certPass), certlocatorOk);
  EXPECT_NE(certUri, nullptr);
  EXPECT_STREQ(certUri, "file://./ut/tst1third.tmp");
  EXPECT_NE(certPass, nullptr);
  EXPECT_STREQ(certPass, "pc3pass");

  rdkcertlocator_free(&tstcl1);
}
