# Copyright 2025 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
#

Feature: OCSP stapling scenarios

	Scenario: Sequence 16 - Good OCSP staple, no fallback
		Given the cert selector is initialized with a multi-cert group containing ocsp-valid.p12 and ocsp-revoked.p12
		When the first cert (good OCSP status) is presented
		Then setCurlStatus with error code 0 (SUCCESS) should return NO_RETRY
		And the cert should be reused on subsequent calls without fallback

	Scenario: Sequence 17 - Revoked OCSP staple, fallback to valid cert
		Given the cert selector is initialized with a multi-cert group containing ocsp-valid.p12 and ocsp-revoked.p12
		When the first cert succeeds initially
		Then setCurlStatus with error code 0 (SUCCESS) should return NO_RETRY
		When the first cert later fails with revoked OCSP status
		Then setCurlStatus with error code 91 (INVALIDCERTSTATUS) should return TRY_ANOTHER
		When the selector falls back to the second cert
		Then setCurlStatus with error code 0 (SUCCESS) should return NO_RETRY
		And subsequent calls should skip the revoked cert

	Scenario: Sequence 18 - OCSP responder unreachable, fallback then recovery
		Given the cert selector is initialized with a multi-cert group containing ocsp-valid.p12 and ocsp-revoked.p12
		When the first cert fails due to OCSP responder being unreachable
		Then setCurlStatus with error code 91 (INVALIDCERTSTATUS) should return TRY_ANOTHER
		When the selector falls back to the second cert
		Then setCurlStatus with error code 0 (SUCCESS) should return NO_RETRY
		When the OCSP responder recovers (simulated by file touch renewal on first cert)
		Then the first cert should become eligible again
		And setCurlStatus with error code 0 (SUCCESS) should return NO_RETRY
