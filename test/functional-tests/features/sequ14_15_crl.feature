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

Feature: CRL-based certificate revocation scenarios

	Scenario: Sequence 14 - Revoked leaf cert on CRL, fallback to valid cert
		Given the cert selector is initialized with a multi-cert group containing crl-revoked.p12 and crl-valid.p12
		When the first cert (revoked leaf) is presented
		Then setCurlStatus with error code 91 (INVALIDCERTSTATUS) should return TRY_ANOTHER
		When the selector falls back to the valid cert
		Then setCurlStatus with error code 0 (SUCCESS) should return NO_RETRY
		And subsequent calls should skip the revoked cert and use the valid cert directly

	Scenario: Sequence 15 - Revoked intermediate CA, fallback to valid ICA cert
		Given the cert selector is initialized with a multi-cert group containing ica-revoked-leaf.p12 and ica-valid-leaf.p12
		When the first cert (under revoked ICA) is presented
		Then setCurlStatus with error code 80 (ISSUER_ERROR) should return TRY_ANOTHER
		When the selector falls back to the cert under valid ICA
		Then setCurlStatus with error code 0 (SUCCESS) should return NO_RETRY
