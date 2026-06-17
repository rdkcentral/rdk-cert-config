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

Feature: Cross-signed certificate mTLS trust scenarios

	Scenario: Sequence 9 - Root B absent, no bridge cert, mTLS failure
		Given the cert selector is initialized with a single-cert group containing client-nobridge.p12 (issued by Root B)
		And the native platform trust store contains Root A and Root C but not Root B
		When the cert is presented without a cross-signed bridge
		Then setCurlStatus with error code 80 (ISSUER_ERROR) should return NO_RETRY
		And no fallback cert is available

	Scenario: Sequence 10 - Root B absent, bridge cert present, mTLS success
		Given the cert selector is initialized with a single-cert group containing client-xsign.p12 (issued by Root B, bridge embedded)
		And the native platform trust store contains Root A and Root C but not Root B
		When the cert is presented with a valid cross-signed bridge (Root B signed by Root C)
		Then setCurlStatus with error code 0 (SUCCESS) should return NO_RETRY
		And the cert should be reused on subsequent calls

	Scenario: Sequence 11 - All roots present, no bridge needed, mTLS success
		Given the cert selector is initialized with a single-cert group containing client-nobridge.p12 (issued by Root B)
		And the native platform trust store contains Root A, Root B, and Root C
		When the cert is presented without a cross-signed bridge
		Then setCurlStatus with error code 0 (SUCCESS) should return NO_RETRY via direct trust through Root B
		And the cert should be reused on subsequent calls

	Scenario: Sequence 12 - Root B absent, expired bridge cert, mTLS failure
		Given the cert selector is initialized with a single-cert group containing client-expxs.p12 (issued by Root B, expired bridge)
		And the native platform trust store contains Root A and Root C but not Root B
		When the cert is presented with an expired cross-signed bridge
		Then setCurlStatus with error code 80 (ISSUER_ERROR) should return NO_RETRY
		And no fallback cert is available

	Scenario: Sequence 13 - Root B absent, revoked bridge cert, mTLS failure
		Given the cert selector is initialized with a single-cert group containing client-revxs.p12 (issued by Root B, revoked bridge)
		And the native platform trust store contains Root A and Root C but not Root B
		When the cert is presented with a revoked cross-signed bridge
		Then setCurlStatus with error code 91 (INVALIDCERTSTATUS) should return NO_RETRY
		And no fallback cert is available
