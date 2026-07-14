Feature: OCSP stapling and cross-signed bridge expiry (sequences 14-17)

  Background:
    Given the l2sampleapp binary is built and available at "./test/l2-sampleapp/l2sampleapp"
    And the test setup has run creating placeholder P12 files in "./l2/xs/"

  Scenario: Sequence 14 - OCSP good status; cert selected without fallback
    Given the certsel config "xs_ocsp.cfg" has group "OCSPGOODGRP" listing "ocsp-valid.p12"
    When l2sampleapp is invoked with sequence number "14"
    Then the exit code should be 0
    And "ocsp-valid.p12" is selected with CURL_SUCCESS on the first call (NO_RETRY)
    And the same cert is reused on the next call

  Scenario: Sequence 15 - OCSP revoked status; fallback to valid cert; revoked stays skipped
    Given the certsel config "xs_ocsp.cfg" has group "OCSPGRP" listing "ocsp-revoked.p12" then "ocsp-valid.p12"
    When l2sampleapp is invoked with sequence number "15"
    Then the exit code should be 0
    And "ocsp-revoked.p12" fails with CURLERR_CERTSTATUS (91) and selector signals TRY_ANOTHER
    And "ocsp-valid.p12" is selected with CURL_SUCCESS and selector signals NO_RETRY
    And on the subsequent call "ocsp-valid.p12" is returned directly (revoked cert stays skipped)

  Scenario: Sequence 16 - OCSP responder unreachable; fallback used; cert renewed then reused
    Given the certsel config "xs_ocsp.cfg" has group "OCSPNRGRP" listing "ocsp-noresponder.p12" then "ocsp-valid.p12"
    When l2sampleapp is invoked with sequence number "16"
    Then the exit code should be 0
    And "ocsp-noresponder.p12" fails with CURLERR_CERTSTATUS (91) and selector signals TRY_ANOTHER
    And "ocsp-valid.p12" is used as fallback with CURL_SUCCESS (NO_RETRY)
    And "ocsp-noresponder.p12" remains skipped on the next call
    And when "ocsp-noresponder.p12" file timestamp is updated (touch) simulating cert renewal
    Then "ocsp-noresponder.p12" is reselected with CURL_SUCCESS

  Scenario: Sequence 17 - Bridge cert expires mid-session; fallback to new-root cert; renewed then reused
    Given the certsel config "xs_expxs.cfg" has group "EXPXSGRP" listing "client-expxs.p12" then "client-new.p12"
    When l2sampleapp is invoked with sequence number "17"
    Then the exit code should be 0
    And the first call to "client-expxs.p12" succeeds (bridge still valid) with NO_RETRY
    And the second call to "client-expxs.p12" fails with CURLERR_ISSUER (80) (bridge expired) and selector signals TRY_ANOTHER
    And "client-new.p12" takes over with CURL_SUCCESS (NO_RETRY)
    And "client-expxs.p12" remains skipped on the next call
    And when "client-expxs.p12" file timestamp is updated (touch) simulating bundle reissuance with fresh bridge
    Then "client-expxs.p12" is reselected with CURL_SUCCESS
