Feature: CRL revocation certificate selection (sequences 12-13)

  Background:
    Given the l2sampleapp binary is built and available at "./test/l2-sampleapp/l2sampleapp"
    And the test setup has run creating placeholder P12 files in "./l2/xs/"

  Scenario: Sequence 12 - Leaf cert on CRL; fallback to valid cert; revoked stays skipped
    Given the certsel config "xs_crl.cfg" has group "CRLGRP" listing "crl-revoked.p12" then "crl-valid.p12"
    When l2sampleapp is invoked with sequence number "12"
    Then the exit code should be 0
    And "crl-revoked.p12" fails with CURLERR_CERTSTATUS (91) and selector signals TRY_ANOTHER
    And "crl-valid.p12" is selected with CURL_SUCCESS and selector signals NO_RETRY
    And on the subsequent call "crl-valid.p12" is returned directly without retrying the revoked cert

  Scenario: Sequence 13 - Intermediate CA revoked; fallback to cert under valid ICA
    Given the certsel config "xs_crl.cfg" has group "ICAGRP" listing "ica-revoked-leaf.p12" then "ica-valid-leaf.p12"
    When l2sampleapp is invoked with sequence number "13"
    Then the exit code should be 0
    And "ica-revoked-leaf.p12" fails with CURLERR_ISSUER (80) and selector signals TRY_ANOTHER
    And "ica-valid-leaf.p12" is selected with CURL_SUCCESS and selector signals NO_RETRY
