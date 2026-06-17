Feature: Cross-signed mTLS certificate selection (sequences 9-11)

  Background:
    Given the l2sampleapp binary is built and available at "./test/l2-sampleapp/l2sampleapp"
    And the test setup has run creating placeholder P12 files in "./l2/xs/"

  Scenario: Sequence 9 - Both roots trusted; cross-signed cert selected immediately
    Given the certsel config "xs_both_roots.cfg" has group "XSGRP" listing "client-xsign.p12"
    When l2sampleapp is invoked with sequence number "9"
    Then the exit code should be 0
    And the cross-signed cert "client-xsign.p12" is selected with CURL_SUCCESS on the first call
    And the same cert is reused on the next call without retry

  Scenario: Sequence 10 - OldRoot expires; migrate config to new-root; xsign succeeds via bridge
    Given the certsel config "xs_old_root_only.cfg" has group "XSOLDGRP" listing "client-old.p12"
    And the certsel config "xs_new_root_only.cfg" has group "XSNEWGRP" listing "client-xsign.p12" then "client-old.p12"
    When l2sampleapp is invoked with sequence number "10"
    Then the exit code should be 0
    And phase A: "client-old.p12" succeeds then fails with CURLERR_CACERT (NO_RETRY - server-side trust failure)
    And phase B: a new selector session uses "xs_new_root_only.cfg" and "client-xsign.p12" succeeds via bridge

  Scenario: Sequence 11 - NewRoot absent; both certs fail with ISSUER; NoCert state
    Given the certsel config "xs_new_root_only.cfg" has group "XSNEWGRP" listing "client-xsign.p12" then "client-old.p12"
    When l2sampleapp is invoked with sequence number "11"
    Then the exit code should be 0
    And "client-xsign.p12" fails with CURLERR_ISSUER (80) and selector signals TRY_ANOTHER
    And "client-old.p12" also fails with CURLERR_ISSUER (80) and selector signals NO_RETRY (NoCert state)
