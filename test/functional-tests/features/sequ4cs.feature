Feature: Certificate selection using certselector API
        Scenario: Sequence 5 - Recovery and fallback through multiple certificate states
                Given the certselector is initialized with cert group GRP1
                When the first cert is missing
                And I pass curl status "CURLERR_LOCALCERT" with cert URI "file://./ut/tst2first.tmp" with password "pc2pass"
                Then it should retry and use the next cert
                When I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst3first.tmp" with password "pc3pass"
                Then it should not retry and use the third cert
                When the second cert is restored
                And I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst2first.tmp" with password "pc2pass"
                Then it should use the second cert again
                When I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst2first.tmp" with password "pc2pass"
                Then it should continue to use the second cert
                When the first cert is restored
                And I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst1first.tmp" with password "pc1pass"
                Then it should use the first cert
                When I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst1first.tmp" with password "pc1pass"
                Then it should continue to use the first cert
