Feature: Certificate selection using certselector API
        Scenario: Sequence 3 - First cert fails, fallback to second, then first is restored and reused
                Given the certselector is initialized with cert group GRP1
                When I pass curl status "CURLERR_LOCALCERT" with cert URI "file://./ut/tst1first.tmp" with password "pc1pass"
                Then it should retry and use the next cert
                When I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst2first.tmp" with password "pc2pass"
                Then it should not retry and use the second cert
                When first cert is restored
                And I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst1first.tmp" with password "pc1pass"
                Then it should use the first cert again
                When next try I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst1first.tmp" with password "pc1pass"
                Then it should continue to use the first cert
