Feature: Certificate selection using certselector API
        Scenario: Sequence 1 - First cert fails, fallback to second
                Given the certselector is initialized with cert group GRP1
                When I pass curl status "CURLERR_LOCALCERT" with cert URI "file://./ut/tst1first.tmp" with password "pc1pass"
                Then it should retry and use the next cert
                When I pass curl status "CURL_SUCCESS" with expect cert URI "file://./ut/tst2first.tmp" with password "pc2pass"
                Then it should not retry and use the second cert
                When next try I pass curl status "CURL_SUCCESS" with expect cert URI "file://./ut/tst2first.tmp" with password "pc1pass"
                Then Next try skips first cert, the selector should directly use the second certificate URI "file://./ut/tst2first.tmp" and password "pc2pass"
