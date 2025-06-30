Feature: Certificate selection using certselector API
        Scenario: Sequence 6 - First cert fails,  second cert fails,  third cert fails, renew first, use first
                Given the certselector is initialized with cert group GRP1
                When I pass curl status "CURLERR_LOCALCERT" with cert URI "file://./ut/tst1first.tmp" with password "pc1pass"
                Then it should retry and use the next cert
                When I pass curl status "CURLERR_LOCALCERT" with cert URI "file://./ut/tst2first.tmp" with password "pc2pass"
                Then it should retry and use the next cert
                When I pass curl status "CURLERR_LOCALCERT" with cert URI "file://./ut/tst3first.tmp" with password "pc3pass"
                Then it should not retry because there is no cert in same group, make first cert renewed
                When I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst1first.tmp" with password "pc1pass"
                Then it should continue to use the first cert
