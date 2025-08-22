Feature: Certificate selection using certselector API
        Scenario: Sequence 2 - Second cert fails, fallback to first, then first fails and third is used
                Given the certselector is initialized with cert group GRP1
                When second cert is marked as bad already
                And I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst1first.tmp" with password "pc1pass"
                Then it should not retry and use the first cert
                When I pass curl status "CURLERR_LOCALCERT" with cert URI "file://./ut/tst1first.tmp" with password "pc1pass"
                Then it should retry and use the next available cert
                When I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst3first.tmp" with password "pc3pass"
                Then it should not retry and use the third cert
                When next try I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst3first.tmp" with password "pc3pass"
                Then Next try should skip both first and second certs, and directly use the third cert
