Feature: Certificate selection using certselector API
        Scenario: Sequence 5 - First cert fails, use second, handle network error and retry
                Given the certselector is initialized with cert group GRP1
                When I pass curl status "CURLERR_LOCALCERT" with cert URI "file://./ut/tst1first.tmp" with password "pc1pass"
                Then it should retry and use the next cert
                When I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst2first.tmp" with password "pc2pass"
                Then it should not retry and use the second cert
                When I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst2first.tmp" with password "pc2pass"
                Then it should continue to use the second cert
                When I pass curl status "CURLERR_RECV_ERROR" with cert URI "file://./ut/tst2first.tmp" with password "pc2pass"
                Then it should not mark the cert bad and should retry the same cert
                When I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst2first.tmp" with password "pc2pass"
                Then it should continue to use the second cert
                When I pass curl status "CURL_SUCCESS" with cert URI "file://./ut/tst2first.tmp" with password "pc2pass"
                Then it should continue to use the second cert
