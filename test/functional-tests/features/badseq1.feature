Feature: Certificate Selector - Bad Sequence Handling
	Scenario: badseq1 - Double get and double set handling
		Given the certificate selector is initialized with multiple certificates
		When it performs another get immediately
		Then it should fails with certselectorGeneralFailure
		When it performs another set immediately
		Then it should fails with RETRY_ERROR


