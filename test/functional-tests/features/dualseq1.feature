Feature: Certificate Selector Dual Sequence Handling
	Scenario: dualseq1 - Two instances with different fallback behaviors
		Given the certificate selector is initialized with multiple certificates
		And two instances (obj1 and obj2) are running independently
		When obj1 tries to use the first certificate and it fails
		Then obj1 should fallback and use the second certificate
		When obj1 retries
		Then obj1 should skip the first and continue using the second certificate
		When obj2 starts operation
		Then obj2 should use the first certificate
		When obj2 retries
		Then obj2 should continue using the first certificate
