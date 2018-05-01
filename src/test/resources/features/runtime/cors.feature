@cors @skip
Feature: Cross Origin Resource Sharing
  Verify that the application does not allow the browser to perform requests outside of the allowed origins

  @iriusriskcwe-942-cors_allowed
  Scenario Outline: Permit allowed origins to make CORS requests
    Given a new browser or client instance
    And the client/browser is configured to use an intercepting proxy
    When the path <path> is requested with the HTTP method GET with the 'Origin' header set to <origin>
    Then the returned 'Access-Control-Allow-Origin' header has the value <origin>
    Examples:
     |path                         |origin               |
     | e1.pncie.com | |
     | e2.pncie.com | |
     | e3.pncie.com | |
     | csaa-insurance.aaa.com | |
     | mypolicy.digital.pncie.com |  |
     | mypolicy.perf.digital.pncie.com | |
     | quote2.apps.prod.pdc.digital.csaa-insurance.aaa.com |  |
     | quote2-test.apps.prod.pdc.digital.csaa-insurance.aaa.com ||


  @iriusrisk-cwe-942-cors_disallowed
  Scenario Outline: Forbid disallowed origins from making CORS requests
    Given a new browser or client instance
    And the client/browser is configured to use an intercepting proxy
    When the path <path> is requested with the HTTP method GET with the 'Origin' header set to <origin>
    Then the 'Access-Control-Allow-Origin' header is not returned
    Examples:
      |path                         |origin               |
      | e1.pncie.com | |
      | e2.pncie.com | |
      | e3.pncie.com | |
      | csaa-insurance.aaa.com | |
      | mypolicy.digital.pncie.com |  |
      | mypolicy.perf.digital.pncie.com | |
      | quote2.apps.prod.pdc.digital.csaa-insurance.aaa.com |  |
      | quote2-test.apps.prod.pdc.digital.csaa-insurance.aaa.com ||

