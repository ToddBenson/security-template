@runtime
Feature: Detect changes in the established baseline - csaa-insurance

  Background:
    Given a new browser or client instance
    When the following URLs are visited and their HTTP responses recorded
      | baseurl |

# Headers
  Scenario: Restrict other sites from placing it in an iframe in order to prevent ClickJacking attacks
    Then the HTTP X-Frame-Options header is not present

  Scenario: Enable built in browser protection again Cross Site Scriping
    Then the HTTP X-XSS-Protection header is not present

  Scenario: Force the use of HTTPS for the base secure Url
    Then the HTTP Strict-Transport-Security header is not present

  Scenario: Restrict HTML5 Cross Domain Requests to only trusted hosts
    Then the Access-Control-Allow-Origin header must not be: *

  Scenario: Enable anti-MIME sniffing prevention in browsers
    Then the HTTP X-Content-Type-Options header is not present

# Passive scanning
  Scenario: The application should not contain vulnerabilities identified using passive scanning
    Given a new scanning session
    And a scanner with all policies disabled
    And the passive scanner is enabled
    And the following URLs are visited and their HTTP responses recorded
      | baseurl |
    And the following false positives are removed
      |url                    |parameter          |cweId      |wascId   |
    And the XML report is written to the file build/zap/passive.xml
    Then no Medium or higher risk vulnerabilities should be present

# Shell-shock, padding oracle, and HTTP verbs
  Scenario: The application should not be vulnerable to Shell Shock
    And the shell-shock policy is enabled
    And the attack strength is set to High
    And the alert threshold is set to Low
    When the scanner is run
    And the following false positives are removed
      |url                    |parameter          |cweId      |wascId   |
    And the XML report is written to the file build/zap/shell_shock.xml
    Then no Medium or higher risk vulnerabilities should be present

  Scenario: The application should not be vulnerable to the Generic Padding Oracle attack
    And the padding-oracle policy is enabled
    And the attack strength is set to High
    And the alert threshold is set to Low
    When the scanner is run
    And the following false positives are removed
      |url                    |parameter          |cweId      |wascId   |
    And the XML report is written to the file build/zap/padding_oracle.xml
    Then no Medium or higher risk vulnerabilities should be present

  Scenario: The application should not expose insecure HTTP methods
    And the insecure-http-methods policy is enabled
    And the attack strength is set to High
    And the alert threshold is set to Low
    When the scanner is run
    And the following false positives are removed
      |url                    |parameter          |cweId      |wascId   |
    And the XML report is written to the file build/zap/insecure_methods.xml
    Then no Medium or higher risk vulnerabilities should be present

# Port scanning
  Scenario Outline: Only the required ports should be open
    Given the target host name <host>
    When TCP ports from <startPort> to <endPort> are scanned using <threads> threads and a timeout of <timeout> milliseconds
    And the <state> ports are selected
    Then the ports should be <ports>
    Examples:
      | host      | startPort | endPort | threads | timeout | state | ports  |
      | csaa-insurance.aaa.com | 1         | 65535   | 100     | 500     | open  | 80,443,1720,21 |