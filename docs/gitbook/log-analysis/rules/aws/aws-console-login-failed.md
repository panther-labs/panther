# AWS Console Login Failed

This rule monitors for failed AWS console logins.

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

Failed logins may be indicative of brute force attacks or the use of old compromised credentials.

**Remediation**

In small numbers, this does not bear investigation. In large numbers, check for the possibility of brute force attacks and consider upgrading password strength.

**References**

- CIS AWS Benchmark 3.6: "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures"
