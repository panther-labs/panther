# AWS WAF Has Correct Rule Ordering

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that each WAF Web ACL has the correct ordering of rules. This allows you to ensure the rules are evaluated in the intended order on all WAFs.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, re-order rules so they are in the correct order on all WAF's.

**Reference**

- AWS [How WAF Works](https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works.html) documentation
