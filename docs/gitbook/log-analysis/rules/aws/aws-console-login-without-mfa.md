# AWS Console Login Without MFA

This rule monitors for failed AWS console logins without the use of MFA.

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Low**            |

MFA adds an additional layer of security above passwords to user logins. Best practice is to require MFA for all user logins, and this rule can serve as a supplement to such configurations to ensure they are not accidentally or intentionally subverted.

**Remediation**

Investigate why this user was able to authenticate without MFA. Enable MFA for the user, and modify permissions to ensure further logins without MFA cannot happen.

**References**

- CIS AWS Benchmark 3.2: "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA"
