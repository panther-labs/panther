# AWS ACM Certificates are Valid

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that all ACM Certificates are in the `ISSUED` state. Policies not in the `ISSUED` state are ineligible for use, for one reason or another.

**Remediation**

To remediate this, address the issue causing the certificate to not be in the `ISSUED` state. Most of these issues can be addressed from the [ACM panel](https://us-west-2.console.aws.amazon.com/acm/home) in the AWS console.

**References**

- AWS ACM [Troubleshooting Guide ](https://docs.aws.amazon.com/acm/latest/userguide/troubleshooting.html)
