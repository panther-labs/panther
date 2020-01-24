# AWS IAM Assume Role Blacklist Ignored

This rule monitors for any users assuming roles that have been explicitly blacklisted from user assumption.

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Medium**         |

Some IAM roles are created for services to access, or for emergencies only. These roles may not be intended to ever be assumed manually by an IAM user, although sometimes it is difficult or impossible to enforce this directly. This rule supplements this intention by monitoring for when these roles are assumed directly by a user and alerting.

**Remediation**

Verify that the IAM Role was approved for use, for example due to remediating downtime or a security incident.
