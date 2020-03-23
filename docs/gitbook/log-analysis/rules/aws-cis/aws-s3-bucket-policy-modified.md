# AWS S3 Bucket Policy Modified

This rule monitors for changes to S3 bucket access policies.

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

S3 bucket access policies dictate who has what access to contents of the S3 bucket. S3 buckets are an extremely common form of storage, and data is often leaked from S3 bucket access misconfigurations where private company data is accidentally made publicly available.

**Remediation**

Verify that the S3 bucket policy change was planned, and is reasonable in scope. If not planned, revert the change immediately and modify permissions to ensure this does not happen again.

**References**

- CIS AWS Benchmark 3.8: "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
