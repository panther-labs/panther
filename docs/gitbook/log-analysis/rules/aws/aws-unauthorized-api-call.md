# AWS Unauthorized API Call

This rule monitors for unauthorized API calls.

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

Unauthorized API calls indicate someone tried to perform an action in your AWS account that they did not have permission to carry out. This may be due to a script/vendor misconfiguration, human error, or a malicious actor probing for publicly exposed resources or testing out the limits of compromised credentials.

**Remediation**

In small numbers, this often does not bear investigation. In large numbers, check if the access is from a programmatic tool that is misconfigured. If not, validate with the person responsible for the credentials being used that this is expected activity. If not, credentials should be rotated as they may be compromised.

**References**

- CIS AWS Benchmark 3.1: "Ensure a log metric filter and alarm exist for unauthorized API calls"
