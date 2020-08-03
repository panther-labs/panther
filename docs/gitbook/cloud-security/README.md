# Cloud Security

Panther's Cloud Security works by scanning AWS accounts, modeling the **Resources** within them, using **Policies** to detect misconfigurations, and optionally remediating vulnerable resources. This feature can be used to power your compliance and improve your cloud security posture.

Common security misconfigurations include:

- S3 Buckets without encryption
- Security Groups allowing inbound SSH traffic from `0.0.0.0/0`
- Access Keys being older than 90 days
- IAM policies that are too permissive

## How It Works

![Architecture Diagram](../.gitbook/assets/cloud-security/readme-overview.png)

When adding a new AWS account, Panther first conducts a baseline scan and models resources in your account. Account scans are performed daily to ensure the most consistent state possible. This works by using an assumable IAM Role with ReadOnly permissions.

Resources can also be tracked in real-time using either CloudTrail or CloudWatch Events.
