# Panther's CloudFormation Templates

A collection of CloudFormation templates to configure data collection and remediation with multiple satellite accounts.

## Templates

- `panther-aws-compliance-iam`: The IAM Roles used in conjunction with the compliance features.
- `panther-remediations-iam`: The IAM Role used for Automatic Remediation in the satellite accounts.
- `panther-cloudwatch-events`: Configures AWS CloudWatch Events to send to SNS/SQS.
- `panther-stackset-iam-admin-role`: The IAM Role orchestrating the StackSet creation.
- `panther-log-processing-iam`: The IAM Roles used in conjunction with the log processing features.
- `panther-log-processing-infra`: A configuration for log processing in a satellite account.
- `panther-log-processing-notifications` A minimal configuration for log processing in a satellite account.
