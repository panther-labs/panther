# Panther's CloudFormation Templates
A collection of CloudFormation Templates to interact with Panther.

## Templates

* `panther-aws-compliance-iam`: The IAM Roles used in conjunction with the compliance features.
* `panther-aws-remediations-master-account`: The Serverless Application and IAM Role used for Automatic Remediation deployed in the master account.
* `panther-aws-remediations-satellite-account`: The Serverless Application and IAM Role used for Automatic Remediation in the satellite accounts.
* `panther-cloudwatch-events`: Configures AWS CloudWatch Events to send to SNS/SQS.
* `panther-stackset-iam-admin-role`: The IAM Role orchestrating the StackSet creation.
* `panther-log-processing-iam`: The IAM Roles used in conjunction with the log processing features.
* `panther-log-processing-infra`: A configuration for log processing in a satellite account.
* `panther-log-processing-notifications` A minimal configuration for log processing in a satellite account.
