# Automatic Remediation

## Overview

Panther supports Automatic Remediation of non-compliant resources to ensure that your infrastructure is as secure as possible. This works by:

- Associating a remediation with a given Policy
- When a Policy failure occurs, the `aws-remediation` Lambda assumes a role in the target account with the offending resource and performs the remediation

The following diagram shows how Panther supports Automatic Remediation:

![remediation diagram](../../.gitbook/assets/autoremediationmulticustomeraccount.png)

## Setup

Enabling automatic remediation for a Cloud Security source is simple.

The only requirement is to check the `AWS Automatic Remediations` checkbox while onboarding the Cloud Security source, and the prerequisite role will be deployed as part of the onboarding stack.

![enable remediations checkbox](../../.gitbook/assets/enableRemediations.png)

To enable automatic remediation on an existing source, go to your sources list and edit the existing source for which you wish to enable automatic remediation. This will bring you to the same setup wizard as above, with instructions on how to deploy the updated stack template.

## Writing a Remediation

To write a new remediation, follow the steps below.

### Code

In the `./internal/compliance/remediation_aws/src/app/remediations` folder of the Panther [repo](https://github.com/panther-labs/panther), add a Python file called `aws_<service>_name_of_remediation` with the following structure:

```python
from typing import Any, Dict

from boto3 import Session

from .remediation import Remediation
from .remediation_base import RemediationBase

@Remediation
class AwsNameOfRemediation(RemediationBase):
    """Remediation that does something to help with your security!"""

    # The unique identifier to be referenced in Policies
    @classmethod
    def _id(cls) -> str:
        return 'Service.NameOfRemediation'

    # Any custom parameters needed to set the resource in the correct state
    @classmethod
    def _parameters(cls) -> Dict[str, str]:
        return {}

    # The API call to fix the resource
    @classmethod
    def _fix(cls, session: Session, resource: Dict[str, Any], parameters: Dict[str, str]) -> None:
        session.client('<service>').action(Some='Parameters')
```

### IAM Role

After the code is written, make sure to update the `PantherRemediationRole` role Policy in both CloudFormation and Terraform:

```yaml
RemediationRole:
  Type: AWS::IAM::Role
  Properties:
    RoleName: !Sub PantherRemediationRole-${MasterAccountRegion} # DO NOT CHANGE! backend.yml CF depends on this name
    Description: The Panther master account assumes this role for automatic remediation of policy violations
    Policies:
      - PolicyName: AllowRemediativeActions
        PolicyDocument:
          Version: 2012-10-17
          Statement:
            - Effect: Allow
              Action:
                - cloudtrail:CreateTrail
                - cloudtrail:StartLogging
                - cloudtrail:UpdateTrail
                - dynamodb:UpdateTable
                - ec2:CreateFlowLogs
                - ec2:StopInstances
                - ec2:TerminateInstances
                - ec2:ModifyImageAttribute
                - guardduty:CreateDetector
                - iam:CreateAccessKey
                - iam:CreateServiceLinkedRole
                - iam:DeleteAccessKey
                - iam:UpdateAccessKey
                - iam:UpdateAccountPasswordPolicy
                - kms:EnableKeyRotation
                - logs:CreateLogDelivery
                - rds:ModifyDBInstance
                - rds:ModifyDBSnapshotAttribute
                - s3:PutBucketAcl
                - s3:PutBucketPublicAccessBlock
                - s3:PutBucketVersioning
                - s3:PutBucketLogging
                - s3:PutEncryptionConfiguration
              Resource: '*'
```

### Testing

1. Deploy your branch
2. Add your new Remediation to an existing or new Policy
3. Click the Remediate button on a Resource
4. Check the `/aws/lambda/panther-aws-remediation` group in CloudWatch if errors occurred.
