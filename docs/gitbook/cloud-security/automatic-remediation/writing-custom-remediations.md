# Writing a Remediation

To write a new remediation, follow the steps below.

Currently custom automatic remediations are only possible with "from source" deployments. If you have a pre-packaged deployment, you may deploy on top of it with a "from-source" deployment.

## Code Structure

In the [`./internal/compliance/remediation_aws/src/app/remediations`](https://github.com/panther-labs/panther/tree/master/internal/compliance/remediation_aws/src/app/remediations) folder inside the [Panther repo](https://github.com/panther-labs/panther), add a Python file called `aws_<service>_name_of_remediation` with the following structure:

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

## IAM Role Updates

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

## Testing

1. Deploy your branch
2. Add your new Remediation to an existing or new Policy
3. Click the Remediate button on a Resource
4. Check the `/aws/lambda/panther-aws-remediation` group in CloudWatch if errors occurred.
