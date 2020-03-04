locals {
  MasterAccountId = "123456789012"
}

###############################################################
# Policy Audit Role
###############################################################

resource "aws_iam_role" "PantherAudit" {
  name               = "PantherAudit"
  description        = "The Panther master account assumes this role for read-only security scanning"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${local.MasterAccountId}:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
	"Bool": {"aws:SecureTransport": "true"}
	}    
    }
  ]
}
EOF

  tags = {
    Name        = "Panther Audit Role"
    Description = "The Panther master account assumes this role for read-only security scanning"
    Owner       = "SEC"
    terraform   = true
    source_repo = "https://git.lo/terraform/terraform-aws-root"
    Application = "Panther"
  }
}

resource "aws_iam_role_policy_attachment" "SecurityAudit" {
  role       = "${aws_iam_role.PantherAudit.name}"
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_policy" "PantherCloudFormationStackDriftDetection" {
  name        = "PantherCloudFormationStackDriftDetection"
  description = "Allows PantherAudit Role to detect CloudFormation stack drift"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "cloudformation:DetectStackDrift",
        "cloudformation:DetectStackResourceDrift"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

}

resource "aws_iam_policy_attachment" "PantherCloudFormationStackDriftDetection" {
  name       = "PantherCloudFormationStackDriftDetection"
  roles      = ["${aws_iam_role.PantherAudit.name}"]
  policy_arn = "${aws_iam_policy.PantherCloudFormationStackDriftDetection.arn}"
}


resource "aws_iam_policy" "PantherGetWAFACLs" {
  name        = "GetWAFACLsPolicy"
  description = "Allows PantherAudit Role to get WAF ACLs"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "waf:GetRule",
        "waf:GetWebACL",
        "waf-regional:GetRule",
        "waf-regional:GetWebACL",
        "waf-regional:GetWebACLForResource"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

}

resource "aws_iam_policy_attachment" "PantherGetWAFACLs" {
  name       = "PantherGetWAFACLs"
  roles      = ["${aws_iam_role.PantherAudit.name}"]
  policy_arn = "${aws_iam_policy.PantherGetWAFACLs.arn}"
}

resource "aws_iam_policy" "PantherGetTags" {
  name        = "PantherGetTags"
  description = "Allows PantherAudit Role to get tags of specified resources"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "dynamodb:ListTagsOfResource",
        "kms:ListResourceTags",
        "waf:ListTagsForResource",
        "waf-regional:ListTagsForResource"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy_attachment" "PantherGetTags" {
  name       = "PantherGetTags"
  roles      = ["${aws_iam_role.PantherAudit.name}"]
  policy_arn = "${aws_iam_policy.PantherGetTags.arn}"
}


###############################################################
# CloudFormation Stack Set Execution Role
###############################################################

resource "aws_iam_role" "PantherCloudFormationStackSetExecution" {
  name               = "PantherCloudFormationStackSetExecution"
  description        = "CloudFormation assumes this role to execute a stack set"
  assume_role_policy = <<EOF
{ 
  "Version": "2012-10-17",
  "Statement": [
    { 
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${local.MasterAccountId}:root"
      },
      "Action": "sts:AssumeRole"
} 
  ]
}
EOF

  tags = {
    Name        = "Panther CloudFormation Stack Set Execution Role"
    Description = "CloudFormation assumes this role to execute a stack set"
    Owner       = "SEC"
    terraform   = true
    source_repo = "https://git.lo/terraform/terraform-aws-root"
    Application = "Panther"
  }
}

resource "aws_iam_policy" "PantherManageCloudFormationStack" {
  name        = "PantherManageCloudFormationStack"
  description = "Allows PantherCloudFormationStackSetExecution Role to administer all CloudFormation resources"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "cloudformation:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy_attachment" "PantherManageCloudFormationStack" {
  name       = "PantherManageCloudFormationStack"
  roles      = ["${aws_iam_role.PantherCloudFormationStackSetExecution.name}"]
  policy_arn = "${aws_iam_policy.PantherManageCloudFormationStack.arn}"
}

resource "aws_iam_policy" "PantherSetupRealTimeEvents" {
  name        = "PantherSetupRealTimeEvents"
  description = "Allows PantherCloudFormationStackSetExecution Role to administer all events and SNS"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "events:*",
	"sns:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy_attachment" "PantherSetupRealTimeEvents" {
  name       = "PantherSetupRealTimeEvents"
  roles      = ["${aws_iam_role.PantherCloudFormationStackSetExecution.name}"]
  policy_arn = "${aws_iam_policy.PantherSetupRealTimeEvents.arn}"
}


###############################################################
# Remediation Role
###############################################################

resource "aws_iam_role" "PantherRemediation" {
  name               = "PantherRemediation"
  description        = "The Panther master account assumes this role for automatic remediation of policy violations"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${local.MasterAccountId}:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
	"Bool": {"aws:SecureTransport": "true"}
	}    
    }
  ]
}
EOF

  tags = {
    Name        = "Panther Remediation Role"
    Description = "The Panther master account assumes this role for automatic remediation of policy violations"
    Owner       = "SEC"
    terraform   = true
    source_repo = "https://git.lo/terraform/terraform-aws-root"
    Application = "Panther"
  }
}

resource "aws_iam_policy" "PantherAllowRemediativeActions" {
  name        = "PantherAllowRemediativeActions"
  description = "Allows Panther Remediation Role to perform numerous actions to remediate policy violations"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "cloudtrail:CreateTrail",
        "cloudtrail:CreateTrail",
        "cloudtrail:StartLogging",
        "cloudtrail:UpdateTrail",
        "dynamodb:UpdateTable",
        "ec2:CreateFlowLogs",
        "ec2:StopInstances",
        "ec2:TerminateInstances",
        "guardduty:CreateDetector",
        "iam:CreateAccessKey",
        "iam:CreateServiceLinkedRole",
        "iam:DeleteAccessKey",
        "iam:UpdateAccessKey",
        "iam:UpdateAccountPasswordPolicy",
        "kms:EnableKeyRotation",
        "logs:CreateLogDelivery",
        "rds:ModifyDBInstance",
        "rds:ModifyDBSnapshotAttribute",
        "s3:PutBucketAcl",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketVersioning",
        "s3:PutBucketLogging",
        "s3:PutEncryptionConfiguration"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

}

resource "aws_iam_policy_attachment" "PantherAllowRemediativeActions" {
  name       = "PantherAllowRemediativeActions"
  roles      = ["${aws_iam_role.PantherRemediation.name}"]
  policy_arn = "${aws_iam_policy.PantherAllowRemediativeActions.arn}"
}


###############################################################
# Outputs
###############################################################

output "PantherAuditRoleArn" {
  value       = aws_iam_role.PantherAudit.arn
  description = "The Arn of the Panther Audit IAM Role"
}

output "PantherCloudFormationStackSetExecutionRoleArn" {
  value       = aws_iam_role.PantherCloudFormationStackSetExecution.arn
  description = "The Arn of the CloudFormation StackSet Execution IAM Role"
}

output "PantherRemediationRoleArn" {
  value       = aws_iam_role.PantherRemediation.arn
  description = "The Arn of the Panther Auto Remediation IAM Role"
}
