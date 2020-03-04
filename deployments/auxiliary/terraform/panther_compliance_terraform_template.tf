locals {
  MasterAccountId = "<insert accountID for account running Panther>"
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
    Application = "Panther"
  }
}

resource "aws_iam_role_policy_attachment" "SecurityAudit" {
  role       = "${aws_iam_role.PantherAudit.name}"
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy" "PantherCloudFormationStackDriftDetection" {
  name        = "PantherCloudFormationStackDriftDetection"
  role        = aws_iam_role.PantherAudit.id

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

resource "aws_iam_role_policy" "PantherGetWAFACLs" {
  name        = "GetWAFACLsPolicy"
  role        = aws_iam_role.PantherAudit.id

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

resource "aws_iam_role_policy" "PantherGetTags" {
  name        = "PantherGetTags"
  role        = aws_iam_role.PantherAudit.id

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


###############################################################
# CloudFormation StackSet Execution Role
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
    Name        = "Panther CloudFormation StackSet Execution Role"
    Description = "CloudFormation assumes this role to execute a stack set"
    Application = "Panther"
  }
}

iesource "aws_iam_role_policy" "PantherManageCloudFormationStack" {
  name        = "PantherManageCloudFormationStack"
  role        = aws_iam_role.PantherCloudFormationStackSetExecution.id

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

resource "aws_iam_role_policy" "PantherSetupRealTimeEvents" {
  name        = "PantherSetupRealTimeEvents"
  role        = aws_iam_role.PantherCloudFormationStackSetExecution.id

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
    Application = "Panther"
  }
}

resource "aws_iam_role_policy" "PantherAllowRemediativeActions" {
  name        = "PantherAllowRemediativeActions"
  role        = aws_iam_role.PantherRemediation.id

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
