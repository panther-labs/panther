# Panther is a Cloud-Native SIEM for the Modern Security Team.
# Copyright (C) 2021 Panther Labs Inc
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

##### IAM roles for an account being scanned by Panther #####

###############################################################
# Policy Audit Role
###############################################################

resource "aws_iam_role" "panther_audit" {
  count       = var.include_audit_role ? 1 : 0
  name        = "PantherAuditRole-${var.master_account_region}"
  description = "The Panther master account assumes this role for read-only security scanning"

  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Principal : {
          AWS : "arn:${var.aws_partition}:iam::${var.master_account_id}:root"
        },
        Action : "sts:AssumeRole",
        Condition : {
          Bool : { "aws:SecureTransport" : true }
        }
      }
    ]
  })

  tags = {
    Application = "Panther"
  }
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  count      = var.include_audit_role ? 1 : 0
  role       = aws_iam_role.panther_audit[0].id
  policy_arn = "arn:${var.aws_partition}:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy" "panther_cloud_formation_stack_drift_detection" {
  count = var.include_audit_role ? 1 : 0
  name  = "CloudFormationStackDriftDetection"
  role  = aws_iam_role.panther_audit[0].id

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "cloudformation:DetectStackDrift",
          "cloudformation:DetectStackResourceDrift"
        ],
        Resource : "*"
      }
    ]
  })
}

# These permissions are not directly required for scanning, but are required by AWS in
# order to perform CloudFormation Stack drift detection on the corresponding resource types.
resource "aws_iam_role_policy" "panther_cloud_formation_stack_drift_detection_supplements" {
  count = var.include_audit_role ? 1 : 0
  name  = "CloudFormationStackDriftDetectionSupplements"
  role  = aws_iam_role.panther_audit[0].id

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "apigateway:GET",
          "lambda:GetFunction",
          "sns:ListTagsForResource"
        ],
        Resource : "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "panther_get_waf_acls" {
  count = var.include_audit_role ? 1 : 0
  name  = "GetWAFACLs"
  role  = aws_iam_role.panther_audit[0].id

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "waf:GetRule",
          "waf:GetWebACL",
          "waf-regional:GetRule",
          "waf-regional:GetWebACL",
          "waf-regional:GetWebACLForResource"
        ],
        Resource : "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "panther_get_tags" {
  count = var.include_audit_role ? 1 : 0
  name  = "GetTags"
  role  = aws_iam_role.panther_audit[0].id

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "dynamodb:ListTagsOfResource",
          "kms:ListResourceTags",
          "waf:ListTagsForResource",
          "waf-regional:ListTagsForResource"
        ],
        Resource : "*"
      }
    ]
  })
}


###############################################################
# CloudFormation StackSet Execution Role
###############################################################

resource "aws_iam_role" "panther_cloud_formation_stackset_execution" {
  count       = var.include_stack_set_execution_role ? 1 : 0
  name        = "PantherCloudFormationStackSetExecutionRole-${var.master_account_region}"
  description = "CloudFormation assumes this role to execute a stack set"

  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Principal : {
          "AWS" : "arn:${var.aws_partition}:iam::${var.master_account_id}:root"
        },
        Action : "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Application = "Panther"
  }
}

resource "aws_iam_role_policy" "panther_manage_cloud_formation_stack" {
  count = var.include_stack_set_execution_role ? 1 : 0
  name  = "ManageCloudFormationStack"
  role  = aws_iam_role.panther_cloud_formation_stackset_execution[0].id

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : "cloudformation:*",
        Resource : "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "panther_setup_realtime_events" {
  count = var.include_stack_set_execution_role ? 1 : 0
  name  = "PantherSetupRealTimeEvents"
  role  = aws_iam_role.panther_cloud_formation_stackset_execution[0].id

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "events:*",
          "sns:*"
        ],
        Resource : "*"
      }
    ]
  })
}


###############################################################
# Remediation Role
###############################################################

resource "aws_iam_role" "panther_remediation" {
  count                = var.include_remediation_role ? 1 : 0
  name                 = "PantherRemediationRole-${var.master_account_region}"
  description          = "The Panther master account assumes this role for automatic remediation of policy violations"
  max_session_duration = 3600 # 1 hour

  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Principal : {
          "AWS" : "arn:${var.aws_partition}:iam::${var.master_account_id}:root"
        },
        Action : "sts:AssumeRole",
        Condition : {
          Bool : { "aws:SecureTransport" : true }
        }
      }
    ]
  })

  tags = {
    Application = "Panther"
  }
}

resource "aws_iam_role_policy" "panther_allow_remediative_actions" {
  count = var.include_remediation_role ? 1 : 0
  name  = "AllowRemediativeActions"
  role  = aws_iam_role.panther_remediation[0].id

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "cloudtrail:CreateTrail",
          "cloudtrail:StartLogging",
          "cloudtrail:UpdateTrail",
          "dynamodb:UpdateTable",
          "ec2:CreateFlowLogs",
          "ec2:ModifyImageAttribute",
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
        Resource : "*"
      }
    ]
  })
}
