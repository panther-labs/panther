variable "MasterAccountId" {
  type = string
}

###############################################################
# Policy Audit Role
###############################################################

resource "aws_iam_role" "panther_audit" {
  name        = "PantherAudit"
  description = "The Panther master account assumes this role for read-only security scanning"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${var.MasterAccountId}:root"
        },
        "Action" : "sts:AssumeRole",
        "Condition" : {
          "Bool" : { "aws:SecureTransport" : "true" }
        }
      }
    ]
  })

  tags = {
    Application = "Panther"
  }
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.panther_audit.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy" "panther_cloud_formation_stack_drift_detection" {
  name = "PantherCloudFormationStackDriftDetection"
  role = aws_iam_role.panther_audit.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "cloudformation:DetectStackDrift",
          "cloudformation:DetectStackResourceDrift"
        ],
        "Effect" : "Allow",
        "Resource" : "*"
      }
    ]
  })

}

resource "aws_iam_role_policy" "panther_get_waf_acls" {
  name = "GetWAFACLsPolicy"
  role = aws_iam_role.panther_audit.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "waf:GetRule",
          "waf:GetWebACL",
          "waf-regional:GetRule",
          "waf-regional:GetWebACL",
          "waf-regional:GetWebACLForResource"
        ],
        "Effect" : "Allow",
        "Resource" : "*"
      }
    ]
  })

}

resource "aws_iam_role_policy" "panther_get_tags" {
  name = "PantherGetTags"
  role = aws_iam_role.panther_audit.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "dynamodb:ListTagsOfResource",
          "kms:ListResourceTags",
          "waf:ListTagsForResource",
          "waf-regional:ListTagsForResource"
        ],
        "Effect" : "Allow",
        "Resource" : "*"
      }
    ]
  })
}


###############################################################
# CloudFormation StackSet Execution Role
###############################################################

resource "aws_iam_role" "panther_cloud_formation_stackset_execution" {
  name        = "PantherCloudFormationStackSetExecution"
  description = "CloudFormation assumes this role to execute a stack set"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${var.MasterAccountId}:root"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Application = "Panther"
  }
}

resource "aws_iam_role_policy" "panther_manage_cloud_formation_stack" {
  name = "PantherManageCloudFormationStack"
  role = aws_iam_role.panther_cloud_formation_stackset_execution.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "cloudformation:*"
        ],
        "Effect" : "Allow",
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "panther_setup_realtime_events" {
  name = "PantherSetupRealTimeEvents"
  role = aws_iam_role.panther_cloud_formation_stackset_execution.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
          "events:*",
          "sns:*"
        ],
        "Effect" : "Allow",
        "Resource" : "*"
      }
    ]
  })
}


###############################################################
# Remediation Role
###############################################################

resource "aws_iam_role" "panther_remediation" {
  name        = "PantherRemediation"
  description = "The Panther master account assumes this role for automatic remediation of policy violations"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${var.MasterAccountId}:root"
        },
        "Action" : "sts:AssumeRole",
        "Condition" : {
          "Bool" : { "aws:SecureTransport" : "true" }
        }
      }
    ]
  })

  tags = {
    Application = "Panther"
  }
}

resource "aws_iam_role_policy" "panther_allow_remediative_actions" {
  name = "PantherAllowRemediativeActions"
  role = aws_iam_role.panther_remediation.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Action" : [
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
        "Effect" : "Allow",
        "Resource" : "*"
      }
    ]
  })

}


###############################################################
# Outputs
###############################################################

output "panther_audit_role_arn" {
  value       = aws_iam_role.panther_audit.arn
  description = "The Arn of the Panther Audit IAM Role"
}

output "panther_cloud_formation_stackset_execution_role_arn" {
  value       = aws_iam_role.panther_cloud_formation_stackset_execution.arn
  description = "The Arn of the CloudFormation StackSet Execution IAM Role"
}

output "panther_remediation_role_arn" {
  value       = aws_iam_role.panther_remediation.arn
  description = "The Arn of the Panther Auto Remediation IAM Role"
}
