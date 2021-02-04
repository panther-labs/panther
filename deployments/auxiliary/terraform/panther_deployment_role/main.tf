# Panther is a Cloud-Native SIEM for the Modern Security Team.
# Copyright (C) 2020 Panther Labs Inc
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

resource "aws_iam_role" "deployment" {
  name        = var.deployment_role_name
  description = "IAM role for deploying Panther"

  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Principal : {
          AWS : var.assume_role_principal == "" ? "arn:${var.aws_partition}:iam::${var.aws_account_id}:root" : var.assume_role_principal
        }
        Action : "sts:AssumeRole",
        Condition : {
          Bool : { "aws:SecureTransport" : true }
        }
      },
      {
        Effect : "Allow",
        Principal : {
          Service : "cloudformation.amazonaws.com"
        }
        Action : "sts:AssumeRole",
        Condition : {
          Bool : { "aws:SecureTransport" : true }
        }
      },
    ]
  })

  tags = {
    Application = "Panther"
  }
}

resource "aws_iam_policy" "deployment" {
  name = "PantherDeployment"

  # DO NOT EDIT - policy is automatically copied from CloudFormation by 'mage fmt'
  policy = <<EOT
{
  "Statement": [
    {
      "Action": [
        "acm:*",
        "apigateway:*",
        "application-autoscaling:DeleteScalingPolicy",
        "application-autoscaling:DeregisterScalableTarget",
        "application-autoscaling:DescribeScalingPolicies",
        "application-autoscaling:DescribeScalableTargets",
        "application-autoscaling:PutScalingPolicy",
        "application-autoscaling:RegisterScalableTarget",
        "appsync:*",
        "athena:*",
        "cloudformation:Describe*",
        "cloudformation:List*",
        "cloudtrail:DescribeTrails",
        "cloudtrail:CreateTrail",
        "cloudwatch:*",
        "cognito-idp:*",
        "dynamodb:List*",
        "ec2:AllocateAddress",
        "ec2:AssociateRouteTable",
        "ec2:AssociateSubnetCidrBlock",
        "ec2:AssociateVpcCidrBlock",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AttachInternetGateway",
        "ec2:CreateFlowLogs",
        "ec2:CreateInternetGateway",
        "ec2:CreateNatGateway",
        "ec2:CreateRoute",
        "ec2:CreateRouteTable",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSubnet",
        "ec2:CreateTags",
        "ec2:CreateVpc",
        "ec2:DeleteFlowLogs",
        "ec2:DeleteInternetGateway",
        "ec2:DeleteNatGateway",
        "ec2:DeleteRoute",
        "ec2:DeleteRouteTable",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSubnet",
        "ec2:DeleteTags",
        "ec2:DeleteVpc",
        "ec2:Describe*",
        "ec2:DetachInternetGateway",
        "ec2:DisassociateAddress",
        "ec2:DisassociateRouteTable",
        "ec2:DisassociateSubnetCidrBlock",
        "ec2:ModifySubnetAttribute",
        "ec2:ModifyVpcAttribute",
        "ec2:ReleaseAddress",
        "ec2:ReplaceRoute",
        "ec2:ReplaceRouteTableAssociation",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
        "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientRootAccess",
        "elasticfilesystem:ClientWrite",
        "elasticfilesystem:CreateAccessPoint",
        "elasticfilesystem:CreateFileSystem",
        "elasticfilesystem:CreateMountTarget",
        "elasticfilesystem:DeleteAccessPoint",
        "elasticfilesystem:DeleteFileSystem",
        "elasticfilesystem:DeleteMountTarget",
        "elasticfilesystem:DescribeAccessPoints",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeFileSystemPolicy",
        "elasticfilesystem:DescribeLifecycleConfiguration",
        "elasticfilesystem:DescribeMountTargets",
        "elasticfilesystem:PutLifecycleConfiguration",
        "elasticfilesystem:PutFileSystemPolicy",
        "elasticfilesystem:ListTagsForResource",
        "elasticfilesystem:TagResource",
        "elasticfilesystem:UntagResource",
        "elasticloadbalancing:*",
        "ecr:GetAuthorizationToken",
        "ecs:*",
        "events:*",
        "firehose:DescribeDeliveryStream",
        "firehose:CreateDeliveryStream",
        "firehose:DeleteDeliveryStream",
        "firehose:ListDeliveryStreams",
        "glue:*",
        "guardduty:CreatePublishingDestination",
        "guardduty:ListDetectors",
        "kms:CreateKey",
        "kms:List*",
        "lambda:*EventSourceMapping",
        "lambda:List*",
        "logs:*",
        "s3:ListAllMyBuckets",
        "sns:List*",
        "sqs:List*",
        "states:CreateStateMachine",
        "states:TagResource",
        "states:UntagResource"
      ],
      "Effect": "Allow",
      "Resource": "*"
    },
    {
      "Action": [
        "cloudtrail:AddTags",
        "cloudtrail:DeleteTrail",
        "cloudtrail:PutEventSelectors",
        "cloudtrail:StartLogging",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail"
      ],
      "Effect": "Allow",
      "Resource": "arn:${var.aws_partition}:cloudtrail:*:${var.aws_account_id}:trail/panther-cloudtrail-*"
    },
    {
      "Action": "cloudformation:*",
      "Effect": "Allow",
      "Resource": [
        "arn:${var.aws_partition}:cloudformation:*:${var.aws_account_id}:stack/panther*",
        "arn:${var.aws_partition}:cloudformation:*:${var.aws_account_id}:stackset/panther*"
      ]
    },
    {
      "Action": "cloudformation:*",
      "Effect": "Allow",
      "Resource": "arn:${var.aws_partition}:cloudformation:*:aws:transform/Serverless-2016-10-31"
    },
    {
      "Action": "serverlessrepo:*",
      "Effect": "Allow",
      "Resource": "arn:${var.aws_partition}:serverlessrepo:*:*:applications/*"
    },
    {
      "Action": [
        "lambda:GetFunction",
        "lambda:CreateFunction"
      ],
      "Effect": "Allow",
      "Resource": "arn:${var.aws_partition}:lambda:*:${var.aws_account_id}:function:ddb"
    },
    {
      "Action": "s3:GetObject",
      "Effect": "Allow",
      "Resource": "arn:${var.aws_partition}:s3:::awsserverlessrepo-changesets-*"
    },
    {
      "Action": "dynamodb:*",
      "Effect": "Allow",
      "Resource": "arn:${var.aws_partition}:dynamodb:*:${var.aws_account_id}:table/panther-*"
    },
    {
      "Action": "ecr:*",
      "Effect": "Allow",
      "Resource": "arn:${var.aws_partition}:ecr:*:${var.aws_account_id}:repository/panther-*"
    },
    {
      "Action": "execute-api:Invoke",
      "Effect": "Allow",
      "Resource": "arn:${var.aws_partition}:execute-api:*:${var.aws_account_id}:*"
    },
    {
      "Action": "firehose:*",
      "Effect": "Allow",
      "Resource": "arn:${var.aws_partition}:firehose:*:${var.aws_account_id}:deliverystream/panther-*"
    },
    {
      "Action": "iam:*",
      "Effect": "Allow",
      "Resource": [
        "arn:${var.aws_partition}:iam::${var.aws_account_id}:role/AWSServiceRole*",
        "arn:${var.aws_partition}:iam::${var.aws_account_id}:role/aws-service-role/*",
        "arn:${var.aws_partition}:iam::${var.aws_account_id}:role/panther-*",
        "arn:${var.aws_partition}:iam::${var.aws_account_id}:role/Panther*",
        "arn:${var.aws_partition}:iam::${var.aws_account_id}:server-certificate/panther/*"
      ]
    },
    {
      "Action": "kms:*",
      "Effect": "Allow",
      "Resource": [
        "arn:${var.aws_partition}:kms:*:${var.aws_account_id}:alias/panther-*",
        "arn:${var.aws_partition}:kms:*:${var.aws_account_id}:key/*"
      ]
    },
    {
      "Action": "lambda:*",
      "Effect": "Allow",
      "Resource": [
        "arn:${var.aws_partition}:lambda:*:${var.aws_account_id}:event-source-mapping:*",
        "arn:${var.aws_partition}:lambda:*:${var.aws_account_id}:function:panther-*",
        "arn:${var.aws_partition}:lambda:*:${var.aws_account_id}:layer:panther-*",
        "arn:${var.aws_partition}:lambda:*:${var.aws_account_id}:function:ddb"
      ]
    },
    {
      "Action": "s3:*",
      "Effect": "Allow",
      "Resource": "arn:${var.aws_partition}:s3:::panther-*"
    },
    {
      "Action": "sns:*",
      "Effect": "Allow",
      "Resource": "arn:${var.aws_partition}:sns:*:${var.aws_account_id}:panther-*"
    },
    {
      "Action": "sqs:*",
      "Effect": "Allow",
      "Resource": "arn:${var.aws_partition}:sqs:*:${var.aws_account_id}:panther-*"
    },
    {
      "Action": "states:*",
      "Effect": "Allow",
      "Resource": [
        "arn:${var.aws_partition}:states:*:${var.aws_account_id}:activity:panther-*",
        "arn:${var.aws_partition}:states:*:${var.aws_account_id}:execution:panther-*:*",
        "arn:${var.aws_partition}:states:*:${var.aws_account_id}:stateMachine:panther-*"
      ]
    }
  ],
  "Version": "2012-10-17"
}
EOT
}

resource "aws_iam_role_policy_attachment" "deployment" {
  role       = aws_iam_role.deployment.name
  policy_arn = aws_iam_policy.deployment.arn
}
