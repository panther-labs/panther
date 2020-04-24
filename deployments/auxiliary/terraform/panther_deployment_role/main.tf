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
  name        = "PantherDeploymentRole"
  description = "IAM role for deploying Panther"

  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Principal : {
          AWS : "arn:${var.aws_partition}:iam::${var.aws_account_id}:root"
        }
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

resource "aws_iam_policy" "deployment" {
  name = "PantherDeployment"

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "acm:*",
          "apigateway:*",
          "appsync:*",
          "athena:*",
          "cloudformation:Describe*",
          "cloudformation:List*",
          "cloudwatch:*",
          "cognito-idp:*",
          "dynamodb:List*",
          "ecr:GetAuthorizationToken",
          "ecs:*",
          "events:*",
          "glue:*",
          "guardduty:CreatePublishingDestination",
          "guardduty:ListDetectors",
          "kms:CreateKey",
          "kms:List*",
          "lambda:*EventSourceMapping",
          "lambda:List*",
          "logs:*",
          "sns:List*",
          "sqs:List*",
          "states:CreateStateMachine",
          "states:TagResource",
          "states:UntagResource",
        ],
        Resource : "*"
      },
      {
        Effect : "Allow",
        Action : "cloudformation:*",
        Resource : [
          "arn:${var.aws_partition}:cloudformation:*:${var.aws_account_id}:stack/panther-*",
          "arn:${var.aws_partition}:cloudformation:*:${var.aws_account_id}:stackset/panther-*",
          "arn:${var.aws_partition}:cloudformation:*:aws:transform/Serverless-2016-10-31",
        ]
      },
      {
        Effect : "Allow",
        Action : "dynamodb:*",
        Resource : "arn:${var.aws_partition}:dynamodb:*:${var.aws_account_id}:table/panther-*"
      },
      {
        Effect : "Allow",
        Action : [
          "ec2:AssociateRouteTable",
          "ec2:AssociateSubnetCidrBlock",
          "ec2:AssociateVpcCidrBlock",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AttachInternetGateway",
          "ec2:CreateFlowLogs",
          "ec2:CreateInternetGateway",
          "ec2:CreateRoute",
          "ec2:CreateRouteTable",
          "ec2:CreateSecurityGroup",
          "ec2:CreateSubnet",
          "ec2:CreateTags",
          "ec2:CreateVpc",
          "ec2:DeleteFlowLogs",
          "ec2:DeleteInternetGateway",
          "ec2:DeleteRoute",
          "ec2:DeleteRouteTable",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteSubnet",
          "ec2:DeleteTags",
          "ec2:DeleteVpc",
          "ec2:Describe*",
          "ec2:DetachInternetGateway",
          "ec2:DisassociateRouteTable",
          "ec2:DisassociateSubnetCidrBlock",
          "ec2:ModifySubnetAttribute",
          "ec2:ModifyVpcAttribute",
          "ec2:ReplaceRoute",
          "ec2:ReplaceRouteTableAssociation",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
          "elasticloadbalancing:*"
        ],
        Resource : "*"
      },
      {
        Effect : "Allow",
        Action : "ecr:*",
        Resource : "arn:${var.aws_partition}:ecr:*:${var.aws_account_id}:repository/panther-*"
      },
      {
        Effect : "Allow",
        Action : "execute-api:Invoke",
        Resource : "arn:${var.aws_partition}:execute-api:*:${var.aws_account_id}:*"
      },
      {
        Effect : "Allow",
        Action : "iam:*",
        Resource : [
          "arn:${var.aws_partition}:iam::${var.aws_account_id}:role/panther-*",
          "arn:${var.aws_partition}:iam::${var.aws_account_id}:role/Panther-*",
          "arn:${var.aws_partition}:iam::${var.aws_account_id}:server-certificate/panther/*"
        ]
      },
      {
        Effect : "Allow",
        Action : "kms:*",
        Resource : [
          "arn:${var.aws_partition}:kms:*:${var.aws_account_id}:alias/panther-*",
          "arn:${var.aws_partition}:kms:*:${var.aws_account_id}:key/*"
        ]
      },
      {
        Effect : "Allow",
        Action : "lambda:*",
        Resource : [
          "arn:${var.aws_partition}:lambda:*:${var.aws_account_id}:event-source-mapping:*",
          "arn:${var.aws_partition}:lambda:*:${var.aws_account_id}:function:panther-*",
          "arn:${var.aws_partition}:lambda:*:${var.aws_account_id}:layer:panther-*",
        ]
      },
      {
        Effect : "Allow",
        Action : "s3:*",
        Resource : "arn:${var.aws_partition}:s3:::panther-*"
      },
      {
        Effect : "Allow",
        Action : "sns:*",
        Resource : "arn:${var.aws_partition}:sns:*:${var.aws_account_id}:panther-*",
      },
      {
        Effect : "Allow",
        Action : "sqs:*",
        Resource : "arn:${var.aws_partition}:sqs:*:${var.aws_account_id}:panther-*",
      },
      {
        Effect : "Allow",
        Action : "states:*",
        Resource : [
          "arn:${var.aws_partition}:states:*:${var.aws_account_id}:activity:panther-*",
          "arn:${var.aws_partition}:states:*:${var.aws_account_id}:execution:panther-*:*",
          "arn:${var.aws_partition}:states:*:${var.aws_account_id}:stateMachine:panther-*",
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "deployment" {
  role       = aws_iam_role.deployment.name
  policy_arn = aws_iam_policy.deployment.arn
}
