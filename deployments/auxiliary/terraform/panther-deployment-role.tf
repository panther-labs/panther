provider "aws" {
  version = "~> 2.0"
}

variable "aws_partition" {
  type    = string
  default = "aws"
}

variable "aws_region" {
  type = string
}

variable "aws_account_id" {
  type = string
}

resource "aws_iam_role" "deployment" {
  name        = "PantherDeployment2"
  description = "IAM role for deploying Panther"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Principal": {
        "AWS": "arn:${var.aws_partition}:iam::${var.aws_account_id}:root"
      },
      "Condition": {
        "Bool": {
          "aws:SecureTransport": true
        }
      }
    }
  ]
}
EOF

  tags = {
    Application = "Panther"
  }
}

resource "aws_iam_policy" "deployment" {
  name        = "PantherDeployment2"
  description = "IAM policy for deploying Panther"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "acm:*",
        "apigateway:*",
        "appsync:*",
        "athena:*",
        "cloudformation:List*",
        "cloudwatch:*",
        "cognito-idp:*",
        "dynamodb:List*",
        "ecr:GetAuthorizationToken",
        "ecs:*",
        "events:*",
        "glue:*",
        "kms:CreateKey",
        "kms:List*",
        "lambda:*EventSourceMapping",
        "lambda:List*",
        "logs:*",
        "sns:List*",
        "sqs:List*"
      ],
      "Resource": "*",
      "Effect": "Allow"
    },
    {
      "Action": "cloudformation:*",
      "Resource": [
        "arn:${var.aws_partition}:cloudformation:${var.aws_region}:${var.aws_account_id}:stack/panther-*",
        "arn:${var.aws_partition}:cloudformation:${var.aws_region}:aws:transform/Serverless-2016-10-31"
      ],
      "Effect": "Allow"
    },
    {
      "Action": "dynamodb:*",
      "Resource": "arn:${var.aws_partition}:dynamodb:${var.aws_region}:${var.aws_account_id}:table/panther-*",
      "Effect": "Allow"
    },
    {
      "Action": [
        "ec2:AssociateRouteTable",
        "ec2:AssociateSubnetCidrBlock",
        "ec2:AssociateVpcCidrBlock",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AttachInternetGateway",
        "ec2:CreateInternetGateway",
        "ec2:CreateRoute",
        "ec2:CreateRouteTable",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSubnet",
        "ec2:CreateTags",
        "ec2:CreateVpc",
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
      "Resource": "*",
      "Effect": "Allow"
    },
    {
      "Action": "ecr:*",
      "Resource": "arn:${var.aws_partition}:ecr:${var.aws_region}:${var.aws_account_id}:repository/panther-*",
      "Effect": "Allow"
    },
    {
      "Action": "execute-api:Invoke",
      "Resource": "arn:${var.aws_partition}:execute-api:${var.aws_region}:${var.aws_account_id}:*",
      "Effect": "Allow"
    },
    {
      "Action": "iam:*",
      "Resource": "arn:${var.aws_partition}:iam::${var.aws_account_id}:role/panther-*",
      "Effect": "Allow"
    },
    {
      "Action": "kms:*",
      "Resource": [
        "arn:${var.aws_partition}:kms:${var.aws_region}:${var.aws_account_id}:alias/panther-*",
        "arn:${var.aws_partition}:kms:${var.aws_region}:${var.aws_account_id}:key/*"
      ],
      "Effect": "Allow"
    },
    {
      "Action": "lambda:*",
      "Resource": [
        "arn:${var.aws_partition}:lambda:${var.aws_region}:${var.aws_account_id}:event-source-mapping:*",
        "arn:${var.aws_partition}:lambda:${var.aws_region}:${var.aws_account_id}:function:panther-*",
        "arn:${var.aws_partition}:lambda:${var.aws_region}:${var.aws_account_id}:layer:panther-*"
      ],
      "Effect": "Allow"
    },
    {
      "Action": "s3:*",
      "Resource": "arn:${var.aws_partition}:s3:::panther-*",
      "Effect": "Allow"
    },
    {
      "Action": "sns:*",
      "Resource": "arn:${var.aws_partition}:sns:${var.aws_region}:${var.aws_account_id}:panther-*",
      "Effect": "Allow"
    },
    {
      "Action": "sqs:*",
      "Resource": "arn:${var.aws_partition}:sqs:${var.aws_region}:${var.aws_account_id}:panther-*",
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "deployment" {
  role       = aws_iam_role.deployment.name
  policy_arn = aws_iam_policy.deployment.arn
}
