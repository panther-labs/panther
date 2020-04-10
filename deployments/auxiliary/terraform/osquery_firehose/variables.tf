variable "aws_account_id" {
  type        = string
  description = "AWS account where this template will be deployed"
}

variable "aws_region" {
  type        = string
  description = "AWS region where this template will be deployed"
}

variable "s3_notifications_topic" {
  type        = string
  description = "SNS topic arn to send S3 notifications for pulling data"
}
