# NOTE: this resource must be applied in the Panther master account, not in a satellite account. Each monitored account requires its own topic subscription resource. In Terraform, this can be accomplished for multiple accounts using a for_each expression.

resource "aws_sns_topic_subscription" "panther_cloudwatch" {
  for_each = {var.satellite_accounts}
  
  endpoint             = "arn:${var.aws_partition}:sqs:${var.panther_region}:${var.master_account_id}:panther-aws-events-queue"
  protocol             = "sqs"
  raw_message_delivery = true
  topic_arn            = "arn:${var.aws_partition}:sns:${var.satellite_account_region}:${each.key}:panther-cloudwatch-events-topic"
}

variable "satellite_accounts" {
  type = list(string)

  default = [
    "123456789012",
    "123456789013"
  ]
}
