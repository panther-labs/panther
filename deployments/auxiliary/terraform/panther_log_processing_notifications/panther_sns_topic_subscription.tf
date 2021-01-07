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

# NOTE: this resource must be applied in the Panther master account, not in a satellite account.
# Each monitored account requires its own topic subscription resource. In Terraform, this can be 
# accomplished for multiple accounts using a for_each expression.

resource "aws_sns_topic_subscription" "subscription" {
  for_each = toset(var.satellite_accounts)

  endpoint             = "arn:${var.aws_partition}:sqs:${var.panther_region}:${var.master_account_id}:panther-input-data-notifications-queue"
  protocol             = "sqs"
  raw_message_delivery = false
  topic_arn            = "arn:${var.aws_partition}:sns:${var.satellite_account_region}:${each.key}:panther-notifications-topic"
}

variable "satellite_accounts" {
  description = "The account numbers of satellite accounts that will have the Log Processing Notifications module applied to them"
  type        = list(string)
}
