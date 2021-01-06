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

variable "aws_partition" {
  type        = string
  description = "AWS partition of the account running the Panther backend"
  default     = "aws"
}

variable "panther_region" {
  type        = string
  description = "The AWS region where you have deployed Panther"
}

variable "satellite_account_region" {
  type        = string
  description = "Account which Panther is pulling or receiving log data from"
}

variable "master_account_id" {
  type        = string
  description = "AWS account ID of the account running the Panther backend"
}

# topic name is hardcoded in Panther infra; see master account panther-aws-event-processor
# SQS queue access policy
variable "sns_topic_name" {
  type        = string
  description = "The name of the SNS topic"
  default     = "-PantherEventsTopic-"
}
