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

####
# This template configures Panther's real-time CloudWatch Event collection process.
# It works by creating CloudWatch Event rules which feed to Panther's SQS Queue proxied by
# a local SNS topic in each region.

resource "aws_sns_topic" "panther_events" {
  name = var.sns_topic_name
}

resource "aws_sns_topic_policy" "panther_events" {
  arn = aws_sns_topic.panther_events.arn

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Sid : "CloudWatchEventsPublish",
        Effect : "Allow",
        Principal : {
          Service : "events.amazonaws.com"
        }
        Action : "sns:Publish",
        Resource : aws_sns_topic.panther_events.arn
      },
      {
        Sid : "CrossAccountSubscription",
        Effect : "Allow",
        Principal : {
          AWS : "arn:${var.aws_partition}:iam::${var.master_account_id}:root"
        }
        Action : "sns:Subscribe",
        Resource : aws_sns_topic.panther_events.arn
      }
    ]
  })
}

resource "aws_cloudwatch_event_rule" "cloudtrail" {
  description = "Collect CloudTrail API calls"
  is_enabled  = true

  event_pattern = jsonencode({
    detail-type : [
      "AWS API Call via CloudTrail"
    ]
  })
}

resource "aws_cloudwatch_event_target" "cloudtrail" {
  rule      = aws_cloudwatch_event_rule.cloudtrail.name
  target_id = "panther-collect-cloudtrail-events"
  arn       = aws_sns_topic.panther_events.arn
}
