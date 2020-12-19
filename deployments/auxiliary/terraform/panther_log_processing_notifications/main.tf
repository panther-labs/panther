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


#####
# Sets up an SNS topic.

# This topic is used to notify the Panther master account whenever new data is written to the
# LogProcessing bucket.
resource "aws_sns_topic" "topic" {
  name = var.sns_topic_name
}

resource "aws_sns_topic_policy" "policy" {
  arn = aws_sns_topic.topic.arn

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      # Reference: https://amzn.to/2ouFmhK
      {
        Sid : "AllowS3EventNotifications",
        Effect : "Allow",
        Principal : {
          Service : "s3.amazonaws.com"
        },
        Action : "sns:Publish",
        Resource : aws_sns_topic.topic.arn
      },
      {
        Sid : "AllowCloudTrailNotification",
        Effect : "Allow",
        Principal : {
          Service : "cloudtrail.amazonaws.com"
        },
        Action : "sns:Publish",
        Resource : aws_sns_topic.topic.arn
      },
      {
        Sid : "AllowSubscriptionToPanther",
        Effect : "Allow",
        Principal : {
          AWS : "arn:${var.aws_partition}:iam::${var.master_account_id}:root"
        },
        Action : "sns:Subscribe",
        Resource : aws_sns_topic.topic.arn
      }
    ]
  })
}
