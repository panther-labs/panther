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

# Sample template for gathering osquery logs into S3 via Firehose.

### Osquery Firehose, Role, and Bucket ###

resource "aws_kinesis_firehose_delivery_stream" "osquery_data_firehose" {
  name        = "osquery-data-${var.aws_region}"
  destination = "extended_s3"

  extended_s3_configuration {
    bucket_arn         = aws_s3_bucket.osquery_data_bucket.arn
    role_arn           = aws_iam_role.osquery_data_firehose_role.arn
    prefix             = "osquery/"
    compression_format = "GZIP"

    # Data is flushed once one of the buffer hints are satisfied
    buffer_interval = 300
    buffer_size     = 128
  }
}

resource "aws_iam_role" "osquery_data_firehose_role" {
  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Sid : "FirehoseServiceAssumeRole"
        Effect : "Allow",
        Principal : {
          Service : "firehose.amazonaws.com"
        },
        Action : "sts:AssumeRole",
        Condition : {
          StringEquals : { "sts:ExternalId" : var.aws_account_id }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "osquery_firehose_managed_policy" {
  description = "Firehose permissions to write to data bucket"
  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Sid : "AllowS3Delivery"
        Effect : "Allow",
        Action : [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ],
        Resource : [
          aws_s3_bucket.osquery_data_bucket.arn,
          "${aws_s3_bucket.osquery_data_bucket.arn}/osquery/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "osquery" {
  policy_arn = aws_iam_policy.osquery_firehose_managed_policy.arn
  role       = aws_iam_role.osquery_data_firehose_role.id
}

resource "aws_s3_bucket" "osquery_data_bucket" {
  acl = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  # Short expiration because this data is sent to Panther.
  # This can be adjusted per your individual needs.
  lifecycle_rule {
    id      = "30DayExpiration"
    enabled = true
    expiration {
      days = 30
    }
    noncurrent_version_expiration {
      days = 30
    }
  }
}

resource "aws_s3_bucket_policy" "osquery_data_bucket" {
  bucket     = aws_s3_bucket.osquery_data_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.osquery_data_bucket]

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Deny",
        Principal : "*",
        Action : "s3:GetObject",
        Resource : "${aws_s3_bucket.osquery_data_bucket.arn}/*"
        Condition : {
          Bool : { "aws:SecureTransport" : false }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_public_access_block" "osquery_data_bucket" {
  bucket                  = aws_s3_bucket.osquery_data_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_notification" "osquery_data_bucket" {
  bucket = aws_s3_bucket.osquery_data_bucket.id

  topic {
    events = [
      "s3:ObjectCreated:*"
    ]
    topic_arn = var.s3_notifications_topic
  }
}

### EC2 Instance Profile ###
resource "aws_iam_instance_profile" "osquery_firehose" {
  name = "OsqueryFirehoseWriteOnly-${var.aws_region}"
  role = aws_iam_role.osquery_firehose_instance_profile.id
}

resource "aws_iam_role" "osquery_firehose_instance_profile" {
  name = "OsqueryFirehoseAssumeRole-${var.aws_region}"

  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Principal : {
          Service : "ec2.amazonaws.com"
        },
        Action : "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "osquery_firehose_instance_profile" {
  name = "AssumeFirehoseRole"
  role = aws_iam_role.osquery_firehose_instance_profile.id

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : "sts:AssumeRole",
        Resource : aws_iam_role.osquery_firehose_write_only.arn
      }
    ]
  })
}

resource "aws_iam_role" "osquery_firehose_write_only" {
  name = "OsqueryFirehoseWriteOnly-${var.aws_region}"

  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Principal : {
          AWS : "arn:aws:iam::${var.aws_account_id}:root"
        },
        Action : "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "osquery_firehose_write_only" {
  name = "FirehosePutRecords"
  role = aws_iam_role.osquery_firehose_write_only.id

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "firehose:PutRecord",
          "firehose:PutRecordBatch"
        ]
        Resource : aws_kinesis_firehose_delivery_stream.osquery_data_firehose.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "kinesis_read_only" {
  role       = aws_iam_role.osquery_firehose_write_only.id
  policy_arn = "arn:aws:iam::aws:policy/AmazonKinesisFirehoseReadOnlyAccess"
}
