# Panther is a Cloud-Native SIEM for the Modern Security Team.
# Copyright (C) 2021 Panther Labs Inc
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
# Panther IAM Role for creating and managing StackSets. The purpose of this role is to assume
# the execution IAM roles in each target account for configuring various Panther infrastructure.

resource "aws_iam_role" "stack_set_admin" {
  name = "PantherCloudFormationStackSetAdminRole-${var.aws_region}"

  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Principal : {
          Service : "cloudformation.amazonaws.com"
        },
        Action : "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "stack_set_admin" {
  name = "AssumeRolesInTargetAccounts"
  role = aws_iam_role.stack_set_admin.id

  policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : "sts:AssumeRole",
        Resource : "arn:${var.aws_partition}:iam::*:role/PantherCloudFormationStackSetExecutionRole-${var.aws_region}"
      }
    ]
  })
}