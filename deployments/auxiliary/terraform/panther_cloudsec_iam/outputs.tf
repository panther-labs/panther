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

output "panther_audit_role_arn" {
  value       = var.include_audit_role ? aws_iam_role.panther_audit[0].arn : "N/A"
  description = "The ARN of the Panther Audit IAM Role"
}

output "panther_cloud_formation_stackset_execution_role_arn" {
  value       = var.include_stack_set_execution_role ? aws_iam_role.panther_cloud_formation_stackset_execution[0].arn : "N/A"
  description = "The ARN of the CloudFormation StackSet Execution IAM Role"
}

output "panther_remediation_role_arn" {
  value       = var.include_remediation_role ? aws_iam_role.panther_remediation[0].arn : "N/A"
  description = "The ARN of the Panther Auto Remediation IAM Role"
}
