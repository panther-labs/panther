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

variable "aws_partition" {
  type        = string
  description = "AWS partition where this template / Panther is deployed"
  default     = "aws"
}

variable "master_account_id" {
  type        = string
  description = "Panther AWS account ID"
}

variable "master_account_region" {
  type        = string
  description = "Panther AWS account region"
}

variable "include_audit_role" {
  type    = bool
  default = true
}

variable "include_stack_set_execution_role" {
  type    = bool
  default = true
}

variable "include_remediation_role" {
  type    = bool
  default = true
}