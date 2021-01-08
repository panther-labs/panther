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


class RemediationException(Exception):
    """Base exception class for remediations"""


class RemediationDoesNotExist(RemediationException):
    """Exception thrown when defined remediation couldn't be found"""


class RemediationAlreadyExists(RemediationException):
    """Exception thrown when a remediation with the same id already exists"""


class RemediationNotAuthorized(RemediationException):
    """Exception thrown when remediation was not authorized to perform operation on AWS resource"""


class InvalidInput(Exception):
    """Exception thrown when input to Lambda is invalid"""


class InvalidParameterException(RemediationException):
    """Exception thrown when a remediation was provided an an invalid parameter"""
