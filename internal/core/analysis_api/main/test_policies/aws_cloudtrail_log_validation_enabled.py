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

# Tags: ['CIS', 'AWS Managed Rules - Management and Governance']
# OutputIds: ['621a1c7b-273f-4a03-99a7-5c661de5b0e8']
def policy(resource):
    # Explicit check for True as the value may be None, and we want to return a bool not a NoneType
    return resource['Info']['LogFileValidationEnabled'] is True
