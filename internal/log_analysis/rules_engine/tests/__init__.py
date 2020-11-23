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

from unittest import mock

S3_MOCK = mock.MagicMock()
DDB_MOCK = mock.MagicMock()
SNS_MOCK = mock.MagicMock()
LAMBDA_MOCK = mock.MagicMock()


# pylint: disable=unused-argument
def mock_to_return(value: str, **kwargs: int) -> mock.MagicMock:
    if value == 'sns':
        return SNS_MOCK

    if value == 's3':
        return S3_MOCK

    if value == 'dynamodb':
        return DDB_MOCK

    if value == 'lambda':
        return LAMBDA_MOCK

    raise Exception('Unexpected value {}'.format(value))
