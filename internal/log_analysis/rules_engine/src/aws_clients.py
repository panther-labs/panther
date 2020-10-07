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

import boto3
from botocore.config import Config

# https://boto3.amazonaws.com/v1/documentation/api/latest/guide/retries.html
_BOTO_CONFIG = Config(retries={'max_attempts': 10, 'mode': 'standard'})

# AWS Clients
S3_CLIENT = boto3.client('s3', config=_BOTO_CONFIG)
SNS_CLIENT = boto3.client('sns', config=_BOTO_CONFIG)
DDB_CLIENT = boto3.client('dynamodb', config=_BOTO_CONFIG)
