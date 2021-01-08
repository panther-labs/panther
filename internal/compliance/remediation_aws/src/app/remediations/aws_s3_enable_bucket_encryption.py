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

from typing import Any, Dict

from boto3 import Session

from .remediation import Remediation
from .remediation_base import RemediationBase
from ..common.exceptions import InvalidParameterException


@Remediation
class AwsS3EnableBucketEncryption(RemediationBase):
    """Remediation that enables encryption for an S3 bucket"""

    @classmethod
    def _id(cls) -> str:
        return 'S3.EnableBucketEncryption'

    @classmethod
    def _parameters(cls) -> Dict[str, str]:
        return {'SSEAlgorithm': 'AES256', 'KMSMasterKeyID': ''}

    @classmethod
    def _fix(cls, session: Session, resource: Dict[str, Any], parameters: Dict[str, str]) -> None:
        if parameters['SSEAlgorithm'] == 'AES256':
            session.client('s3').put_bucket_encryption(
                Bucket=resource['Name'],
                ServerSideEncryptionConfiguration={
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        },
                    },],
                },
            )
        elif parameters['SSEAlgorithm'] == 'aws:kms':
            session.client('s3').put_bucket_encryption(
                Bucket=resource['Name'],
                ServerSideEncryptionConfiguration={
                    'Rules':
                        [
                            {
                                'ApplyServerSideEncryptionByDefault':
                                    {
                                        'SSEAlgorithm': "aws:kms",
                                        'KMSMasterKeyID': parameters['KMSMasterKeyID']
                                    },
                            },
                        ],
                },
            )
        else:
            raise InvalidParameterException("Invalid value {} for parameter {}".format(parameters['SSEAlgorithm'], 'SSEAlgorithm'))
