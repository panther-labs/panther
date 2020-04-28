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

from typing import Any, Dict

from boto3 import Session

from .remediation import Remediation
from .remediation_base import RemediationBase


@Remediation
class AwsCloudTrailCreateTrail(RemediationBase):
    """Remediation that creates a new CloudTrail trail to S3"""

    @classmethod
    def _id(cls) -> str:
        return 'CloudTrail.CreateTrail'

    @classmethod
    def _parameters(cls) -> Dict[str, str]:
        return {
            'Name': 'AutoRemediationTrail',
            'TargetBucketName': '',
            'TargetPrefix': '',
            'SnsTopicName': '',
            'IsMultiRegionTrail': 'true',
            'KmsKeyId': '',
            'IncludeGlobalServiceEvents': 'true',
            'IsOrganizationTrail': 'false'
        }

    @classmethod
    def _fix(cls, session: Session, resource: Dict[str, Any], parameters: Dict[str, str]) -> None:
        client = session.client('cloudtrail')
        client.create_trail(
            Name=parameters['Name'],
            S3BucketName=parameters['TargetBucketName'],
            S3KeyPrefix=parameters['TargetPrefix'],
            SnsTopicName=parameters['SnsTopicName'],
            IncludeGlobalServiceEvents=parameters['IncludeGlobalServiceEvents'].lower() == 'true',
            IsMultiRegionTrail=parameters['IsMultiRegionTrail'].lower() == 'true',
            EnableLogFileValidation=True,
            KmsKeyId=parameters['KmsKeyId'],
            IsOrganizationTrail=parameters['IsOrganizationTrail'].lower() == 'true'
        )
        client.start_logging(Name=parameters['Name'])
