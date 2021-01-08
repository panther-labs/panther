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


@Remediation
class AwsEc2EnableVpcFlowLogsToS3(RemediationBase):
    """Remediation that enables VPC Flow logs to S3 bucket"""

    @classmethod
    def _id(cls) -> str:
        return 'EC2.EnableVpcFlowLogsToS3'

    @classmethod
    def _parameters(cls) -> Dict[str, str]:
        return {'TargetBucketName': '', 'TargetPrefix': '', 'TrafficType': 'ALL'}

    @classmethod
    def _fix(cls, session: Session, resource: Dict[str, Any], parameters: Dict[str, str]) -> None:
        response = session.client('ec2').create_flow_logs(
            ResourceIds=[
                resource['Id'],
            ],
            ResourceType='VPC',
            TrafficType=parameters['TrafficType'],
            LogDestinationType='s3',
            LogDestination='arn:aws:s3:::{}/{}'.format(parameters['TargetBucketName'], parameters['TargetPrefix'])
        )
        if 'Unsuccessful' in response:
            raise Exception(response['Unsuccessful'][0])
