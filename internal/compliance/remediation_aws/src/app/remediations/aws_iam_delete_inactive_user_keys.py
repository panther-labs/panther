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
class AwsIamDeleteInactiveAccessKeys(RemediationBase):
    """Remediation that deletes inactive user access keys"""

    @classmethod
    def _id(cls) -> str:
        return 'IAM.DeleteInactiveAccessKeys'

    @classmethod
    def _parameters(cls) -> Dict[str, str]:
        return {}

    @classmethod
    def _fix(cls, session: Session, resource: Dict[str, Any], parameters: Dict[str, str]) -> None:
        client = session.client('iam')
        if 'AccessKey1Active' in resource['CredentialReport'] and not resource['CredentialReport']['AccessKey1Active']:
            client.delete_access_key(UserName=resource['UserName'], AccessKeyId=resource['CredentialReport']['AccessKey1Id'])
        if 'AccessKey2Active' in resource['CredentialReport'] and not resource['CredentialReport']['AccessKey2Active']:
            client.delete_access_key(UserName=resource['UserName'], AccessKeyId=resource['CredentialReport']['AccessKey2Id'])
