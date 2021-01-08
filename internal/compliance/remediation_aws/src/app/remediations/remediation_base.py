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

from abc import abstractmethod
from functools import lru_cache
import os
from typing import Any, Dict

import boto3
from boto3 import Session
from botocore.client import BaseClient
from botocore.credentials import RefreshableCredentials
from botocore.exceptions import ClientError

from ..common import logging
from ..common.exceptions import RemediationException, RemediationNotAuthorized

_STS_CLIENT_MAP: Dict[str, BaseClient] = {}
_DEFAULT_STS_REGION = 'us-east-1'
_MASTER_REGION = os.environ.get('MASTER_REGION')


class RemediationBase:
    """Base class for all remediations"""
    logger = logging.get_logger()

    @classmethod
    @abstractmethod
    def _id(cls) -> str:
        """Gets the id for this remediation

        Examples: 'S3BucketPublicRead', 'S3BucketVersioning', etc
        """

    @classmethod
    @abstractmethod
    def _parameters(cls) -> Dict[str, str]:
        """Gets a map for parameters used by this auto-remediation. """

    @classmethod
    @abstractmethod
    def _fix(cls, session: Session, resource: Dict[str, Any], parameters: Dict[str, str]) -> None:
        """
        This method contains the actual logic ran by the remediation.
        It has to be implemented by all RemediationBase subclasses.

        Args:
             session: The Session object that will be used to perform any AWS related operations.
             It can be used to create the necessary AWS clients

             resource: The resource that fails to pass the rule

             parameters: Any parameters passed to the remediation

        """

    @classmethod
    def parameters(cls) -> Dict[str, str]:
        """Returns the remediationId for the specified remediation"""
        return cls._parameters()

    @classmethod
    def remediation_id(cls) -> str:
        """Returns the remediationId for the specified remediation"""
        return '.'.join(['AWS', cls._id()])

    @classmethod
    def fix(cls, event: Dict[str, Any]) -> None:
        """Method invoked by AWS Lambda to perform remediative actions"""

        session = cls._get_session(event['resource']['AccountId'], event['resource']['Region'])
        try:
            cls.logger.info('Invoking remediation %s ', cls.remediation_id())
            cls._fix(session, event['resource'], event['parameters'])
            cls.logger.info('Successfully invoked remediation %s', cls.remediation_id())
        except ClientError as exception:
            if exception.response['Error']['Code'] == 'AccessDenied':
                raise RemediationNotAuthorized(exception)
            raise RemediationException(exception)
        except Exception as exception:
            raise RemediationException(exception)

    @classmethod
    def _get_session(cls, account_id: str, region: str) -> Session:
        """Retrieves a session with valid credentials for the provided account.

        Args:
            account_id: The id of the account where we will assume the role
        """
        cls.logger.info('Getting session for account %s for region %s', account_id, region)

        # Some resources are global (e.g. IAM roles) - so we defaulting to _DEFAULT_STS_REGION
        if region == "global":
            region = _DEFAULT_STS_REGION

        credentials = cls._get_credentials(account_id, region).get_frozen_credentials()
        return boto3.session.Session(
            aws_access_key_id=credentials.access_key,
            aws_secret_access_key=credentials.secret_key,
            aws_session_token=credentials.token,
            region_name=region
        )

    @classmethod
    @lru_cache(maxsize=64)
    def _get_credentials(cls, account_id: str, region: str) -> RefreshableCredentials:
        """
        Retrieves refreshable credentials for the given account.
        The credentials are cached using a LRU cache.

        Args:
            account_id: The id of the account
        """
        cls.logger.info("Getting credentials for accountId %s and region %s", account_id, region)

        def refresh_credentials() -> Dict[str, str]:
            """Refresh credentials by invoking STS AssumeRole operation"""
            cls.logger.info("Refreshing credentials for account %s and region %s", account_id, region)
            params = {
                'RoleArn': 'arn:aws:iam::{}:role/PantherRemediationRole-{}'.format(account_id, _MASTER_REGION),
                'RoleSessionName': 'RemediationSession',
                'DurationSeconds': 3600,
            }

            response = cls._get_sts_client(region).assume_role(**params).get('Credentials')
            return {
                'access_key': response.get('AccessKeyId'),
                'secret_key': response.get('SecretAccessKey'),
                'token': response.get('SessionToken'),
                'expiry_time': response.get('Expiration').isoformat(),
            }

        return RefreshableCredentials.create_from_metadata(
            metadata=refresh_credentials(),
            refresh_using=refresh_credentials,
            method='sts-assume-role',
        )

    @classmethod
    def _get_sts_client(cls, region: str) -> BaseClient:
        if region in _STS_CLIENT_MAP:
            return _STS_CLIENT_MAP[region]
        client = boto3.client('sts', region_name=region)
        _STS_CLIENT_MAP[region] = client
        return client
