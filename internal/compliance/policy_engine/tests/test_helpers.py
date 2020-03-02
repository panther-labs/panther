# Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
"""Unit tests for src/policy.py"""
import unittest

from ..src import helpers

DYNAMO_GOOD_RESPONSE = {
    'Item':
        {
            'integrationType': 'aws',
            'deleted': False,
            'lowerId': 'arn:aws:s3:::example-bucket',
            'lastModified': '2020-01-01T00:00:00.000000000Z',
            'integrationId': '1111-2222',
            'attributes':
                {
                    'Owner': {
                        'DisplayName': 'example.user',
                        'ID': '1111'
                    },
                    'AccountId': '123456789012',
                    'EncryptionRules':
                        [
                            {
                                'ApplyServerSideEncryptionByDefault':
                                    {
                                        'KMSMasterKeyID': 'arn:aws:kms:us-west-2:123456789012:key1',
                                        'SSEAlgorithm': 'aws:kms'
                                    }
                            }
                        ],
                    'ResourceType': 'AWS.S3.Bucket',
                    'Grants':
                        [
                            {
                                'Permission': 'FULL_CONTROL',
                                'Grantee':
                                    {
                                        'DisplayName': 'example.user',
                                        'Type': 'CanonicalUser',
                                        'ID': '1111',
                                        'URI': None,
                                        'EmailAddress': None
                                    }
                            }, {
                                'Permission': 'WRITE',
                                'Grantee':
                                    {
                                        'DisplayName': None,
                                        'Type': 'Group',
                                        'ID': None,
                                        'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery',
                                        'EmailAddress': None
                                    }
                            }, {
                                'Permission': 'READ_ACP',
                                'Grantee':
                                    {
                                        'DisplayName': None,
                                        'Type': 'Group',
                                        'ID': None,
                                        'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery',
                                        'EmailAddress': None
                                    }
                            }
                        ],
                    'LifecycleRules': None,
                    'Name': 'example-bucket',
                    'TimeCreated': '2020-01-01T00:00:00.000Z',
                    'PublicAccessBlockConfiguration':
                        {
                            'IgnorePublicAcls': True,
                            'RestrictPublicBuckets': True,
                            'BlockPublicPolicy': True,
                            'BlockPublicAcls': True
                        },
                    'Versioning': 'Suspended',
                    'LoggingPolicy': None,
                    'ResourceId': 'arn:aws:s3:::example-bucket',
                    'ObjectLockConfiguration': None,
                    'Region': 'us-west-2',
                    'MFADelete': None,
                    'Arn': 'arn:aws:s3:::example-bucket',
                    'Tags': None
                },
            'id': 'arn:aws:s3:::example-bucket',
            'type': 'AWS.S3.Bucket'
        },
    'ResponseMetadata':
        {
            'RequestId': 'ABC123',
            'HTTPStatusCode': 200,
            'HTTPHeaders':
                {
                    'server': 'Server',
                    'date': 'Wed, 01 Jan 2020 00:00:00 GMT',
                    'content-type': 'application/x-amz-json-1.0',
                    'content-length': '1000',
                    'connection': 'keep-alive',
                    'x-amzn-requestid': 'ABC123',
                    'x-amz-crc32': '12345'
                },
            'RetryAttempts': 0
        }
}


class TestHelpers(unittest.TestCase):
    """Unit tests for policy.Policy"""

    def test_lookup(self) -> None:
        """Imported policy body returns True."""
        helpers.dynamo_lookup = lambda _: DYNAMO_GOOD_RESPONSE

        resource = helpers.resource_lookup('arn:aws:s3:::example_bucket')
        assert resource == DYNAMO_GOOD_RESPONSE['Item']['attributes']
