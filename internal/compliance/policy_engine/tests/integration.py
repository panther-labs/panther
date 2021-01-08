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
"""Integration test to invoke the live Lambda function."""
import json
import os
import unittest

import boto3

_FUNCTION = 'panther-policy-engine'
_INPUT = {
    'policies':
        [
            {
                'body': 'def policy(resource): return resource["AnyExist"] is True',
                'id': 'cloudtrail//!#enabled',  # special characters in policy ID
                'resourceTypes': ['AWS.CloudTrailMeta']
            },
            {
                'body':
                    'from policyuniverse.arn import ARN\n' +
                    (  # test third-party import
                        'def policy(resource): return bool(resource["KmsKeyId"])'
                    ),
                'id': 'cloudtrail-encrypted',
                'resourceTypes': ['AWS.CloudTrail']
            },
            {
                'body': 'def... initely not valid Python',
                'id': 'syntax-error'
            },
            {
                'body': 'def policy(resource): return 0/0',
                'id': 'runtime-error'
            }
        ],
    'resources':
        [
            {
                'attributes':
                    {
                        'CloudWatchLogsLogGroupArn': 'arn:aws:logs:us-west-2:123:log-group:Panther:*',
                        'CloudWatchLogsRoleArn': 'arn:aws:iam::123:role/PantherStreamCloudTrailCWL',
                        'HasCustomEventSelectors': True,
                        'HomeRegion': 'us-west-2',
                        'IncludeGlobalServiceEvents': True,
                        'IsMultiRegionTrail': True,
                        'IsOrganizationTrail': False,
                        'KmsKeyId': None,
                        'LogFileValidationEnabled': True,
                        'Name': 'PantherCloudTrail',
                        'S3BucketName': 'panther-test-cloudtrail',
                        'S3KeyPrefix': None,
                        'SnsTopicARN': None,
                        'SnsTopicName': None,
                        'TrailARN': 'arn:aws:cloudtrail:us-west-2:123:trail/PantherCloudTrail'
                    },
                'id': 'arn:aws:cloudtrail:us-west-2:123:trail/PantherCloudTrail',
                'type': 'AWS.CloudTrail'
            },
            {
                'attributes': {
                    'AnyExist': True
                },
                'id': 'arn:aws:cloudtrail:123:meta',
                'type': 'AWS.CloudTrailMeta'
            },
        ]
}


class IntegrationTest(unittest.TestCase):
    """Test the policy-engine by invoking the Lambda function."""

    def setUp(self) -> None:
        """Create the AWS client."""
        # AWS_DEFAULT_REGION is detected, but not AWS_REGION (not sure why)
        # So if AWS_REGION is set, pass that explicitly, otherwise let boto3 find the region
        if os.environ.get('AWS_REGION'):
            self._client = boto3.client('lambda', region_name=os.environ['AWS_REGION'])
        else:
            self._client = boto3.client('lambda')
        self.maxDiff = None  # pylint: disable=invalid-name

    def test_policy_engine(self) -> None:
        """Invoke the policy-engine and check the response."""
        response = self._client.invoke(FunctionName=_FUNCTION, Payload=json.dumps(_INPUT).encode('utf-8'))
        self.assertIsNone(response.get('FunctionError'))
        output = json.loads(response['Payload'].read())
        expected = {
            'resources':
                [
                    {
                        'id': 'arn:aws:cloudtrail:us-west-2:123:trail/PantherCloudTrail',
                        'errored':
                            [
                                {
                                    'id': 'syntax-error',
                                    'message': 'SyntaxError: invalid syntax (syntax-error.py, line 1)'
                                }, {
                                    'id': 'runtime-error',
                                    'message': 'ZeroDivisionError: division by zero'
                                }
                            ],
                        'failed': ['cloudtrail-encrypted'],
                        'passed': []
                    },
                    {
                        'id': 'arn:aws:cloudtrail:123:meta',
                        'errored':
                            [
                                {
                                    'id': 'syntax-error',
                                    'message': 'SyntaxError: invalid syntax (syntax-error.py, line 1)'
                                }, {
                                    'id': 'runtime-error',
                                    'message': 'ZeroDivisionError: division by zero'
                                }
                            ],
                        'failed': [],
                        'passed': ['cloudtrail//!#enabled']
                    },
                ]
        }
        self.assertEqual(expected, output)


if __name__ == '__main__':
    # Ignore ResourceWarnings from unclosed boto connections
    unittest.main(warnings='ignore')
