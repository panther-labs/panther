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
"""Unit tests for src/engine.py"""
import json
import os
import tempfile
import unittest
from unittest import mock

from ..src import engine

_TMP = tempfile.gettempdir()


@mock.patch.object(engine, 'print')
class TestEngine(unittest.TestCase):
    """Unit tests for engine subprocess."""

    @mock.patch.object(engine.sys.stdin, 'read', return_value='{"policies": [], "resources": []}')
    def test_empty(self, mock_read: mock.MagicMock, mock_print: mock.MagicMock) -> None:
        """Run with no policies and no resources."""
        engine.main()
        mock_read.assert_called_once()
        mock_print.assert_called_once()

        output = json.loads(mock_print.call_args[0][0])
        self.assertEqual({'resources': []}, output)

    @mock.patch.object(
        engine.sys.stdin,
        'read',
        return_value=json.dumps(
            {
                'policies':
                    [
                        {
                            # Import failure
                            'body': os.path.join(_TMP, 'panther-1.py'),
                            'id': 'panther-1',
                            'resourceTypes': ['AWS.CloudTrail']
                        },
                        {
                            # Global policy: return True if resource["key"] == "value"
                            'body': os.path.join(_TMP, 'panther-2.py'),
                            'id': 'panther-2',
                        },
                        {
                            # Return True for all AWS.CloudTrail resources (and imports a library)
                            'body': os.path.join(_TMP, 'panther-3.py'),
                            'id': 'panther-3',
                            'resourceTypes': ['AWS.CloudTrail']
                        },
                        {
                            # Return True if data contains {"hello": "world"}
                            'body': os.path.join(_TMP, 'panther-4.py'),
                            'id': 'panther-4',
                            'resourceTypes': ['AWS.CloudTrail', 'Github.Repo']
                        },
                        {
                            # Runtime exception
                            'body': os.path.join(_TMP, 'panther-5.py'),
                            'id': 'panther-5',
                            'resourceTypes': ['AWS.CloudTrail']
                        },
                        {
                            # Bad and Valid Mocking
                            'body': os.path.join(_TMP, 'panther-6.py'),
                            'id': 'panther-6',
                            'resourceTypes': ['AWS.S3.Bucket']
                        },
                    ],
                'resources':
                    [
                        {
                            'attributes': {
                                'key': 'value'
                            },
                            'id': 'my-trail',
                            'type': 'AWS.CloudTrail',
                        }, {
                            'attributes': {
                                'hello': 'world'
                            },
                            'id': 'github.com/panther-labs/policy-engine',
                            'type': 'Github.Repo'
                        }, {
                            'attributes': {
                                'hello': 'panther'
                            },
                            'id': 'github.com/panther-labs/policy-api',
                            'type': 'Github.Repo'
                        }, {
                            'attributes': {
                                'key': 'value'
                            },
                            'id': 'bad-mock',
                            'type': 'AWS.S3.Bucket',
                            'mocks':
                                {
                                    'boto3': 'example_boto3_return_value',
                                    'date': 'example_date_return_value',
                                    'bad_mock': 'example_bad_mock_return_value',
                                }
                        }, {
                            'attributes': {
                                'key': 'value'
                            },
                            'id': 'valid-mock',
                            'type': 'AWS.S3.Bucket',
                            'mocks': {
                                'boto3': 'example_boto3_return_value',
                                'date': 'example_date_return_value',
                            }
                        }
                    ],
            }
        )
    )
    def test_all(self, mock_read: mock.MagicMock, mock_print: mock.MagicMock) -> None:
        """Test a variety of policy conditions."""
        with open(os.path.join(_TMP, 'panther-1.py'), 'w') as policy_file:
            policy_file.write('def... initely not valid Python')
        with open(os.path.join(_TMP, 'panther-2.py'), 'w') as policy_file:
            policy_file.write('def policy(resource): return resource.get("key") == "value"')
        with open(os.path.join(_TMP, 'panther-3.py'), 'w') as policy_file:
            # random.random() is always less than 1, this is equivalent to "return True"
            policy_file.write('import random\ndef policy(resource): return random.random() <= 1')
        with open(os.path.join(_TMP, 'panther-4.py'), 'w') as policy_file:
            policy_file.write('def policy(resource): return resource.get("hello", "").startswith("wor")')
        with open(os.path.join(_TMP, 'panther-5.py'), 'w') as policy_file:
            policy_file.write('def policy(resource): return 0/0')
        with open(os.path.join(_TMP, 'panther-6.py'), 'w') as policy_file:
            policy_file.write(
                'import boto3\nfrom datetime import date\nfrom unittest.mock import MagicMock\n'
                'def policy(resource): return all([isinstance(boto3, MagicMock), '
                'isinstance(boto3.client, MagicMock), isinstance(date, MagicMock)])'
            )

        engine.main()
        mock_read.assert_called_once()
        mock_print.assert_called_once()

        output = json.loads(mock_print.call_args[0][0])
        for result in output['resources']:  # sort each list in the results
            result['errored'] = list(sorted(result['errored'], key=lambda x: x['id']))
            result['failed'] = list(sorted(result['failed']))
            result['passed'] = list(sorted(result['passed']))

        expected = {
            'resources':
                [
                    {
                        'id': 'my-trail',
                        'errored':
                            [
                                {
                                    'id': 'panther-1',
                                    'message': 'SyntaxError: invalid syntax (panther-1.py, line 1)'
                                }, {
                                    'id': 'panther-5',
                                    'message': 'ZeroDivisionError: division by zero'
                                }
                            ],
                        'failed': ['panther-4'],
                        'passed': ['panther-2', 'panther-3']
                    }, {
                        'id': 'github.com/panther-labs/policy-engine',
                        'errored': [],
                        'failed': ['panther-2'],
                        'passed': ['panther-4']
                    }, {
                        'id': 'github.com/panther-labs/policy-api',
                        'errored': [],
                        'failed': ['panther-2', 'panther-4'],
                        'passed': []
                    }, {
                        'id': 'bad-mock',
                        'errored':
                            [
                                {
                                    'id': 'panther-2',
                                    'message': "Bad Mock Data: 'boto3'"
                                },
                                {
                                    'id': 'panther-6',
                                    'message': "Bad Mock Data: 'bad_mock'"
                                },
                            ],
                        'failed': ['panther-2', 'panther-6'],
                        'passed': []
                    }, {
                        'id': 'valid-mock',
                        'errored': [{
                            'id': 'panther-2',
                            'message': "Bad Mock Data: 'boto3'"
                        },],
                        'failed': ['panther-2'],
                        'passed': ['panther-6']
                    }
                ]
        }
        self.assertEqual(expected, output)
