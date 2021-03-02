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
"""Unit tests for src/policy.py"""
import os
import tempfile
import unittest
from unittest.mock import MagicMock

from ..src.policy import Policy, PolicySet


class TestPolicy(unittest.TestCase):
    """Unit tests for policy.Policy"""

    def test_run_true(self) -> None:
        """Imported policy body returns True."""
        path = os.path.join(tempfile.gettempdir(), 'panther-true.py')
        with open(path, 'w') as policy_file:
            policy_file.write('def policy(resource): return True')
        policy = Policy('test-id', path)
        self.assertTrue(policy.run({'hello': 'world'}))

    def test_run_false(self) -> None:
        """Imported policy body returns False."""
        path = os.path.join(tempfile.gettempdir(), 'panther-true.py')
        with open(path, 'w') as policy_file:
            policy_file.write('def policy(resource): return False')
        policy = Policy('test-id', path)
        self.assertFalse(policy.run({'hello': 'world'}))

    def test_run_import_error(self) -> None:
        """A policy which failed to import will raise errors for every resource."""
        path = os.path.join(tempfile.gettempdir(), 'panther-invalid.py')
        with open(path, 'w') as policy_file:
            policy_file.write('def... initely not valid Python')
        policy = Policy('test-id', path)
        self.assertIsInstance(policy.run({'hello': 'world'}), SyntaxError)

    def test_run_runtime_error(self) -> None:
        """Runtime errors are reported."""
        path = os.path.join(tempfile.gettempdir(), 'panther-runtime-error.py')
        with open(path, 'w') as policy_file:
            policy_file.write('def policy(resource): return 0/0')
        policy = Policy('test-id', path)
        self.assertIsInstance(policy.run({'hello': 'world'}), ZeroDivisionError)

    def test_run_non_bool(self) -> None:
        """Non-boolean returns raise an error."""
        path = os.path.join(tempfile.gettempdir(), 'panther-truthy.py')
        with open(path, 'w') as policy_file:
            policy_file.write('def policy(resource): return len(resource)')  # returns 1
        result = Policy('test-id', path).run({'hello': 'world'})
        self.assertIsInstance(result, TypeError)
        self.assertEqual('policy returned int, expected bool', str(result))

    def test_run_rule(self) -> None:
        """Can also run a 'rule' instead of a 'policy'"""
        path = os.path.join(tempfile.gettempdir(), 'panther-true-rule.py')
        with open(path, 'w') as policy_file:
            policy_file.write('def rule(event): return True')
        policy = Policy('test-id', path)
        self.assertTrue(policy.run({'hello': 'world'}))


class TestPolicySet(unittest.TestCase):
    """Unit tests for policy.PolicySet"""

    def setUp(self) -> None:
        """Load a policy set."""
        path_true = os.path.join(tempfile.gettempdir(), 'panther-true.py')
        with open(path_true, 'w') as policy_file:
            policy_file.write('def policy(resource): return True')

        path_false = os.path.join(tempfile.gettempdir(), 'panther-false.py')
        with open(path_false, 'w') as policy_file:
            policy_file.write('def policy(resource): return False')

        self._policy_set = PolicySet(
            [
                {
                    'body': path_true,
                    'id': 'test-policy-0',
                }, {
                    'body': path_true,
                    'id': 'test-policy-1',
                    'resourceTypes': ['AWS.CloudTrail']
                }, {
                    'body': path_true,
                    'id': 'test-policy-2',
                }, {
                    'body': path_false,
                    'id': 'test-policy-3',
                    'resourceTypes': ['AWS.CloudTrail', 'AWS.S3.Bucket']
                }, {
                    'body': 'invalid.py',
                    'id': 'test-policy-4',
                }
            ]
        )

    def test_analyze(self) -> None:
        """Analyze a resource with a set of policies."""
        resource = {'attributes': {'hello': 'world'}, 'id': 'arn:aws:s3:::my-bucket', 'type': 'AWS.S3.Bucket'}
        result = self._policy_set.analyze(resource, dict())
        result['failed'] = list(sorted(result['failed']))

        expected = {
            'id': 'arn:aws:s3:::my-bucket',
            'errored': [{
                'id': 'test-policy-4',
                'message': 'FileNotFoundError: ' + '[Errno 2] No such file or directory: \'invalid.py\''
            }],
            'failed': ['test-policy-3'],
            'passed': ['test-policy-0', 'test-policy-2'],
        }

        self.assertEqual(expected, result)

    def test_policy_set_bad_mock(self) -> None:
        """Bad Mock data provided"""
        path = os.path.join(tempfile.gettempdir(), 'panther-mock.py')
        with open(path, 'w') as policy_file:
            policy_file.write(
                'import boto3\nfrom datetime import date\nfrom unittest.mock import MagicMock\n'
                'def policy(resource): return all([isinstance(boto3, MagicMock), '
                'isinstance(boto3.client, MagicMock), isinstance(date, MagicMock)])'
            )
        policy_set = PolicySet([{'id': 'test-id', 'body': path, 'resourceTypes': ['resource']}])
        mock_methods = {'bad_mock': MagicMock(return_value='bad_value')}
        test_resource = {
            'attributes': {},
            'id': 'bad-mock',
            'type': 'resource',
        }
        expected = {
            'errored': [{
                'id': 'test-id',
                'message': "Bad Mock Data: 'bad_mock'"
            }],
            'failed': ['test-id'],
            'id': 'bad-mock',
            'passed': []
        }
        self.assertEqual(expected, policy_set.analyze(test_resource, mock_methods))

    def test_policy_set_valid_mock(self) -> None:
        """Bad Mock data provided"""
        path = os.path.join(tempfile.gettempdir(), 'panther-mock.py')
        policy_set = PolicySet([{'id': 'test-id', 'body': path, 'resourceTypes': ['resource']}])
        mock_methods = {
            'boto3': MagicMock(return_value='value'),
            'date': MagicMock(return_value='value'),
        }
        test_resource = {
            'attributes': {},
            'id': 'valid-mock',
            'type': 'resource',
        }
        expected = {'errored': [], 'failed': [], 'id': 'valid-mock', 'passed': ['test-id']}
        self.assertEqual(expected, policy_set.analyze(test_resource, mock_methods))

    def test_policy_set_no_mock(self) -> None:
        """Bad Mock data provided"""
        path = os.path.join(tempfile.gettempdir(), 'panther-mock.py')
        policy_set = PolicySet([{'id': 'test-id', 'body': path, 'resourceTypes': ['resource']}])
        test_resource = {
            'attributes': {},
            'id': 'no-mock',
            'type': 'resource',
        }
        expected = {'errored': [], 'failed': ['test-id'], 'id': 'no-mock', 'passed': []}
        self.assertEqual(expected, policy_set.analyze(test_resource))
