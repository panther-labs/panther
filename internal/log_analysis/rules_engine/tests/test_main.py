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

import io
import json
import os
from typing import Any, Dict
from unittest import TestCase, mock

import boto3

from . import mock_to_return, LAMBDA_MOCK


def _mock_invoke(**unused_kwargs: Any) -> Dict[str, Any]:
    return {
        'Payload':
            io.BytesIO(
                json.dumps(
                    {
                        'body':
                            json.dumps(
                                {
                                    'paging': {
                                        'thisPage': 1,
                                        'totalItems': 0,
                                        'totalPages': 1
                                    },
                                    'models': [],  # for listModels
                                    'rules': [],  # for listRules
                                }
                            ),
                        'statusCode': 200,
                    }
                ).encode('utf-8')
            ),
        'StatusCode': 200
    }


LAMBDA_MOCK.invoke.side_effect = _mock_invoke

_ENV_VARIABLES_MOCK = {
    'ALERTS_DEDUP_TABLE': 'table_name',
    'S3_BUCKET': 's3_bucket',
    'NOTIFICATIONS_TOPIC': 'sns_topic',
}
with mock.patch.dict(os.environ, _ENV_VARIABLES_MOCK), \
     mock.patch.object(boto3, 'client', side_effect=mock_to_return):
    from ..src.main import lambda_handler, _load_s3_notifications


class TestMainDirectAnalysis(TestCase):

    def test_direct_analysis_event_matching(self) -> None:
        rule_body = 'def rule(event):\n\treturn True'
        payload = {'rules': [{'id': 'rule_id', 'body': rule_body}], 'events': [{'id': 'event_id', 'data': {'key': 'value'}}]}
        expected_response = {
            'results':
                [
                    {
                        'id': 'event_id',
                        'ruleId': 'rule_id',
                        'genericError': None,
                        'errored': False,
                        'ruleOutput': True,
                        'ruleError': None,
                        'titleOutput': None,
                        'titleError': None,
                        'descriptionOutput': None,
                        'descriptionError': None,
                        'referenceOutput': None,
                        'referenceError': None,
                        'severityOutput': None,
                        'severityError': None,
                        'runbookOutput': None,
                        'runbookError': None,
                        'destinationsOutput': None,
                        'destinationsError': None,
                        'dedupOutput': 'defaultDedupString:rule_id',
                        'dedupError': None,
                        'alertContextOutput': None,
                        'alertContextError': None
                    }
                ]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_event_matching_with_generated_fields(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\n' \
                    'def title(event):\n\treturn "generated title"\n' \
                    'def description(event):\n\treturn "generated description"\n' \
                    'def reference(event):\n\treturn "generated reference"\n' \
                    'def severity(event):\n\treturn "HIGH"\n' \
                    'def runbook(event):\n\treturn "generated runbook"\n' \
                    'def destinations(event):\n\treturn []'
        payload = {'rules': [{'id': 'rule_id', 'body': rule_body}], 'events': [{'id': 'event_id', 'data': {'key': 'value'}}]}
        expected_response: dict = {
            'results':
                [
                    {
                        'id': 'event_id',
                        'ruleId': 'rule_id',
                        'genericError': None,
                        'errored': False,
                        'ruleOutput': True,
                        'ruleError': None,
                        'titleOutput': 'generated title',
                        'titleError': None,
                        'descriptionOutput': 'generated description',
                        'descriptionError': None,
                        'referenceOutput': 'generated reference',
                        'referenceError': None,
                        'severityOutput': "HIGH",
                        'severityError': None,
                        'runbookOutput': 'generated runbook',
                        'runbookError': None,
                        'destinationsOutput': [],
                        'destinationsError': None,
                        'dedupOutput': 'generated title',
                        'dedupError': None,
                        'alertContextOutput': None,
                        'alertContextError': None
                    }
                ]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_event_not_matching(self) -> None:
        rule_body = 'def rule(event):\n\treturn False'
        payload = {'rules': [{'id': 'rule_id', 'body': rule_body}], 'events': [{'id': 'event_id', 'data': {'key': 'value'}}]}
        expected_response = {
            'results':
                [
                    {
                        'id': 'event_id',
                        'ruleId': 'rule_id',
                        'genericError': None,
                        'errored': False,
                        'ruleOutput': False,
                        'ruleError': None,
                        'titleOutput': None,
                        'titleError': None,
                        'descriptionOutput': None,
                        'descriptionError': None,
                        'referenceOutput': None,
                        'referenceError': None,
                        'severityOutput': None,
                        'severityError': None,
                        'runbookOutput': None,
                        'runbookError': None,
                        'destinationsOutput': None,
                        'destinationsError': None,
                        'dedupOutput': 'defaultDedupString:rule_id',
                        'dedupError': None,
                        'alertContextOutput': None,
                        'alertContextError': None
                    }
                ]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_rule_throwing_exception(self) -> None:
        payload = {
            'rules': [{
                'id': 'rule_id',
                'body': 'def rule(event):\n\traise Exception("Failure message")'
            }],
            'events': [{
                'id': 'event_id',
                'data': {
                    'key': 'value'
                }
            }]
        }
        expected_response = {
            'results':
                [
                    {
                        'id': 'event_id',
                        'ruleId': 'rule_id',
                        'genericError': None,
                        'errored': True,
                        'ruleOutput': None,
                        'ruleError': 'Exception: Failure message',
                        'titleOutput': None,
                        'titleError': None,
                        'descriptionOutput': None,
                        'descriptionError': None,
                        'referenceOutput': None,
                        'referenceError': None,
                        'severityOutput': None,
                        'severityError': None,
                        'runbookOutput': None,
                        'runbookError': None,
                        'destinationsOutput': None,
                        'destinationsError': None,
                        'dedupOutput': 'defaultDedupString:rule_id',
                        'dedupError': None,
                        'alertContextOutput': None,
                        'alertContextError': None
                    }
                ]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_rule_invalid(self) -> None:
        payload = {'rules': [{'id': 'rule_id', 'body': 'import stuff'}], 'events': [{'id': 'event_id', 'data': {'key': 'value'}}]}
        expected_response = {
            'results':
                [
                    {
                        'id': 'event_id',
                        'ruleId': 'rule_id',
                        'genericError': "ModuleNotFoundError: No module named 'stuff'",
                        'errored': True,
                        'ruleOutput': None,
                        'ruleError': None,
                        'titleOutput': None,
                        'titleError': None,
                        'descriptionOutput': None,
                        'descriptionError': None,
                        'referenceOutput': None,
                        'referenceError': None,
                        'severityOutput': None,
                        'severityError': None,
                        'runbookOutput': None,
                        'runbookError': None,
                        'destinationsOutput': None,
                        'destinationsError': None,
                        'dedupOutput': None,
                        'dedupError': None,
                        'alertContextOutput': None,
                        'alertContextError': None
                    }
                ]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_dedup_exception_fails_test(self) -> None:
        """If rule dedup() raises an exception while testing a rule (not normal analysis), we should fail the test"""
        payload = {
            'rules': [{
                'id': 'rule_id',
                'body': "def rule(event):\n\treturn True\ndef dedup(event):\n\traise Exception('dedup error')"
            }],
            'events': [{
                'id': 'event_id',
                'data': {
                    'key': 'value'
                }
            }]
        }
        expected_response = {
            'results':
                [
                    {
                        'id': 'event_id',
                        'ruleId': 'rule_id',
                        'genericError': None,
                        'errored': True,
                        'ruleOutput': True,
                        'ruleError': None,
                        'titleOutput': None,
                        'titleError': None,
                        'descriptionOutput': None,
                        'descriptionError': None,
                        'referenceOutput': None,
                        'referenceError': None,
                        'severityOutput': None,
                        'severityError': None,
                        'runbookOutput': None,
                        'runbookError': None,
                        'destinationsOutput': None,
                        'destinationsError': None,
                        'dedupOutput': None,
                        'dedupError': 'Exception: dedup error',
                        'alertContextOutput': None,
                        'alertContextError': None
                    }
                ]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_title_exception_fails_test(self) -> None:
        """If rule title() raises an exception while testing a rule (not normal analysis), we should fail the test"""
        payload = {
            'rules': [{
                'id': 'rule_id',
                'body': "def rule(event):\n\treturn True\ndef title(event):\n\traise Exception('title error')"
            }],
            'events': [{
                'id': 'event_id',
                'data': {
                    'key': 'value'
                }
            }]
        }

        expected_response = {
            'results':
                [
                    {
                        'id': 'event_id',
                        'ruleId': 'rule_id',
                        'genericError': None,
                        'errored': True,
                        'ruleOutput': True,
                        'ruleError': None,
                        'titleOutput': None,
                        'titleError': 'Exception: title error',
                        'descriptionOutput': None,
                        'descriptionError': None,
                        'referenceOutput': None,
                        'referenceError': None,
                        'severityOutput': None,
                        'severityError': None,
                        'runbookOutput': None,
                        'runbookError': None,
                        'destinationsOutput': None,
                        'destinationsError': None,
                        'dedupOutput': 'defaultDedupString:rule_id',
                        'dedupError': None,
                        'alertContextOutput': None,
                        'alertContextError': None
                    }
                ]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_description_exception_fails_test(self) -> None:
        """If rule description() raises exception while testing a rule (not normal analysis), we should fail the test"""
        payload = {
            'rules':
                [
                    {
                        'id': 'rule_id',
                        'body': "def rule(event):\n\treturn True\n" + "def description(event):\n\traise Exception('description error')"
                    }
                ],
            'events': [{
                'id': 'event_id',
                'data': {
                    'key': 'value'
                }
            }]
        }

        expected_response = {
            'results':
                [
                    {
                        'id': 'event_id',
                        'ruleId': 'rule_id',
                        'genericError': None,
                        'errored': True,
                        'ruleOutput': True,
                        'ruleError': None,
                        'titleOutput': None,
                        'titleError': None,
                        'descriptionOutput': None,
                        'descriptionError': 'Exception: description error',
                        'referenceOutput': None,
                        'referenceError': None,
                        'severityOutput': None,
                        'severityError': None,
                        'runbookOutput': None,
                        'runbookError': None,
                        'destinationsOutput': None,
                        'destinationsError': None,
                        'dedupOutput': 'defaultDedupString:rule_id',
                        'dedupError': None,
                        'alertContextOutput': None,
                        'alertContextError': None
                    }
                ]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_reference_exception_fails_test(self) -> None:
        """If rule reference() raises exception while testing a rule (not normal analysis), we should fail the test"""
        payload = {
            'rules':
                [{
                    'id': 'rule_id',
                    'body': "def rule(event):\n\treturn True\ndef reference(event):\n\traise Exception('reference error')"
                }],
            'events': [{
                'id': 'event_id',
                'data': {
                    'key': 'value'
                }
            }]
        }

        expected_response = {
            'results':
                [
                    {
                        'id': 'event_id',
                        'ruleId': 'rule_id',
                        'genericError': None,
                        'errored': True,
                        'ruleOutput': True,
                        'ruleError': None,
                        'titleOutput': None,
                        'titleError': None,
                        'descriptionOutput': None,
                        'descriptionError': None,
                        'referenceOutput': None,
                        'referenceError': 'Exception: reference error',
                        'severityOutput': None,
                        'severityError': None,
                        'runbookOutput': None,
                        'runbookError': None,
                        'destinationsOutput': None,
                        'destinationsError': None,
                        'dedupOutput': 'defaultDedupString:rule_id',
                        'dedupError': None,
                        'alertContextOutput': None,
                        'alertContextError': None
                    }
                ]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_severity_exception_fails_test(self) -> None:
        """If rule severity() raises an exception while testing a rule (not normal analysis), we should fail the test"""
        payload = {
            'rules':
                [{
                    'id': 'rule_id',
                    'body': "def rule(event):\n\treturn True\ndef severity(event):\n\traise Exception('severity error')"
                }],
            'events': [{
                'id': 'event_id',
                'data': {
                    'key': 'value'
                }
            }]
        }

        expected_response = {
            'results':
                [
                    {
                        'id': 'event_id',
                        'ruleId': 'rule_id',
                        'genericError': None,
                        'errored': True,
                        'ruleOutput': True,
                        'ruleError': None,
                        'titleOutput': None,
                        'titleError': None,
                        'descriptionOutput': None,
                        'descriptionError': None,
                        'referenceOutput': None,
                        'referenceError': None,
                        'severityOutput': None,
                        'severityError': 'Exception: severity error',
                        'runbookOutput': None,
                        'runbookError': None,
                        'destinationsOutput': None,
                        'destinationsError': None,
                        'dedupOutput': 'defaultDedupString:rule_id',
                        'dedupError': None,
                        'alertContextOutput': None,
                        'alertContextError': None
                    }
                ]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_runbook_exception_fails_test(self) -> None:
        """If rule runbook() raises an exception while testing a rule (not normal analysis), we should fail the test"""
        payload = {
            'rules': [
                {
                    'id': 'rule_id',
                    'body': "def rule(event):\n\treturn True\ndef runbook(event):\n\traise Exception('runbook error')"
                }
            ],
            'events': [{
                'id': 'event_id',
                'data': {
                    'key': 'value'
                }
            }]
        }

        expected_response = {
            'results':
                [
                    {
                        'id': 'event_id',
                        'ruleId': 'rule_id',
                        'genericError': None,
                        'errored': True,
                        'ruleOutput': True,
                        'ruleError': None,
                        'titleOutput': None,
                        'titleError': None,
                        'descriptionOutput': None,
                        'descriptionError': None,
                        'referenceOutput': None,
                        'referenceError': None,
                        'severityOutput': None,
                        'severityError': None,
                        'runbookOutput': None,
                        'runbookError': 'Exception: runbook error',
                        'destinationsOutput': None,
                        'destinationsError': None,
                        'dedupOutput': 'defaultDedupString:rule_id',
                        'dedupError': None,
                        'alertContextOutput': None,
                        'alertContextError': None
                    }
                ]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_destinations_exception_fails_test(self) -> None:
        """If rule destinations() raises exception while testing a rule (not normal analysis), we should fail the test"""
        payload = {
            'rules':
                [
                    {
                        'id': 'rule_id',
                        'body': "def rule(event):\n\treturn True\n" + "def destinations(event):\n\traise Exception('destinations error')"
                    }
                ],
            'events': [{
                'id': 'event_id',
                'data': {
                    'key': 'value'
                }
            }]
        }

        expected_response = {
            'results':
                [
                    {
                        'id': 'event_id',
                        'ruleId': 'rule_id',
                        'genericError': None,
                        'errored': True,
                        'ruleOutput': True,
                        'ruleError': None,
                        'titleOutput': None,
                        'titleError': None,
                        'descriptionOutput': None,
                        'descriptionError': None,
                        'referenceOutput': None,
                        'referenceError': None,
                        'severityOutput': None,
                        'severityError': None,
                        'runbookOutput': None,
                        'runbookError': None,
                        'destinationsOutput': None,
                        'destinationsError': 'Exception: destinations error',
                        'dedupOutput': 'defaultDedupString:rule_id',
                        'dedupError': None,
                        'alertContextOutput': None,
                        'alertContextError': None
                    }
                ]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))


class TestMainLoadS3Notifications(TestCase):

    def test_load_s3_notifications(self) -> None:
        notifications = [
            {
                'eventVersion': '2.0',
                'eventSource': 'aws:s3',
                'eventName': 'ObjectCreated:Put',
                's3': {
                    'bucket': {
                        'name': 'mybucket'
                    },
                    'object': {
                        'key': 'mykey',
                        'size': 100
                    }
                }
            }, {
                'eventVersion': '2.0',
                'eventSource': 'aws:s3',
                'eventName': 'ObjectCreated:Put',
                's3': {
                    'bucket': {
                        'name': 'mybucket2'
                    },
                    'object': {
                        'key': 'mykey2',
                        'size': 100
                    }
                }
            }
        ]
        expected_response = [('mybucket', 'mykey'), ('mybucket2', 'mykey2')]
        self.assertEqual(expected_response, _load_s3_notifications(notifications))
