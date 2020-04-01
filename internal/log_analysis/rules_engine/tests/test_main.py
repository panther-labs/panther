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
import os
from unittest import TestCase, mock

import boto3
import requests
from botocore.auth import SigV4Auth

from . import mock_to_return

_RESPONSE_MOCK = mock.MagicMock()
_RESPONSE_MOCK.json.return_value = {'policies': []}

_ENV_VARIABLES_MOCK = {
    'ALERTS_DEDUP_TABLE': 'table_name',
    'ANALYSIS_API_FQDN': 'analysis_fqdn',
    'S3_BUCKET': 's3_bucket',
    'NOTIFICATIONS_TOPIC': 'sns_topic',
    'ANALYSIS_API_PATH': 'path'
}
with mock.patch.dict(os.environ, _ENV_VARIABLES_MOCK),\
     mock.patch.object(boto3, 'client', side_effect=mock_to_return), \
     mock.patch.object(SigV4Auth, 'add_auth'), \
     mock.patch.object(requests, 'get', return_value=_RESPONSE_MOCK):
    from ..src.main import lambda_handler, _load_s3_notifications


class TestMainDirectAnalysis(TestCase):

    def test_direct_analysis_event_matching(self) -> None:
        rule_body = 'def rule(event):\n\treturn True'
        payload = {'rules': [{'id': 'rule_id', 'body': rule_body}], 'events': [{'id': 'event_id', 'data': 'data'}]}
        expected_response = {'events': [{'id': 'event_id', 'matched': ['rule_id'], 'notMatched': [], 'errored': []}]}
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_event_not_matching(self) -> None:
        rule_body = 'def rule(event):\n\treturn False'
        payload = {'rules': [{'id': 'rule_id', 'body': rule_body}], 'events': [{'id': 'event_id', 'data': 'data'}]}
        expected_response = {'events': [{'id': 'event_id', 'matched': [], 'notMatched': ['rule_id'], 'errored': []}]}
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_rule_throwing_exception(self) -> None:
        payload = {
            'rules': [{
                'id': 'rule_id',
                'body': 'def rule(event):\n\traise Exception("Failure message")'
            }],
            'events': [{
                'id': 'event_id',
                'data': 'data'
            }]
        }
        expected_response = {
            'events': [{
                'id': 'event_id',
                'matched': [],
                'notMatched': [],
                'errored': [{
                    'id': 'rule_id',
                    'message': 'Failure message'
                }]
            }]
        }
        self.assertEqual(expected_response, lambda_handler(payload, None))

    def test_direct_analysis_rule_invalid(self) -> None:
        payload = {'rules': [{'id': 'rule_id', 'body': 'import stuff'}], 'events': [{'id': 'event_id', 'data': 'data'}]}
        expected_response = {
            'events':
                [
                    {
                        'id': 'event_id',
                        'matched': [],
                        'notMatched': [],
                        'errored': [{
                            'id': 'rule_id',
                            'message': 'No module named \'stuff\''
                        }]
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
