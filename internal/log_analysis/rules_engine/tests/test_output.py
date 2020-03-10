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

import hashlib
import json
import os
import re
from datetime import datetime
from gzip import GzipFile
from unittest import TestCase, mock

import boto3

from . import mock_to_return, DDB_MOCK, S3_MOCK, SNS_MOCK
from ..src import EventMatch

with mock.patch.dict(os.environ, {'ALERTS_DEDUP_TABLE': 'table_name', 'S3_BUCKET': 's3_bucket', 'NOTIFICATIONS_TOPIC': 'sns_topic'}), \
     mock.patch.object(boto3, 'client', side_effect=mock_to_return) as mock_boto:
    from ..src.output import MatchedEventsBuffer


class TestMatchedEventsBuffer(TestCase):

    def setUp(self) -> None:
        S3_MOCK.reset_mock()
        SNS_MOCK.reset_mock()
        DDB_MOCK.reset_mock()

    def test_add_and_flush_event_generate_new_alert(self) -> None:
        buffer = MatchedEventsBuffer()
        event_match = EventMatch('rule_id', 'rule_version', 'log_type', 'dedup', 'INFO', {'data_key': 'data_value'})
        buffer.add_event(event_match)

        self.assertEqual(len(buffer.data), 1)

        DDB_MOCK.update_item.return_value = {'Attributes': {'alertCount': {'N': '1'}}}
        buffer.flush()

        DDB_MOCK.update_item.assert_called_once_with(
            ConditionExpression='(#10 < :10) OR (attribute_not_exists(#11))',
            ExpressionAttributeNames={
                '#1': 'ruleId',
                '#2': 'dedup',
                '#3': 'alertCreationTime',
                '#4': 'alertUpdateTime',
                '#5': 'eventCount',
                '#6': 'severity',
                '#7': 'logTypes',
                '#8': 'ruleVersion',
                '#9': 'alertCount',
                '#10': 'alertCreationTime',
                '#11': 'partitionKey'
            },
            ExpressionAttributeValues={
                ':1': {
                    'S': 'rule_id'
                },
                ':2': {
                    'S': 'dedup'
                },
                ':3': {
                    'N': mock.ANY
                },
                ':4': {
                    'N': mock.ANY
                },
                ':5': {
                    'N': '1'
                },
                ':6': {
                    'S': 'INFO'
                },
                ':7': {
                    'SS': ['log_type']
                },
                ':8': {
                    'S': 'rule_version'
                },
                ':9': {
                    'N': '1'
                },
                ':10': {
                    'N': mock.ANY
                }
            },
            Key={
                'partitionKey': {
                    'S':
                        hashlib.md5(b'rule_id:dedup').hexdigest()  # nosec
                }
            },
            ReturnValues='ALL_NEW',
            TableName='table_name',
            UpdateExpression='SET #1=:1, #2=:2, #3=:3, #4=:4, #5=:5, #6=:6, #7=:7, #8=:8\nADD #9 :9'
        )

        S3_MOCK.put_object.assert_called_once_with(Body=mock.ANY, Bucket='s3_bucket', ContentType='gzip', Key=mock.ANY)

        _, call_args = S3_MOCK.put_object.call_args
        # Verify key format
        key = call_args['Key']
        pattern = re.compile("^rules/log_type/year=\\d{4}/month=\\d{2}/day=\\d{2}/hour=\\d{2}/.*json.gz$")
        self.assertIsNotNone(pattern.match(key))
        # Verify content
        data = GzipFile(None, 'rb', fileobj=call_args['Body'])
        content = json.loads(data.read().decode('utf-8'))
        # Verify extra fields
        self.assertEqual(content['p_rule_id'], 'rule_id')
        self.assertEqual(content['p_alert_id'], hashlib.md5(b'rule_id:1:dedup').hexdigest())  # nosec
        # Verify fields are valid dates
        self.assertIsNotNone(datetime.strptime(content['p_alert_creation_time'], '%Y-%m-%d %H:%M:%S.%f000'))
        self.assertIsNotNone(datetime.strptime(content['p_alert_update_time'], '%Y-%m-%d %H:%M:%S.%f000'))
        # Actual event
        self.assertEqual(content['data_key'], 'data_value')

        SNS_MOCK.publish.assert_called_once_with(
            TopicArn='sns_topic',
            Message=mock.ANY,
            MessageAttributes={
                'type': {
                    'DataType': 'String',
                    'StringValue': 'RuleMatches'
                },
                'id': {
                    'DataType': 'String',
                    'StringValue': 'rule_id'
                }
            }
        )

        # Assert that the buffer has been cleared
        self.assertEqual(len(buffer.data), 0)
        self.assertEqual(buffer.bytes_in_memory, 0)

    def test_add_same_rule_different_log(self) -> None:
        buffer = MatchedEventsBuffer()
        buffer.add_event(EventMatch('id', 'version', 'log1', 'dedup', 'INFO', {'key1': 'value1'}))
        buffer.add_event(EventMatch('id', 'version', 'log2', 'dedup', 'INFO', {'key2': 'value2'}))

        self.assertEqual(len(buffer.data), 2)

        DDB_MOCK.update_item.return_value = {'Attributes': {'alertCount': {'N': '1'}}}
        buffer.flush()

        self.assertEqual(DDB_MOCK.update_item.call_count, 2)
        self.assertEqual(S3_MOCK.put_object.call_count, 2)
        self.assertEqual(SNS_MOCK.publish.call_count, 2)

        call_args_list = S3_MOCK.put_object.call_args_list
        for _, call_args in call_args_list:
            data = GzipFile(None, 'rb', fileobj=call_args['Body'])
            content = json.loads(data.read().decode('utf-8'))

            # Verify fields are valid dates
            self.assertIsNotNone(datetime.strptime(content['p_alert_creation_time'], '%Y-%m-%d %H:%M:%S.%f000'))
            self.assertIsNotNone(datetime.strptime(content['p_alert_update_time'], '%Y-%m-%d %H:%M:%S.%f000'))

            if 'key1' in content:
                # Verify actual event
                self.assertEqual(content['key1'], 'value1')
                # Verify extra fields
                self.assertEqual(content['p_rule_id'], 'id')
                self.assertEqual(content['p_alert_id'], hashlib.md5(b'id:1:dedup').hexdigest())  # nosec
            elif 'key2' in content:
                # Verify actual event
                self.assertEqual(content['key2'], 'value2')
                # Verify extra fields
                self.assertEqual(content['p_rule_id'], 'id')
                self.assertEqual(content['p_alert_id'], hashlib.md5(b'id:1:dedup').hexdigest())  # nosec
            else:
                self.fail('unexpected content')

        # Assert that the buffer has been cleared
        self.assertEqual(len(buffer.data), 0)
        self.assertEqual(buffer.bytes_in_memory, 0)

    def test_add_same_log_different_rules(self) -> None:
        buffer = MatchedEventsBuffer()
        buffer.add_event(EventMatch('id1', 'version', 'log', 'dedup', 'INFO', {'key1': 'value1'}))
        buffer.add_event(EventMatch('id2', 'version', 'log', 'dedup', 'INFO', {'key2': 'value2'}))

        self.assertEqual(len(buffer.data), 2)

        DDB_MOCK.update_item.return_value = {'Attributes': {'alertCount': {'N': '1'}}}
        buffer.flush()

        self.assertEqual(DDB_MOCK.update_item.call_count, 2)
        self.assertEqual(S3_MOCK.put_object.call_count, 2)
        self.assertEqual(SNS_MOCK.publish.call_count, 2)

        call_args_list = S3_MOCK.put_object.call_args_list
        for _, call_args in call_args_list:
            data = GzipFile(None, 'rb', fileobj=call_args['Body'])
            content = json.loads(data.read().decode('utf-8'))

            # Verify fields are valid dates
            self.assertIsNotNone(datetime.strptime(content['p_alert_creation_time'], '%Y-%m-%d %H:%M:%S.%f000'))
            self.assertIsNotNone(datetime.strptime(content['p_alert_update_time'], '%Y-%m-%d %H:%M:%S.%f000'))

            if 'key1' in content:
                # Verify actual event
                self.assertEqual(content['key1'], 'value1')
                # Verify extra fields
                self.assertEqual(content['p_rule_id'], 'id1')
                self.assertEqual(content['p_alert_id'], hashlib.md5(b'id1:1:dedup').hexdigest())  # nosec
            elif 'key2' in content:
                # Verify actual event
                self.assertEqual(content['key2'], 'value2')
                # Verify extra fields
                self.assertEqual(content['p_rule_id'], 'id2')
                self.assertEqual(content['p_alert_id'], hashlib.md5(b'id2:1:dedup').hexdigest())  # nosec
            else:
                self.fail('unexpected content')

        # Assert that the buffer has been cleared
        self.assertEqual(len(buffer.data), 0)
        self.assertEqual(buffer.bytes_in_memory, 0)

    def test_group_events_together(self) -> None:
        buffer = MatchedEventsBuffer()
        buffer.add_event(EventMatch('id', 'version', 'log', 'dedup', 'INFO', {'key1': 'value1'}))
        buffer.add_event(EventMatch('id', 'version', 'log', 'dedup', 'INFO', {'key2': 'value2'}))

        self.assertEqual(len(buffer.data), 1)

        DDB_MOCK.update_item.return_value = {'Attributes': {'alertCount': {'N': '1'}}}
        buffer.flush()

        DDB_MOCK.update_item.assert_called_once()
        S3_MOCK.put_object.assert_called_once()
        SNS_MOCK.publish.assert_called_once()

        _, call_args = S3_MOCK.put_object.call_args
        data = GzipFile(None, 'rb', fileobj=call_args['Body'])

        # Verify first event
        event1 = json.loads(data.readline().decode('utf-8'))
        self.assertIsNotNone(datetime.strptime(event1['p_alert_creation_time'], '%Y-%m-%d %H:%M:%S.%f000'))
        self.assertIsNotNone(datetime.strptime(event1['p_alert_update_time'], '%Y-%m-%d %H:%M:%S.%f000'))
        self.assertEqual(event1['p_rule_id'], 'id')
        self.assertEqual(event1['p_alert_id'], hashlib.md5(b'id:1:dedup').hexdigest())  # nosec
        self.assertEqual(event1['key1'], 'value1')

        # Verify first event
        event2 = json.loads(data.readline().decode('utf-8'))
        self.assertIsNotNone(datetime.strptime(event2['p_alert_creation_time'], '%Y-%m-%d %H:%M:%S.%f000'))
        self.assertIsNotNone(datetime.strptime(event2['p_alert_update_time'], '%Y-%m-%d %H:%M:%S.%f000'))
        self.assertEqual(event2['p_rule_id'], 'id')
        self.assertEqual(event2['p_alert_id'], hashlib.md5(b'id:1:dedup').hexdigest())  # nosec
        self.assertEqual(event2['key2'], 'value2')

        # Assert that the buffer has been cleared
        self.assertEqual(len(buffer.data), 0)
        self.assertEqual(buffer.bytes_in_memory, 0)

    def test_add_overflows_buffer(self) -> None:
        buffer = MatchedEventsBuffer()
        # Reducing max_bytes so that it will cause the overflow condition to trigger earlier
        buffer.max_bytes = 50
        event_match = EventMatch('rule_id', 'rule_version', 'log_type', 'dedup', 'INFO', {'data_key': 'data_value'})

        DDB_MOCK.update_item.return_value = {'Attributes': {'alertCount': {'N': '1'}}}

        buffer.add_event(event_match)

        DDB_MOCK.update_item.assert_called_once()
        S3_MOCK.put_object.assert_called_once()
        SNS_MOCK.publish.assert_called_once()

        # Assert that the buffer has been cleared
        self.assertEqual(len(buffer.data), 0)
        self.assertEqual(buffer.bytes_in_memory, 0)
