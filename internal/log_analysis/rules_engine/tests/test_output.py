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

import hashlib
import json
import os
import re
from datetime import datetime
from gzip import GzipFile
from unittest import TestCase, mock

import boto3

from . import mock_to_return, DDB_MOCK, S3_MOCK, SNS_MOCK
from ..src import EngineResult

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
        event_match = EngineResult(
            rule_id='rule_id',
            rule_version='rule_version',
            log_type='log_type',
            dedup='dedup',
            dedup_period_mins=100,
            alert_context='{"key":"value"}',
            event={'data_key': 'data_value'},
            title='test title'
        )
        buffer.add_event(event_match)

        self.assertEqual(len(buffer.data), 1)

        DDB_MOCK.update_item.return_value = {'Attributes': {'alertCount': {'N': '1'}}}
        buffer.flush()

        DDB_MOCK.update_item.assert_called_once_with(
            ConditionExpression='(#1 < :1) OR (attribute_not_exists(#2))',
            ExpressionAttributeNames={
                '#1': 'alertCreationTime',
                '#2': 'partitionKey',
                '#3': 'alertCount',
                '#4': 'ruleId',
                '#5': 'dedup',
                '#6': 'alertCreationTime',
                '#7': 'alertUpdateTime',
                '#8': 'eventCount',
                '#9': 'logTypes',
                '#10': 'ruleVersion',
                '#11': 'type',
                '#12': 'context',
                '#13': 'title'
            },
            ExpressionAttributeValues={
                ':1': {
                    'N': mock.ANY
                },
                ':3': {
                    'N': '1'
                },
                ':4': {
                    'S': 'rule_id'
                },
                ':5': {
                    'S': 'dedup'
                },
                ':6': {
                    'N': mock.ANY
                },
                ':7': {
                    'N': mock.ANY
                },
                ':8': {
                    'N': '1'
                },
                ':9': {
                    'SS': ['log_type']
                },
                ':10': {
                    'S': 'rule_version'
                },
                ':11': {
                    'S': 'RULE'
                },
                ':12': {
                    'S': '{"key":"value"}'
                },
                ':13': {
                    'S': 'test title'
                },
            },
            Key={
                'partitionKey': {
                    'S':
                        hashlib.md5(b'rule_id:dedup').hexdigest()  # nosec
                }
            },
            ReturnValues='ALL_NEW',
            TableName='table_name',
            UpdateExpression='ADD #3 :3\nSET #4=:4, #5=:5, #6=:6, #7=:7, #8=:8, #9=:9, #10=:10, #11=:11, #12=:12, #13=:13'
        )

        S3_MOCK.put_object.assert_called_once_with(Body=mock.ANY, Bucket='s3_bucket', ContentType='gzip', Key=mock.ANY)

        _, call_args = S3_MOCK.put_object.call_args
        bucket = call_args['Bucket']
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

        _, call_args = SNS_MOCK.publish.call_args
        message_json = json.loads(call_args['Message'])
        self.assertEqual(message_json['Records'][0]['s3']['bucket']['name'], bucket)
        self.assertEqual(message_json['Records'][0]['s3']['object']['key'], key)

        # Assert that the buffer has been cleared
        self.assertEqual(len(buffer.data), 0)
        self.assertEqual(buffer.bytes_in_memory, 0)

    def test_add_same_rule_different_log(self) -> None:
        buffer = MatchedEventsBuffer()
        buffer.add_event(
            EngineResult(
                rule_id='id', rule_version='version', log_type='log1', dedup='dedup', dedup_period_mins=100, event={'key1': 'value1'}
            )
        )
        buffer.add_event(
            EngineResult(
                rule_id='id', rule_version='version', log_type='log2', dedup='dedup', dedup_period_mins=100, event={'key2': 'value2'}
            )
        )

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
        buffer.add_event(
            EngineResult(
                rule_id='id1',
                rule_version='version',
                log_type='log',
                dedup='dedup',
                dedup_period_mins=100,
                event={'key1': 'value1'},
                rule_tags=['test-tag'],
                rule_reports={'key': ['value']}
            )
        )
        buffer.add_event(
            EngineResult(
                rule_id='id2', rule_version='version', log_type='log', dedup='dedup', dedup_period_mins=100, event={'key2': 'value2'}
            )
        )

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
                self.assertEqual(content['p_rule_tags'], ['test-tag'])
                self.assertEqual(content['p_rule_reports'], {'key': ['value']})
                self.assertEqual(content['p_alert_id'], hashlib.md5(b'id1:1:dedup').hexdigest())  # nosec
            elif 'key2' in content:
                # Verify actual event
                self.assertEqual(content['key2'], 'value2')
                # Verify extra fields
                self.assertEqual(content['p_rule_id'], 'id2')
                # Assert that tags row is not populated
                self.assertEqual(content['p_rule_tags'], [])
                self.assertEqual(content['p_rule_reports'], {})
                self.assertEqual(content['p_alert_id'], hashlib.md5(b'id2:1:dedup').hexdigest())  # nosec
            else:
                self.fail('unexpected content')

        # Assert that the buffer has been cleared
        self.assertEqual(len(buffer.data), 0)
        self.assertEqual(buffer.bytes_in_memory, 0)

    def test_group_events_together(self) -> None:
        buffer = MatchedEventsBuffer()
        buffer.add_event(
            EngineResult(
                rule_id='id', rule_version='version', log_type='log', dedup='dedup', dedup_period_mins=100, event={'key1': 'value1'}
            )
        )
        buffer.add_event(
            EngineResult(
                rule_id='id', rule_version='version', log_type='log', dedup='dedup', dedup_period_mins=100, event={'key2': 'value2'}
            )
        )

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
        buffer.max_bytes = 20
        event_match = EngineResult(
            rule_id='rule_id',
            rule_version='rule_version',
            log_type='log_type',
            dedup='dedup',
            dedup_period_mins=100,
            event={'data_key': 'data_value'}
        )

        DDB_MOCK.update_item.return_value = {'Attributes': {'alertCount': {'N': '1'}}}

        buffer.add_event(event_match)

        DDB_MOCK.update_item.assert_called_once()
        S3_MOCK.put_object.assert_called_once()
        SNS_MOCK.publish.assert_called_once()

        # Assert that the buffer has been cleared
        self.assertEqual(len(buffer.data), 0)
        self.assertEqual(buffer.bytes_in_memory, 0)
