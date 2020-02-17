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

import json
import os
from datetime import datetime
from gzip import GzipFile
from unittest import TestCase, mock

import boto3

from . import mock_to_return, DDB_MOCK, S3_MOCK, SNS_MOCK

with mock.patch.dict(os.environ, {'ALERTS_DEDUP_TABLE': 'table_name', 'S3_BUCKET': 's3_bucket', 'NOTIFICATIONS_TOPIC': 'sns_topic'}):
    with mock.patch.object(boto3, 'client', side_effect=mock_to_return) as mock_boto:
        from ..src.output import MatchedEventsBuffer
        from ..src import EventMatch


class TestMatchedEventsBuffer(TestCase):

    def setUp(self) -> None:
        S3_MOCK.reset_mock()
        SNS_MOCK.reset_mock()
        DDB_MOCK.reset_mock()

    def test_add_and_flush_event_generate_new_alert(self) -> None:
        buffer = MatchedEventsBuffer()
        event_match = EventMatch('rule_id', 'rule_version', 'log_type', 'dedup', {'data_key': 'data_value'})
        buffer.add_event(event_match)

        self.assertEqual(len(buffer.data), 1)

        DDB_MOCK.update_item.return_value = {'Attributes': {'alertCount': {'N': '1'}}}
        buffer.flush()

        DDB_MOCK.update_item.assert_called_once_with(
            ConditionExpression='(#5 < :5) OR (attribute_not_exists(#6))',
            ExpressionAttributeNames={
                '#1': 'alertCreationTime',
                '#2': 'alertUpdateTime',
                '#3': 'eventCount',
                '#4': 'alertCount',
                '#5': 'alertCreationTime',
                '#6': 'partitionKey'
            },
            ExpressionAttributeValues={
                ':1': {
                    'N': mock.ANY
                },
                ':2': {
                    'N': mock.ANY
                },
                ':3': {
                    'N': '1'
                },
                ':4': {
                    'N': '1'
                },
                ':5': {
                    'N': mock.ANY
                }
            },
            Key={'partitionKey': {
                'S': 'rule_id-dedup'
            }},
            ReturnValues='ALL_NEW',
            TableName='table_name',
            UpdateExpression='SET #1=:1, #2=:2, #3=:3\nADD #4 :4'
        )

        S3_MOCK.put_object.assert_called_once_with(Body=mock.ANY, Bucket='s3_bucket', ContentType='gzip', Key=mock.ANY)

        # Verify content
        _, call_args = S3_MOCK.put_object.call_args
        data = GzipFile(None, 'rb', fileobj=call_args['Body'])
        content = json.loads(data.read().decode('utf-8'))
        # Verify extra fields
        self.assertEqual(content['p_rule_id'], 'rule_id')
        self.assertEqual(content['p_alert_id'], 'rule_id-1')
        datetime.strptime(content['p_alert_creation_time'], '%Y-%m-%d %H:%M:%S.%f000')
        datetime.strptime(content['p_alert_update_time'], '%Y-%m-%d %H:%M:%S.%f000')
        # Actual event
        self.assertEqual(content['data_key'], 'data_value')

        SNS_MOCK.publish.assert_called_once_with(
            TopicArn='sns_topic',
            Message=mock.ANY,
            MessageAttributes={
                "type": {
                    "DataType": "String",
                    'StringValue': 'RuleOutput'
                },
                "id": {
                    "DataType": "String",
                    'StringValue': 'rule_id'
                }
            }
        )

        # Assert that the buffer has been cleared
        self.assertEqual(len(buffer.data), 0)
        self.assertEqual(buffer.total_bytes, 0)

    def test_add_overflows_buffer(self) -> None:
        buffer = MatchedEventsBuffer()
        # Reducing max_bytes so that it will cause the overflow condition to trigger earlier
        buffer.max_bytes = 50
        event_match = EventMatch('rule_id', 'rule_version', 'log_type', 'dedup', {'data_key': 'data_value'})

        DDB_MOCK.update_item.return_value = {'Attributes': {'alertCount': {'N': '1'}}}

        buffer.add_event(event_match)

        DDB_MOCK.update_item.assert_called_once()
        S3_MOCK.put_object.assert_called_once()
        SNS_MOCK.publish.assert_called_once()

        # Assert that the buffer has been cleared
        self.assertEqual(len(buffer.data), 0)
        self.assertEqual(buffer.total_bytes, 0)
