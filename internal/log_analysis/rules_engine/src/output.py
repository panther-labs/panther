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
import collections
import gzip
import json
import os
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime
from io import BytesIO
from typing import Dict, List

import boto3

from . import EventMatch, OutputNotification, AlertInfo
from .alert_merger import Merger
from .logging import get_logger

_KEY_FORMAT = 'rules/{}/year={}/month={}/day={}/hour={}/rule_id={}/{}-{}.gz'
_S3_KEY_DATE_FORMAT = '%Y%m%d%H%M%S'
_DATE_FORMAT = '%Y-%m-%d %H:%M:%S.%f000'
_s3_bucket = os.environ['S3_BUCKET']
_sns_topic = os.environ['NOTIFICATIONS_TOPIC']

_s3_client = boto3.client('s3')
_sns_client = boto3.client('sns')

_logger  = get_logger()

@dataclass
class EventCommonFields:
    """Fields that will be added to all stored events"""
    p_rule_id: str
    p_alert_id: str
    p_alert_creation_time: str
    p_alert_update_time: str


@dataclass(frozen=True, eq=True)
class BufferDictKey:
    rule_id: str
    log_type: str
    dedup: str


class MatchedEventsBuffer:
    """Buffer containing the matched events"""

    def __init__(self):
        self.merger = Merger()
        self.data: Dict[BufferDictKey, List[EventMatch]] = collections.defaultdict(list)

    def add_event(self, match: EventMatch) -> None:
        """Adds a matched event to the buffer"""
        key = BufferDictKey(match.rule_id, match.log_type, match.dedup)
        self.data[key].append(match)

    def flush(self):
        """Flushes the buffer and writes data in S3"""
        current_time = datetime.utcnow()
        for key, events in self.data.items():
            alert_info = self.merger.update_get_alert_info(current_time, len(events, key.rule_id, key.dedup))
            data_stream = BytesIO()
            writer = gzip.GzipFile(fileobj=data_stream, mode='wb')
            for event in events:
                serialized_data = self._serialize_event(event, alert_info)
                writer.write(serialized_data)

            writer.close()
            data_stream.seek(0)
            output_uuid = uuid.uuid4()
            object_key = _KEY_FORMAT.format(
                key.log_type,
                current_time.year,
                current_time.month,
                current_time.day,
                current_time.hour,
                key.rule_id,
                current_time.strftime(_S3_KEY_DATE_FORMAT),
                output_uuid)

            byte_size = data_stream.getbuffer().nbytes
            # Write data to S3
            _s3_client.put_object(
                Bucket=_s3_bucket,
                ContentType='gzip',
                Body=data_stream,
                Key=object_key)

            # Send notification to SNS topic
            notification = OutputNotification(
                s3Bucket=_s3_bucket,
                s3ObjectKey=object_key,
                events=len(events),
                bytes=byte_size,
                id=key.rule_id)

            # MessageAttributes are required so that subscribers to SNS topic
            # can filter events in the subscription
            _sns_client.publish(
                TopicArn=_sns_topic,
                Message=json.dumps(asdict(notification)),
                MessageAttributes={
                    "type": {
                        "DataType": "String",
                        'StringValue': notification.type
                    },
                    "id": {
                        "DataType": "String",
                        'StringValue': notification.id
                    }
                }
            )

        self.data.clear()

    def _serialize_event(self, match: EventMatch, alert_info: AlertInfo) -> bytearray:
        """Serializes an event match"""
        common_fields = self._get_common_fields(match, alert_info)
        common_fields.update(match.event)
        serialized_data = json.dumps(common_fields) + '\n'
        return serialized_data.encode('utf-8')

    def _get_common_fields(self, match: EventMatch, alert_info: AlertInfo) -> Dict[str, str]:
        """Retrieves a dictionary with common fields"""
        common_fields = EventCommonFields(
            p_rule_id=match.rule_id,
            p_alert_id=alert_info.alert_id,
            p_alert_creation_time=alert_info.alert_creation_time.strftime(_DATE_FORMAT),
            p_alert_update_time=alert_info.alert_update_time.strftime(_DATE_FORMAT)
        )
        return asdict(common_fields)
