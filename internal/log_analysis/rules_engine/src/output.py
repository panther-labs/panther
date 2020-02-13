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
from .alert_merger import update_get_alert_info
from .logging import get_logger

_KEY_FORMAT = 'rules/{}/year={}/month={}/day={}/hour={}/rule_id={}/{}-{}.gz'
_S3_KEY_DATE_FORMAT = '%Y%m%d%H%M%S'
_DATE_FORMAT = '%Y-%m-%d %H:%M:%S.%f000'
_S3_BUCKET = os.environ['S3_BUCKET']
_SNS_TOPIC_ARN = os.environ['NOTIFICATIONS_TOPIC']

# AWS Clients
_S3_CLIENT = boto3.client('s3')
_SNS_CLIENT = boto3.client('sns')

_LOGGER = get_logger()


@dataclass
class EventCommonFields:
    """Fields that will be added to all stored events"""
    p_rule_id: str
    p_alert_id: str
    p_alert_creation_time: str
    p_alert_update_time: str


@dataclass(frozen=True, eq=True)
class BufferDictKey:
    """Class representing the key for internal buffer"""
    rule_id: str
    log_type: str
    dedup: str


class MatchedEventsBuffer:
    """Buffer containing the matched events"""

    def __init__(self) -> None:
        self.data: Dict[BufferDictKey, List[EventMatch]] = collections.defaultdict(list)

    def add_event(self, match: EventMatch) -> None:
        """Adds a matched event to the buffer"""
        key = BufferDictKey(match.rule_id, match.log_type, match.dedup)
        self.data[key].append(match)

    def flush(self) -> None:
        """Flushes the buffer and writes data in S3"""
        current_time = datetime.utcnow()
        for key, events in self.data.items():
            alert_info = update_get_alert_info(current_time, len(events), key.rule_id, key.dedup)
            data_stream = BytesIO()
            writer = gzip.GzipFile(fileobj=data_stream, mode='wb')
            for event in events:
                serialized_data = _serialize_event(event, alert_info)
                writer.write(serialized_data)

            writer.close()
            data_stream.seek(0)
            output_uuid = uuid.uuid4()
            object_key = _KEY_FORMAT.format(
                key.log_type, current_time.year, current_time.month, current_time.day, current_time.hour, key.rule_id,
                current_time.strftime(_S3_KEY_DATE_FORMAT), output_uuid
            )

            byte_size = data_stream.getbuffer().nbytes
            # Write data to S3
            _S3_CLIENT.put_object(Bucket=_S3_BUCKET, ContentType='gzip', Body=data_stream, Key=object_key)

            # Send notification to SNS topic
            notification = OutputNotification(
                s3Bucket=_S3_BUCKET, s3ObjectKey=object_key, events=len(events), bytes=byte_size, id=key.rule_id
            )

            # MessageAttributes are required so that subscribers to SNS topic
            # can filter events in the subscription
            _SNS_CLIENT.publish(
                TopicArn=_SNS_TOPIC_ARN,
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


def _serialize_event(match: EventMatch, alert_info: AlertInfo) -> bytes:
    """Serializes an event match"""
    common_fields = _get_common_fields(match, alert_info)
    common_fields.update(match.event)
    data = json.dumps(common_fields) + '\n'
    return data.encode('utf-8')


def _get_common_fields(match: EventMatch, alert_info: AlertInfo) -> Dict[str, str]:
    """Retrieves a dictionary with common fields"""
    common_fields = EventCommonFields(
        p_rule_id=match.rule_id,
        p_alert_id=alert_info.alert_id,
        p_alert_creation_time=alert_info.alert_creation_time.strftime(_DATE_FORMAT),
        p_alert_update_time=alert_info.alert_update_time.strftime(_DATE_FORMAT)
    )
    return asdict(common_fields)
