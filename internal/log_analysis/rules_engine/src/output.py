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
import sys
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from io import BytesIO
from typing import Dict, List, Optional

import boto3

from . import AlertInfo, EventMatch, OutputNotification
from .alert_merger import update_get_alert_info
from .logging import get_logger

_KEY_FORMAT = 'rules/{}/year={:d}/month={:02d}/day={:02d}/hour={:02d}/rule_id={}/{}-{}.json.gz'
# Maximum number of events in an S3 object
_MAX_BYTES_IN_MEMORY = 100000000
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
class BufferKey:
    """Class representing the key for internal buffer"""
    rule_id: str
    log_type: str
    dedup: str

    def table_name(self) -> str:
        """ Output the name of the Glue table name for this log type"""
        return self.log_type.lower().replace('.', '_')


@dataclass
class BufferValue:
    """Class representing the value of the internal buffer"""
    matches: List[EventMatch]
    size_in_bytes: int


class MatchedEventsBuffer:
    """Buffer containing the matched events"""

    def __init__(self) -> None:
        self.data: Dict[BufferKey, BufferValue] = collections.defaultdict()
        self.bytes_in_memory = 0
        self.max_bytes = _MAX_BYTES_IN_MEMORY
        self.total_events = 0

    def add_event(self, match: EventMatch) -> None:
        """Adds a matched event to the buffer"""
        key = BufferKey(match.rule_id, match.log_type, match.dedup)
        # Getting estimation of struct size in memory
        size = sys.getsizeof(match)

        value = self.data.get(key)
        if value:
            value.matches.append(match)
            value.size_in_bytes += size
        else:
            value = BufferValue([match], size)
            self.data[key] = value

        self.bytes_in_memory += size
        self.total_events += 1
        # Check the total size of data in memory. If we exceed threshold, flush data from the biggest 'offender'
        if self.bytes_in_memory > self.max_bytes:
            _LOGGER.debug('data reached size threshold')
            max_size = 0
            key_to_remove: Optional[BufferKey]
            for key, value in self.data.items():
                if value.size_in_bytes > max_size:
                    max_size = value.size_in_bytes
                    key_to_remove = key

            if key_to_remove:
                # Write the data to S3
                _write_to_s3(datetime.utcnow(), key_to_remove, self.data[key_to_remove].matches)
                self.bytes_in_memory -= self.data[key_to_remove].size_in_bytes
                # Delete data from memory
                del self.data[key_to_remove]

    def flush(self) -> None:
        """Flushes the buffer and writes data in S3"""
        current_time = datetime.utcnow()
        for key, values in self.data.items():
            _write_to_s3(current_time, key, values.matches)
        self.data.clear()
        self.bytes_in_memory = 0
        self.total_events = 0


def _write_to_s3(time: datetime, key: BufferKey, events: List[EventMatch]) -> None:
    rule_severity = events[0].severity  # severity of a rule might differ if the rule was modifying while the rules
    # engine was running. We pick the first encountered severity as the alert severity
    alert_info = update_get_alert_info(time, len(events), key.rule_id, key.dedup, key.log_type, rule_severity)
    data_stream = BytesIO()
    writer = gzip.GzipFile(fileobj=data_stream, mode='wb')
    for event in events:
        serialized_data = _serialize_event(event, alert_info)
        writer.write(serialized_data)

    writer.close()
    data_stream.seek(0)
    output_uuid = uuid.uuid4()
    object_key = _KEY_FORMAT.format(
        key.table_name(), time.year, time.month, time.day, time.hour, key.rule_id, time.strftime(_S3_KEY_DATE_FORMAT), output_uuid
    )

    byte_size = data_stream.getbuffer().nbytes
    # Write data to S3
    _S3_CLIENT.put_object(Bucket=_S3_BUCKET, ContentType='gzip', Body=data_stream, Key=object_key)

    # Send notification to SNS topic
    notification = OutputNotification(s3Bucket=_S3_BUCKET, s3ObjectKey=object_key, events=len(events), bytes=byte_size, id=key.rule_id)

    # MessageAttributes are required so that subscribers to SNS topic
    # can filter events in the subscription
    _SNS_CLIENT.publish(
        TopicArn=_SNS_TOPIC_ARN,
        Message=json.dumps(asdict(notification)),
        MessageAttributes={
            'type': {
                'DataType': 'String',
                'StringValue': notification.type
            },
            'id': {
                'DataType': 'String',
                'StringValue': notification.id
            }
        }
    )


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
