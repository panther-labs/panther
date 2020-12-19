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

from . import AlertInfo, EngineResult, OutputGroupingKey
from .alert_merger import MatchingGroupInfo, update_get_alert_info
from .logging import get_logger
from .aws_clients import S3_CLIENT, SNS_CLIENT

# Format of the S3 objects containing the events that matched a rule
_RULE_MATCHES_KEY_FORMAT = 'rules/{}/year={:d}/month={:02d}/day={:02d}/hour={:02d}/rule_id={}/{}-{}.json.gz'
# Format of the S3 objects containing the events that caused an exception on the rule
_RULE_ERRORS_KEY_FORMAT = 'rule_errors/{}/year={:d}/month={:02d}/day={:02d}/hour={:02d}/rule_id={}/{}-{}.json.gz'
# Maximum number of events in an S3 object
_MAX_BYTES_IN_MEMORY = 100000000
_S3_KEY_DATE_FORMAT = '%Y%m%dT%H%M%SZ'
_DATE_FORMAT = '%Y-%m-%d %H:%M:%S.%f000'
_S3_BUCKET = os.environ['S3_BUCKET']
_SNS_TOPIC_ARN = os.environ['NOTIFICATIONS_TOPIC']

_LOGGER = get_logger()


# pylint: disable=too-many-instance-attributes,unsubscriptable-object
@dataclass
class EventCommonFields:
    """Fields that will be added to all stored events"""
    p_rule_id: str
    p_rule_tags: List[str]
    p_rule_reports: Dict[str, List[str]]
    p_alert_id: str
    p_alert_creation_time: str
    p_alert_update_time: str
    p_rule_error: Optional[str] = None
    p_alert_context: Optional[str] = None


@dataclass
class BufferValue:
    """Class representing the value of the internal buffer"""
    matches: List[EngineResult]
    size_in_bytes: int


class MatchedEventsBuffer:
    """Buffer containing the matched events"""

    def __init__(self) -> None:
        self.data: Dict[OutputGroupingKey, BufferValue] = collections.defaultdict()
        self.bytes_in_memory = 0
        self.max_bytes = _MAX_BYTES_IN_MEMORY
        self.total_events = 0

    def add_event(self, engine_result: EngineResult) -> None:
        """Adds a matched event to the buffer"""
        if engine_result.error_message:
            # If the engine result contains an error message, it means that the event in the result caused
            # the rule engine to throw an exception
            key = OutputGroupingKey(engine_result.rule_id, engine_result.log_type, engine_result.dedup, is_rule_error=True)
        else:
            # If the engine result doesn't contain an error message, it means the event in the result matched a rule
            key = OutputGroupingKey(engine_result.rule_id, engine_result.log_type, engine_result.dedup, is_rule_error=False)
        # Getting estimation of struct size in memory
        size = sys.getsizeof(engine_result)

        # Add event to the buffer
        value = self.data.get(key)
        if value:
            value.matches.append(engine_result)
            value.size_in_bytes += size
        else:
            value = BufferValue([engine_result], size)
            self.data[key] = value

        self.bytes_in_memory += size
        self.total_events += 1
        # Check the total size of data in memory. If we exceed threshold, flush data from the biggest 'offender'
        if self.bytes_in_memory > self.max_bytes:
            _LOGGER.debug("data reached size threshold")
            max_size = 0
            key_to_remove: Optional[OutputGroupingKey]  # pylint: disable=unsubscriptable-object
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


def _write_to_s3(time: datetime, key: OutputGroupingKey, events: List[EngineResult]) -> None:
    # 'version', 'title', 'dedup_period' of a rule might differ if the rule was modified
    # while the rules engine was running. We pick the first encountered set of values.

    group_info = MatchingGroupInfo(
        rule_id=key.rule_id,
        rule_version=events[0].rule_version,
        log_type=key.log_type,
        dedup=key.dedup,
        dedup_period_mins=events[0].dedup_period_mins,
        num_matches=len(events),
        processing_time=time,
        alert_context=events[0].alert_context,
        is_rule_error=key.is_rule_error,
        title=events[0].title,
        description=events[0].description,
        reference=events[0].reference,
        severity=events[0].severity,
        runbook=events[0].runbook,
        destinations=events[0].destinations,
    )
    alert_info = update_get_alert_info(group_info)
    data_stream = BytesIO()
    writer = gzip.GzipFile(fileobj=data_stream, mode='wb')
    for event in events:
        serialized_data = _serialize_event(event, alert_info)
        writer.write(serialized_data)

    writer.close()
    data_stream.seek(0)
    output_uuid = uuid.uuid4()
    if key.is_rule_error:
        key_format = _RULE_ERRORS_KEY_FORMAT
        data_type = 'RuleErrors'
    else:
        key_format = _RULE_MATCHES_KEY_FORMAT
        data_type = 'RuleMatches'

    object_key = key_format.format(
        key.table_name(), time.year, time.month, time.day, time.hour, key.rule_id, time.strftime(_S3_KEY_DATE_FORMAT), output_uuid
    )

    byte_size = data_stream.getbuffer().nbytes
    # Write data to S3
    S3_CLIENT.put_object(Bucket=_S3_BUCKET, ContentType='gzip', Body=data_stream, Key=object_key)

    # Send notification to SNS topic
    notification = _s3_put_object_notification(_S3_BUCKET, object_key, byte_size)

    # MessageAttributes are required so that subscribers to SNS topic can filter events in the subscription
    SNS_CLIENT.publish(
        TopicArn=_SNS_TOPIC_ARN,
        Message=json.dumps(notification),
        MessageAttributes={
            'type': {
                'DataType': 'String',
                'StringValue': data_type,
            },
            'id': {
                'DataType': 'String',
                'StringValue': key.rule_id
            }
        }
    )


def _s3_put_object_notification(bucket: str, key: str, byte_size: int) -> Dict[str, list]:
    """The notification that will be sent to the SNS topic when we create a new object in S3.

    This needs to have a shape of an S3 event notification:
            https://docs.aws.amazon.com/AmazonS3/latest/dev/notification-content-structure.html

    All elements should be populated (at least with dummy data) to pass schema validation by consumers.
    """
    return {
        'Records':
            [
                {
                    'eventVersion': '2.0',
                    'eventSource': 'aws:s3',
                    'awsRegion': '',
                    'eventTime': '0001-01-01T00:00:00Z',
                    'eventName': 'ObjectCreated:Put',
                    'userIdentity': {
                        'principalId': ''
                    },
                    'requestParameters': {
                        'sourceIPAddress': ''
                    },
                    'responseElements': None,
                    's3':
                        {
                            's3SchemaVersion': '',
                            'configurationId': '',
                            'bucket': {
                                'name': bucket,
                                'ownerIdentity': {
                                    'principalId': ''
                                },
                                'arn': ''
                            },
                            'object': {
                                'key': key,
                                'size': byte_size,
                                'urlDecodedKey': '',
                                'versionId': '',
                                'eTag': '',
                                'sequencer': ''
                            }
                        }
                }
            ]
    }


def _serialize_event(match: EngineResult, alert_info: AlertInfo) -> bytes:
    """Serializes an event match"""
    common_fields = _get_common_fields(match, alert_info)
    common_fields.update(match.event)
    data = json.dumps(common_fields) + '\n'
    return data.encode('utf-8')


def _get_common_fields(match: EngineResult, alert_info: AlertInfo) -> Dict[str, str]:
    """Retrieves a dictionary with common fields"""
    common_fields = EventCommonFields(
        p_rule_id=match.rule_id,
        p_alert_id=alert_info.alert_id,
        p_rule_tags=match.rule_tags,
        p_rule_reports=match.rule_reports,
        p_alert_creation_time=alert_info.alert_creation_time.strftime(_DATE_FORMAT),
        p_alert_update_time=alert_info.alert_update_time.strftime(_DATE_FORMAT),
        p_rule_error=match.error_message,
        p_alert_context=match.alert_context
    )
    return asdict(common_fields)
