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
from typing import List, Dict, Tuple

import boto3

# Max number of SQS messages inside an SQS batch
_MAX_MESSAGES = 10
# Max size of an SQS batch request
_MAX_MESSAGE_SIZE = 256 * 1000

_SQS_RESOURCE = boto3.resource('sqs')
_QUEUE_NAME = _SQS_RESOURCE.get_queue_by_name(QueueName=os.environ['ALERTS_QUEUE'])  # pylint: disable=no-member


def send_to_sqs(matches: List) -> None:
    """Send a tuple of (rule_id, event) to SQS."""
    messages = [_match_to_sqs_entry_message(i) for i in matches]

    current_entries: List[Dict[str, str]] = []
    current_byte_size = 0

    for i, message in enumerate(messages):
        entry = {'Id': str(i), 'MessageBody': message}
        projected_size = current_byte_size + len(message)
        projected_num_entries = len(current_entries) + 1
        if projected_num_entries > _MAX_MESSAGES or projected_size > _MAX_MESSAGE_SIZE:
            _QUEUE_NAME.send_messages(Entries=current_entries)
            current_entries = [entry]
            current_byte_size = len(message)
        else:
            current_entries.append(entry)
            current_byte_size += len(message)

    if len(current_entries) > 0:
        _QUEUE_NAME.send_messages(Entries=current_entries)


def _match_to_sqs_entry_message(match: Tuple[str, str]) -> str:
    notification = {'ruleId': match[0], 'event': match[1], 'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}
    return json.dumps(notification)
