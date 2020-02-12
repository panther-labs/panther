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
import datetime
import gzip
import json
import os
import uuid
from dataclasses import dataclass
from io import BytesIO
from typing import Dict

import boto3

from .engine import AnalysisMatch
from .logging import get_logger
from .alert_merger import Merger

_KEY_FORMAT = 'rules/{}/year={}/month={}/day={}/hour={}/rule_id={}/{}-{}.gz'
_S3_KEY_DATE_FORMAT = '%Y%m%d%H%M%S'
_DATE_FORMAT = '%Y-%m-%d %H:%M:%S.%f000'
_s3_bucket = os.environ['S3_BUCKET']
_s3_client = boto3.client('s3')


@dataclass
class OutputInfo:
    writer: gzip.GzipFile
    data_stream: BytesIO
    processing_time: datetime.datetime


def _generate_dict_key(log_type: str, rule_id: str) -> str:
    return log_type + '-' + rule_id


def _dict_key_to_log_type_rule_id(key: str) -> (str, str):
    values = key.split('-', 1)
    return values[0], values[1]


class Output:
    def __init__(self):
        self.merger = Merger()
        self.rule_id_to_data: Dict[str, OutputInfo] = {}
        self.logger = get_logger()

    def add_match(self, match: AnalysisMatch) -> None:
        dict_key = _generate_dict_key(match.log_type, match.rule_id)
        output_info = self.rule_id_to_data.get(match.rule_id)
        if not output_info:
            data_stream = BytesIO()
            writer = gzip.GzipFile(fileobj=data_stream, mode='wb')
            current_time = datetime.datetime.utcnow()
            output_info = OutputInfo(writer, data_stream, current_time)
            self.rule_id_to_data[dict_key] = output_info

        serialized_data = self._serialize_event(output_info, match)
        output_info.writer.write(serialized_data.encode('utf-8'))

    def flush(self):
        for dict_key, output_info in self.rule_id_to_data.items():
            output_uuid = uuid.uuid4()
            output_info.writer.close()
            output_info.data_stream.seek(0)
            log_type, rule_id = _dict_key_to_log_type_rule_id(dict_key)
            object_key = _KEY_FORMAT.format(
                log_type,
                output_info.processing_time.year,
                output_info.processing_time.month,
                output_info.processing_time.day,
                output_info.processing_time.hour,
                rule_id,
                output_info.processing_time.strftime(_S3_KEY_DATE_FORMAT),
                output_uuid)
            _s3_client.put_object(
                Bucket=_s3_bucket,
                ContentType='gzip',
                Body=output_info.data_stream,
                Key=object_key)
        self.rule_id_to_data: Dict[str, OutputInfo] = collections.defaultdict()

    def _serialize_event(self, output_info: OutputInfo, match: AnalysisMatch) -> str:
        output_event = self._get_common_fields(output_info, match)
        output_event.update(match.event)
        serialized_data = json.dumps(output_event) + '\n'
        return serialized_data

    def _get_common_fields(self, output_info: OutputInfo, match: AnalysisMatch) -> Dict[str, str]:
        alert_info = self.merger.merge_alert(match, output_info.processing_time)
        return {
            'p_rule_id': match.rule_id,
            'p_alert_id': alert_info.alert_id,
            'p_alert_creation_time': alert_info.alert_creation_time.strftime(_DATE_FORMAT),
            'p_alert_update_time': alert_info.alert_update_time.strftime(_DATE_FORMAT)
        }
