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
from typing import Dict, Any

import boto3
import json
from .logging import get_logger
from io import BytesIO
import datetime
import uuid
import os

import gzip

_key_format = "rules/{}/year={}/month={}/day={}/hour={}/rule_id={}/{}.gz"
_s3_bucket = os.environ['S3_BUCKET']
_s3_client = boto3.client('s3')


class Output:
    def __init__(self):
        self.rule_id_to_data: Dict[str, gzip.GzipFile] = collections.defaultdict()
        self.logger = get_logger()

    def matched_event(self, log_type: str, rule_id: str, event: Dict[str, Any]):
        dict_key = self._generate_dict_key(log_type, rule_id)
        compressed_stream = self.rule_id_to_data.get(rule_id)
        if not compressed_stream:
            data_stream = BytesIO()
            compressed_stream = gzip.GzipFile(fileobj=data_stream, mode='wb')
            self.rule_id_to_data[dict_key] = compressed_stream
        data = json.dumps(event).encode('utf-8')
        compressed_stream.write(data)

    def complete(self):
        current_time = datetime.datetime.utcnow()
        for dict_key, compressed_stream in self.rule_id_to_data.items():
            output_uuid = uuid.uuid4()
            compressed_stream.flush()
            log_type, rule_id = self._dict_key_to_log_type_rule_id(dict_key)
            object_key = _key_format.format(
                log_type,
                current_time.year,
                current_time.month,
                current_time.day,
                current_time.hour,
                rule_id,
                output_uuid)
            _s3_client.put_object(
                Bucket=_s3_bucket,
                ContentType='gzip',
                Body=compressed_stream.fileobj,
                Key=object_key)

    def _generate_dict_key(self, log_type: str, rule_id: str) -> str:
        return log_type + "-" + rule_id

    def _dict_key_to_log_type_rule_id(self, key: str) -> (str, str):
        values = key.split("-", 1)
        return values[0], values[1]
