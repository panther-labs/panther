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

import os
from typing import Dict

import boto3

from .logging import get_logger
from . import AlertInfo, AnalysisMatch
from datetime import datetime

_ddb_table = os.environ['ALERTS_DEDUP_TABLE']
_ddb_client = boto3.client('dynamodb')

_PARTITION_KEY_NAME = 'partitionKey'
_ALERT_CREATION_TIME_ATTR_NAME = 'alertCreationTime'
_ALERT_UPDATE_TIME_ATTR_NAME = 'alertUpdateTime'
_ALERT_COUNT_ATTR_NAME = 'alertCount'
_RULE_VERSION_ID_ATTR_NAME = 'ruleVersionId'

_ALERT_MERGE_PERIOD_SECONDS = 3600


def _generate_key(match: AnalysisMatch) -> str:
    return match.rule_id + '-' + match.dedup


class Merger:

    def __init__(self):
        self.rule_to_alert_id: Dict[str, AlertInfo] = {}
        self.logger = get_logger()

    def merge_alert(self, match: AnalysisMatch, processing_time: datetime) -> AlertInfo:
        dict_key = _generate_key(match)
        alert_info = self.rule_to_alert_id.get(dict_key)
        if alert_info:
            return alert_info

        return AlertInfo(
            alert_id="1",
            alert_update_time=processing_time,
            alert_creation_time=processing_time

        )
        # _ddb_client.update_item(
        #     TableName=_ddb_table,
        #     Key={
        #         _PARTITION_KEY_NAME: {
        #             'S': match.rule_id + '-' + match.dedup
        #         }
        #     },
        #
        # )
        # return None
