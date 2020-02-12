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
    """Class responsible for merging of Alerts"""
    def __init__(self):
        self.rule_to_alert_id: Dict[str, AlertInfo] = {}
        self.logger = get_logger()

    def get_alert_info(self, match: AnalysisMatch) -> AlertInfo:
        """The method receives a matched event and the processing time, and """
        key = _generate_key(match)
        alert_info = self.rule_to_alert_id.get(key)
        if alert_info:
            return alert_info

        try:
            alert_info = _update_alerts_conditionally(match)
            self.rule_to_alert_id[key] = alert_info
            return alert_info
        except _ddb_client.exceptions.ConditionalCheckFailedException as e:
            alert_info = _update_alert(match)
            self.rule_to_alert_id[key] = alert_info
            return alert_info


def _update_alert(match: AnalysisMatch) -> AlertInfo:
    response = _ddb_client.update_item(
        TableName=_ddb_table,
        Key={
            _PARTITION_KEY_NAME: {
                'S': _generate_key(match)
            }
        },
        UpdateExpression='SET #1=:1',
        ExpressionAttributeNames={
            '#1': _ALERT_UPDATE_TIME_ATTR_NAME,
        },
        ExpressionAttributeValues={
            ':1': {'N': match.analysis_time.strftime('%s')},
        },
        ReturnValues='ALL_NEW'
    )
    alert_count = response['Attributes'][_ALERT_COUNT_ATTR_NAME]['N']
    return AlertInfo(
        alert_id=match.rule_id + '-' + alert_count,
        alert_creation_time=match.analysis_time,
        alert_update_time=match.analysis_time
    )


def _update_alerts_conditionally(match: AnalysisMatch) -> AlertInfo:
    response = _ddb_client.update_item(
        TableName=_ddb_table,
        Key={
            _PARTITION_KEY_NAME: {
                'S': _generate_key(match)
            }
        },
        UpdateExpression='SET #1=:1, #2=:2, #3=:3\nADD #4 :4',
        ConditionExpression='(#5 < :5) OR (attribute_not_exists(#6))',
        ExpressionAttributeNames={
            '#1': _ALERT_CREATION_TIME_ATTR_NAME,
            '#2': _ALERT_UPDATE_TIME_ATTR_NAME,
            '#3': _RULE_VERSION_ID_ATTR_NAME,
            '#4': _ALERT_COUNT_ATTR_NAME,
            '#5': _ALERT_CREATION_TIME_ATTR_NAME,
            '#6': _PARTITION_KEY_NAME,
        },
        ExpressionAttributeValues={
            ':1': {'N': match.analysis_time.strftime('%s')},
            ':2': {'N': match.analysis_time.strftime('%s')},
            ':3': {'S': match.rule_version},
            ':4': {'N': '1'},
            ':5': {'N': '{}'.format(int(match.analysis_time.timestamp()) - _ALERT_MERGE_PERIOD_SECONDS)}
        },
        ReturnValues='ALL_NEW'
    )
    alert_count = response['Attributes'][_ALERT_COUNT_ATTR_NAME]['N']
    return AlertInfo(
        alert_id=match.rule_id + '-' + alert_count,
        alert_creation_time=match.analysis_time,
        alert_update_time=match.analysis_time
    )
