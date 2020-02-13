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
from datetime import datetime

import boto3

from . import AlertInfo

_DDB_TABLE_NAME = os.environ['ALERTS_DEDUP_TABLE']
_DDB_CLIENT = boto3.client('dynamodb')

# DDB Table attributes and keys
_PARTITION_KEY_NAME = 'partitionKey'
_ALERT_CREATION_TIME_ATTR_NAME = 'alertCreationTime'
_ALERT_UPDATE_TIME_ATTR_NAME = 'alertUpdateTime'
_ALERT_COUNT_ATTR_NAME = 'alertCount'
_ALERT_EVENT_COUNT = 'eventCount'

# TODO Once rules store alert merge period, retrieve it from there
# Currently grouping in 1hr periods
_ALERT_MERGE_PERIOD_SECONDS = 3600


def _generate_key(rule_id: str, dedup: str) -> str:
    return rule_id + '-' + dedup


def update_get_alert_info(match_time: datetime, num_matches: int, rule_id: str, dedup: str) -> AlertInfo:
    """The method will return the alert information after evaluating if a new alert needs to be created
        or if we can re-use an existing alert."""
    try:
        alert_info = _update_get_alert_info_conditional(match_time, num_matches, rule_id, dedup)
        return alert_info
    except _DDB_CLIENT.exceptions.ConditionalCheckFailedException:
        # If conditional update failed on Condition, the event needs to be merged
        return _update_get_alert_info(match_time, num_matches, rule_id, dedup)


def _update_get_alert_info_conditional(match_time: datetime, num_matches: int, rule_id: str, dedup: str) -> AlertInfo:
    """Performs a conditional update to DDB to verify whether we need to create a new alert"""
    response = _DDB_CLIENT.update_item(
        TableName=_DDB_TABLE_NAME,
        Key={_PARTITION_KEY_NAME: {
            'S': _generate_key(rule_id, dedup)
        }},
        # Setting proper values for alertCreationTie, alertUpdateTime,
        UpdateExpression='SET #1=:1, #2=:2, #3=:3\nADD #4 :4',
        ConditionExpression='(#5 < :5) OR (attribute_not_exists(#6))',
        ExpressionAttributeNames={
            '#1': _ALERT_CREATION_TIME_ATTR_NAME,
            '#2': _ALERT_UPDATE_TIME_ATTR_NAME,
            '#3': _ALERT_EVENT_COUNT,
            '#4': _ALERT_COUNT_ATTR_NAME,
            '#5': _ALERT_CREATION_TIME_ATTR_NAME,
            '#6': _PARTITION_KEY_NAME,
        },
        ExpressionAttributeValues={
            ':1': {
                'N': match_time.strftime('%s')
            },
            ':2': {
                'N': match_time.strftime('%s')
            },
            ':3': {
                'N': '{}'.format(num_matches)
            },
            ':4': {
                'N': '1'
            },
            ':5': {
                'N': '{}'.format(int(match_time.timestamp()) - _ALERT_MERGE_PERIOD_SECONDS)
            }
        },
        ReturnValues='ALL_NEW'
    )
    alert_count = response['Attributes'][_ALERT_COUNT_ATTR_NAME]['N']
    return AlertInfo(alert_id=rule_id + '-' + alert_count, alert_creation_time=match_time, alert_update_time=match_time)


def _update_get_alert_info(match_time: datetime, num_matches: int, rule_id: str, dedup: str) -> AlertInfo:
    """Updated alert information"""
    response = _DDB_CLIENT.update_item(
        TableName=_DDB_TABLE_NAME,
        Key={_PARTITION_KEY_NAME: {
            'S': _generate_key(rule_id, dedup)
        }},
        # Setting proper value to alertUpdateTime. Increase event count
        UpdateExpression='SET #1=:1\nADD #2 :2',
        ExpressionAttributeNames={
            '#1': _ALERT_UPDATE_TIME_ATTR_NAME,
            '#2': _ALERT_EVENT_COUNT,
        },
        ExpressionAttributeValues={
            ':1': {
                'N': match_time.strftime('%s')
            },
            ':2': {
                'N': '{}'.format(num_matches)
            },
        },
        ReturnValues='ALL_NEW'
    )
    alert_count = response['Attributes'][_ALERT_COUNT_ATTR_NAME]['N']
    alert_creation_time = response['Attributes'][_ALERT_CREATION_TIME_ATTR_NAME]['N']
    return AlertInfo(
        alert_id=rule_id + '-' + alert_count,
        alert_creation_time=datetime.utcfromtimestamp(int(alert_creation_time)),
        alert_update_time=match_time
    )
