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
_RULE_ID_ATTR_NAME = 'ruleId'
_DEDUP_STR_ATTR_NAME = 'dedup'
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
    """The method will update the alertCreationTime, eventCount of an alert. If a new alert will have to be created,
    it will also create a new alertId with the appropriate alertCreationTime. """
    try:
        return _update_get_alert_info_conditional(match_time, num_matches, rule_id, dedup)
    except _DDB_CLIENT.exceptions.ConditionalCheckFailedException:
        # If conditional update failed on Condition, the event needs to be merged
        return _update_get_alert_info(match_time, num_matches, rule_id, dedup)


def _update_get_alert_info_conditional(match_time: datetime, num_matches: int, rule_id: str, dedup: str) -> AlertInfo:
    """Performs a conditional update to DDB to verify whether we need to create a new alert.
    The condition will succeed only if:
    1. It is the first time this rule with this dedup string fires
    2. This rule with the same dedup string has fired before, but it fired more than _ALERT_MERGE_PERIOD_SECONDS earlier
    """
    response = _DDB_CLIENT.update_item(
        TableName=_DDB_TABLE_NAME,
        Key={_PARTITION_KEY_NAME: {
            'S': _generate_key(rule_id, dedup)
        }},
        # Setting proper values for alertCreationTie, alertUpdateTime,
        UpdateExpression='SET #1=:1, #2=:2, #3=:3, #4=:4, #5=:5\nADD #6 :6',
        ConditionExpression='(#7 < :7) OR (attribute_not_exists(#8))',
        ExpressionAttributeNames={
            '#1': _RULE_ID_ATTR_NAME,
            '#2': _DEDUP_STR_ATTR_NAME,
            '#3': _ALERT_CREATION_TIME_ATTR_NAME,
            '#4': _ALERT_UPDATE_TIME_ATTR_NAME,
            '#5': _ALERT_EVENT_COUNT,
            '#6': _ALERT_COUNT_ATTR_NAME,
            '#7': _ALERT_CREATION_TIME_ATTR_NAME,
            '#8': _PARTITION_KEY_NAME,
        },
        ExpressionAttributeValues={
            ':1': {
                'S': rule_id
            },
            ':2': {
                'S': dedup
            },
            ':3': {
                'N': match_time.strftime('%s')
            },
            ':4': {
                'N': match_time.strftime('%s')
            },
            ':5': {
                'N': '{}'.format(num_matches)
            },
            ':6': {
                'N': '1'
            },
            ':7': {
                'N': '{}'.format(int(match_time.timestamp()) - _ALERT_MERGE_PERIOD_SECONDS)
            }
        },
        ReturnValues='ALL_NEW'
    )
    alert_count = response['Attributes'][_ALERT_COUNT_ATTR_NAME]['N']
    return AlertInfo(alert_id=rule_id + '-' + alert_count, alert_creation_time=match_time, alert_update_time=match_time)


def _update_get_alert_info(match_time: datetime, num_matches: int, rule_id: str, dedup: str) -> AlertInfo:
    """Updates the following attributes in DDB:
    1. Alert event account - it adds the new events to existing
    2. Alert Update Time - it sets it to given time
    """
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
