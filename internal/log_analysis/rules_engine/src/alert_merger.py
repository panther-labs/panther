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

from datetime import datetime
import hashlib
import os
from typing import Optional

import boto3

from . import AlertInfo, OutputGroupingKey

_DDB_TABLE_NAME = os.environ['ALERTS_DEDUP_TABLE']
_DDB_CLIENT = boto3.client('dynamodb')

# DDB Table attributes and keys
_PARTITION_KEY_NAME = 'partitionKey'
_RULE_ID_ATTR_NAME = 'ruleId'
_RULE_VERSION_ATTR_NAME = "ruleVersion"
_DEDUP_STR_ATTR_NAME = 'dedup'
_ALERT_CREATION_TIME_ATTR_NAME = 'alertCreationTime'
_ALERT_UPDATE_TIME_ATTR_NAME = 'alertUpdateTime'
_ALERT_COUNT_ATTR_NAME = 'alertCount'
_ALERT_EVENT_COUNT = 'eventCount'
_ALERT_SEVERITY_ATTR_NAME = 'severity'
_ALERT_LOG_TYPES = 'logTypes'
_ALERT_TITLE = 'title'

# TODO Once rules store alert merge period, retrieve it from there
# Currently grouping in 1hr periods
_ALERT_MERGE_PERIOD_SECONDS = 3600


def _generate_dedup_key(rule_id: str, dedup: str) -> str:
    key = rule_id + ':' + dedup
    return hashlib.md5(key.encode('utf-8')).hexdigest()  # nosec


def _generate_alert_id(rule_id: str, dedup: str, count: str) -> str:
    key = rule_id + ':' + count + ':' + dedup
    return hashlib.md5(key.encode('utf-8')).hexdigest()  # nosec


def update_get_alert_info(match_time: datetime, num_matches: int, key: OutputGroupingKey, severity: str, version: str, title: Optional[str]) -> AlertInfo:
    """Updates the alert information and returns the result.

    The method will update the alertCreationTime, eventCount of an alert. If a new alert will have to be created,
    it will also create a new alertId with the appropriate alertCreationTime. """
    try:
        return _update_get_conditional(match_time, num_matches, key, severity, version, title)
    except _DDB_CLIENT.exceptions.ConditionalCheckFailedException:
        # If conditional update failed on Condition, the event needs to be merged
        return _update_get(match_time, num_matches, key)


def _update_get_conditional(time: datetime, matches: int, key: OutputGroupingKey, severity: str, version: str, title: Optional[str]) -> AlertInfo:
    """Performs a conditional update to DDB to verify whether we need to create a new alert.
    The condition will succeed only if:
    1. It is the first time this rule with this dedup string fires
    2. This rule with the same dedup string has fired before, but it fired more than _ALERT_MERGE_PERIOD_SECONDS earlier
    """
    condition_expression = '(#1 < :1) OR (attribute_not_exists(#2))'
    update_expression = 'ADD #3 :3\nSET #4=:4, #5=:5, #6=:6, #7=:7, #8=:8, #9=:9, #10=:10, #11=:11'

    if title:
        update_expression += ', #12=:12'
    expresion_attribute_names = {
        '#1': _ALERT_CREATION_TIME_ATTR_NAME,
        '#2': _PARTITION_KEY_NAME,
        '#3': _ALERT_COUNT_ATTR_NAME,
        '#4': _RULE_ID_ATTR_NAME,
        '#5': _DEDUP_STR_ATTR_NAME,
        '#6': _ALERT_CREATION_TIME_ATTR_NAME,
        '#7': _ALERT_UPDATE_TIME_ATTR_NAME,
        '#8': _ALERT_EVENT_COUNT,
        '#9': _ALERT_SEVERITY_ATTR_NAME,
        '#10': _ALERT_LOG_TYPES,
        '#11': _RULE_VERSION_ATTR_NAME,
    }

    if title:
        expresion_attribute_names['#12'] = _ALERT_TITLE

    expression_attribute_values = {
        ':1': {
            'N': '{}'.format(int(time.timestamp()) - _ALERT_MERGE_PERIOD_SECONDS)
        },
        ':3': {
            'N': '1'
        },
        ':4': {
            'S': key.rule_id
        },
        ':5': {
            'S': key.dedup
        },
        ':6': {
            'N': time.strftime('%s')
        },
        ':7': {
            'N': time.strftime('%s')
        },
        ':8': {
            'N': '{}'.format(matches)
        },
        ':9': {
            'S': severity
        },
        ':10': {
            'SS': [key.log_type]
        },
        ':11': {
            'S': version
        },
    }

    if title:
        expression_attribute_values[':12'] = {'S': title}

    response = _DDB_CLIENT.update_item(
        TableName=_DDB_TABLE_NAME,
        Key={_PARTITION_KEY_NAME: {
            'S': _generate_dedup_key(key.rule_id, key.dedup)
        }},
        # Setting proper values for alertCreationTime, alertUpdateTime,
        UpdateExpression= update_expression,
        ConditionExpression=condition_expression,
        ExpressionAttributeNames=expresion_attribute_names,
        ExpressionAttributeValues=expression_attribute_values,
        ReturnValues='ALL_NEW'
    )
    alert_count = response['Attributes'][_ALERT_COUNT_ATTR_NAME]['N']
    alert_id = _generate_alert_id(key.rule_id, key.dedup, alert_count)
    return AlertInfo(alert_id=alert_id, alert_creation_time=time, alert_update_time=time)


def _update_get(match_time: datetime, num_matches: int, key: OutputGroupingKey) -> AlertInfo:
    """Updates the following attributes in DDB:
    1. Alert event account - it adds the new events to existing
    2. Alert Update Time - it sets it to given time
    """
    response = _DDB_CLIENT.update_item(
        TableName=_DDB_TABLE_NAME,
        Key={_PARTITION_KEY_NAME: {
            'S': _generate_dedup_key(key.rule_id, key.dedup)
        }},
        # Setting proper value to alertUpdateTime. Increase event count
        UpdateExpression='SET #1=:1\nADD #2 :2, #3 :3',
        ExpressionAttributeNames={
            '#1': _ALERT_UPDATE_TIME_ATTR_NAME,
            '#2': _ALERT_EVENT_COUNT,
            '#3': _ALERT_LOG_TYPES
        },
        ExpressionAttributeValues={
            ':1': {
                'N': match_time.strftime('%s')
            },
            ':2': {
                'N': '{}'.format(num_matches)
            },
            ':3': {
                'SS': [key.log_type]
            },
        },
        ReturnValues='ALL_NEW'
    )
    alert_count = response['Attributes'][_ALERT_COUNT_ATTR_NAME]['N']
    alert_creation_time = response['Attributes'][_ALERT_CREATION_TIME_ATTR_NAME]['N']
    return AlertInfo(
        alert_id=_generate_alert_id(key.rule_id, key.dedup, alert_count),
        alert_creation_time=datetime.utcfromtimestamp(int(alert_creation_time)),
        alert_update_time=match_time
    )
