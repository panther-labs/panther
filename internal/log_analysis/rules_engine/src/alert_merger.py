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

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List

from . import AlertInfo
from .aws_clients import DDB_CLIENT

_DDB_TABLE_NAME = os.environ['ALERTS_DEDUP_TABLE']
# DDB Table attributes and keys

_PARTITION_KEY_NAME = 'partitionKey'
_RULE_ID_ATTR_NAME = 'ruleId'
_RULE_VERSION_ATTR_NAME = "ruleVersion"
_DEDUP_STR_ATTR_NAME = 'dedup'
_ALERT_CREATION_TIME_ATTR_NAME = 'alertCreationTime'
_ALERT_UPDATE_TIME_ATTR_NAME = 'alertUpdateTime'
_ALERT_COUNT_ATTR_NAME = 'alertCount'
_ALERT_EVENT_COUNT = 'eventCount'
_ALERT_LOG_TYPES = 'logTypes'
_ALERT_CONTEXT = 'context'
_ALERT_TITLE = 'title'
_ALERT_DESCRIPTION = 'description'
_ALERT_REFERENCE = 'reference'
_ALERT_SEVERITY = 'severity'
_ALERT_RUNBOOK = 'runbook'
_ALERT_DESTINATIONS = 'destinations'
# The attribute defining the type of the error
_ALERT_TYPE = 'type'


# pylint: disable=too-many-instance-attributes,unsubscriptable-object
@dataclass
class MatchingGroupInfo:
    """Represents information for a batch of matched events"""
    rule_id: str
    rule_version: str
    log_type: str
    dedup: str
    dedup_period_mins: int
    num_matches: int
    processing_time: datetime
    alert_context: Optional[str]
    is_rule_error: bool = False
    # generated fields
    title: Optional[str] = None
    description: Optional[str] = None
    reference: Optional[str] = None
    severity: Optional[str] = None
    runbook: Optional[str] = None
    destinations: Optional[List[str]] = None


def _generate_dedup_key(rule_id: str, dedup: str, is_rule_error: bool) -> str:
    key = rule_id + ':' + dedup
    if is_rule_error:
        key += ":error"
    return hashlib.md5(key.encode('utf-8')).hexdigest()  # nosec


def _generate_alert_id(rule_id: str, dedup: str, count: str) -> str:
    key = rule_id + ':' + count + ':' + dedup
    return hashlib.md5(key.encode('utf-8')).hexdigest()  # nosec


def update_get_alert_info(info: MatchingGroupInfo) -> AlertInfo:
    """Updates the alert information and returns the result.

    The method will update the alertCreationTime, eventCount of an alert. If a new alert will have to be created,
    it will also create a new alertId with the appropriate alertCreationTime. """
    try:
        return _update_get_conditional(info)
    except DDB_CLIENT.exceptions.ConditionalCheckFailedException:
        # If conditional update failed on Condition, the event needs to be merged
        return _update_get(info)


def _update_get_conditional(group_info: MatchingGroupInfo) -> AlertInfo:
    """Performs a conditional update to DDB to verify whether we need to create a new alert.
    The condition will succeed only if:
    1. It is the first time this rule with this dedup string fires
    2. This rule with the same dedup string has fired before, but after the dedup period has expired
    """
    condition_expression = '(#1 < :1) OR (attribute_not_exists(#2))'
    update_expression = 'ADD #3 :3\nSET #4=:4, #5=:5, #6=:6, #7=:7, #8=:8, #9=:9, #10=:10, #11=:11'

    expression_attribute_names = {
        '#1': _ALERT_CREATION_TIME_ATTR_NAME,
        '#2': _PARTITION_KEY_NAME,
        '#3': _ALERT_COUNT_ATTR_NAME,
        '#4': _RULE_ID_ATTR_NAME,
        '#5': _DEDUP_STR_ATTR_NAME,
        '#6': _ALERT_CREATION_TIME_ATTR_NAME,
        '#7': _ALERT_UPDATE_TIME_ATTR_NAME,
        '#8': _ALERT_EVENT_COUNT,
        '#9': _ALERT_LOG_TYPES,
        '#10': _RULE_VERSION_ATTR_NAME,
        '#11': _ALERT_TYPE
    }

    if group_info.is_rule_error:
        alert_type = "RULE_ERROR"
    else:
        alert_type = "RULE"

    expression_attribute_values = {
        ':1':
            {
                # Converting dedup_period_mins to seconds
                'N': '{}'.format(int(group_info.processing_time.timestamp()) - group_info.dedup_period_mins * 60)
            },
        ':3': {
            'N': '1'
        },
        ':4': {
            'S': group_info.rule_id
        },
        ':5': {
            'S': group_info.dedup
        },
        ':6': {
            'N': group_info.processing_time.strftime('%s')
        },
        ':7': {
            'N': group_info.processing_time.strftime('%s')
        },
        ':8': {
            'N': '{}'.format(group_info.num_matches)
        },
        ':9': {
            'SS': [group_info.log_type]
        },
        ':10': {
            'S': group_info.rule_version
        },
        ':11': {
            'S': alert_type
        },
    }

    if group_info.alert_context:
        update_expression += ', #12=:12'
        expression_attribute_names['#12'] = _ALERT_CONTEXT
        expression_attribute_values[':12'] = {'S': group_info.alert_context}

    if group_info.title:
        update_expression += ', #13=:13'
        expression_attribute_names['#13'] = _ALERT_TITLE
        expression_attribute_values[':13'] = {'S': group_info.title}

    if group_info.description:
        update_expression += ', #14=:14'
        expression_attribute_names['#14'] = _ALERT_DESCRIPTION
        expression_attribute_values[':14'] = {'S': group_info.description}

    if group_info.reference:
        update_expression += ', #15=:15'
        expression_attribute_names['#15'] = _ALERT_REFERENCE
        expression_attribute_values[':15'] = {'S': group_info.reference}

    if group_info.severity:
        update_expression += ', #16=:16'
        expression_attribute_names['#16'] = _ALERT_SEVERITY
        expression_attribute_values[':16'] = {'S': group_info.severity}

    if group_info.runbook:
        update_expression += ', #17=:17'
        expression_attribute_names['#17'] = _ALERT_RUNBOOK
        expression_attribute_values[':17'] = {'S': group_info.runbook}

    if group_info.destinations:
        update_expression += ', #18=:18'
        expression_attribute_names['#18'] = _ALERT_DESTINATIONS
        expression_attribute_values[':18'] = {'SS': group_info.destinations}

    response = DDB_CLIENT.update_item(
        TableName=_DDB_TABLE_NAME,
        Key={_PARTITION_KEY_NAME: {
            'S': _generate_dedup_key(group_info.rule_id, group_info.dedup, group_info.is_rule_error)
        }},
        # Setting proper values for alertCreationTime, alertUpdateTime,
        UpdateExpression=update_expression,
        ConditionExpression=condition_expression,
        ExpressionAttributeNames=expression_attribute_names,
        ExpressionAttributeValues=expression_attribute_values,
        ReturnValues='ALL_NEW'
    )
    alert_count = response['Attributes'][_ALERT_COUNT_ATTR_NAME]['N']
    alert_id = _generate_alert_id(group_info.rule_id, group_info.dedup, alert_count)
    return AlertInfo(alert_id=alert_id, alert_creation_time=group_info.processing_time, alert_update_time=group_info.processing_time)


def _update_get(group_info: MatchingGroupInfo) -> AlertInfo:
    """Updates the following attributes in DDB:
    1. Alert event account - it adds the new events to existing
    2. Alert Update Time - it sets it to given time
    """

    response = DDB_CLIENT.update_item(
        TableName=_DDB_TABLE_NAME,
        Key={_PARTITION_KEY_NAME: {
            'S': _generate_dedup_key(group_info.rule_id, group_info.dedup, group_info.is_rule_error)
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
                'N': group_info.processing_time.strftime('%s')
            },
            ':2': {
                'N': '{}'.format(group_info.num_matches)
            },
            ':3': {
                'SS': [group_info.log_type]
            },
        },
        ReturnValues='ALL_NEW'
    )
    alert_count = response['Attributes'][_ALERT_COUNT_ATTR_NAME]['N']
    alert_creation_time = response['Attributes'][_ALERT_CREATION_TIME_ATTR_NAME]['N']
    return AlertInfo(
        alert_id=_generate_alert_id(group_info.rule_id, group_info.dedup, alert_count),
        alert_creation_time=datetime.utcfromtimestamp(int(alert_creation_time)),
        alert_update_time=group_info.processing_time
    )
