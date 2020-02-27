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
import json
from gzip import GzipFile
from io import TextIOWrapper
from timeit import default_timer
from typing import Any, Dict, List, Optional

import boto3

from .engine import Engine
from .analysis_api import AnalysisAPIClient
from .logging import get_logger
from .output import MatchedEventsBuffer
from .rule import Rule

_S3_CLIENT = boto3.client('s3')
_LOGGER = get_logger()
_RULES_ENGINE = Engine(AnalysisAPIClient())


def lambda_handler(event: Dict[str, Any], unused_context: Any) -> Optional[Dict[str, Any]]:
    """Entry point for the Lambda"""
    if 'rules' in event:
        # Handle the direct evaluation of a single rule against some number of events
        return direct_analysis(event)
    log_analysis(event)
    return None


def direct_analysis(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates a single rule against a set of events, and returns the results. Currently used for testing policies directly.
    """
    # Since this is used for testing single rules, it should only ever have one rule
    if len(event['rules']) != 1:
        raise RuntimeError('exactly one rule expected, found {}'.format(len(event['rules'])))

    raw_rule = event['rules'][0]
    # It is possible that during direct analysis the rule doesn't include a severity
    # in this case, we set it to a default value
    severity = raw_rule.get('severity')
    if not severity:
        severity = 'INFO'
    test_rule = Rule(rule_id=raw_rule['id'], rule_body=raw_rule['body'], rule_severity=severity)
    results: Dict[str, Any] = {'events': []}
    for single_event in event['events']:
        result = {
            'id': single_event['id'],
            'matched': [],
            'notMatched': [],
            'errored': [],
        }
        rule_result = test_rule.run(single_event['data'])
        if rule_result.exception:
            result['errored'] = [{
                'id': raw_rule['id'],
                'message': str(rule_result.exception),
            }]
        elif rule_result.matched:
            result['matched'] = [raw_rule['id']]
        else:
            result['notMatched'] = [raw_rule['id']]

        results['events'].append(result)
    return results


# pylint: disable=too-many-locals
def log_analysis(event: Dict[str, Any]) -> None:
    """Runs log analysis"""

    start = default_timer()

    # Dictionary containing mapping from log type to list of TextIOWrapper's
    log_type_to_data: Dict[str, List[TextIOWrapper]] = collections.defaultdict(list)
    for record in event['Records']:
        record_body = json.loads(record['body'])
        bucket = record_body['s3Bucket']
        object_key = record_body['s3ObjectKey']
        _LOGGER.debug("loading object from S3, bucket [%s], key [%s]", bucket, object_key)
        log_type_to_data[record_body['id']].append(_load_contents(bucket, object_key))

    matches = 0
    output_buffer = MatchedEventsBuffer()
    for log_type, data_streams in log_type_to_data.items():
        for data_stream in data_streams:
            for data in data_stream:
                try:  # Bad json data can cause exceptions to be thrown. Best effort: log and continue
                    json_data = json.loads(data)
                except Exception as err:  # pylint: disable=broad-except
                    _LOGGER.error("data is not valid JSON %s", err)  # do not log data!
                    continue

                for analysis_result in _RULES_ENGINE.analyze(log_type, json_data):
                    matches += 1
                    output_buffer.add_event(analysis_result)
    output_buffer.flush()
    end = default_timer()
    _LOGGER.info("Matched %d events in %s seconds", matches, end - start)


# Returns a TextIOWrapper for the S3 data. This makes sure that we don't have to keep all
# contents of S3 object in memory
def _load_contents(bucket: str, key: str) -> TextIOWrapper:
    response = _S3_CLIENT.get_object(Bucket=bucket, Key=key)
    gzipped = GzipFile(None, 'rb', fileobj=response['Body'])
    return TextIOWrapper(gzipped)  # type: ignore
