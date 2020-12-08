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

import collections
import json
from gzip import GzipFile
from io import TextIOWrapper
from timeit import default_timer
from typing import Any, Dict, List, Optional, Tuple

from .analysis_api import AnalysisAPIClient
from .aws_clients import S3_CLIENT
from .engine import Engine
from .logging import get_logger
from .output import MatchedEventsBuffer
from .rule import Rule

_LOGGER = get_logger()

_RULES_ENGINE = Engine(AnalysisAPIClient())


#  pylint: disable=unsubscriptable-object
def lambda_handler(event: Dict[str, Any], unused_context: Any) -> Optional[Dict[str, Any]]:
    """Entry point for the Lambda"""
    if 'rules' in event:
        # Handle the direct evaluation of a single rule against some number of events
        return direct_analysis(event)
    log_analysis(event)
    return None


def direct_analysis(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates a single rule against a set of events, and returns the results. Currently used for testing policies directly.
    """
    # Since this is used for testing single rules, it should only ever have one rule
    if len(request['rules']) != 1:
        raise RuntimeError('exactly one rule expected, found {}'.format(len(request['rules'])))

    raw_rule = request['rules'][0]
    # The rule during direct invocation doesn't have a version
    raw_rule['versionId'] = 'default'
    test_rule = Rule(raw_rule)

    format_exception = lambda exc: '{}: {}'.format(type(exc).__name__, exc) if exc else exc
    results = []
    for event in request['events']:
        rule_result = test_rule.run(event['data'], batch_mode=False)
        results.append(
            {
                'id': event['id'],
                'ruleId': raw_rule['id'],
                'genericError': format_exception(rule_result.setup_exception),
                'errored': rule_result.errored,
                'ruleOutput': rule_result.matched,
                'ruleError': format_exception(rule_result.rule_exception),
                'titleOutput': rule_result.title_output,
                'titleError': format_exception(rule_result.title_exception),
                'descriptionOutput': rule_result.description_output,
                'descriptionError': format_exception(rule_result.description_exception),
                'referenceOutput': rule_result.reference_output,
                'referenceError': format_exception(rule_result.reference_exception),
                'severityOutput': rule_result.severity_output,
                'severityError': format_exception(rule_result.severity_exception),
                'runbookOutput': rule_result.runbook_output,
                'runbookError': format_exception(rule_result.runbook_exception),
                'destinationsOutput': rule_result.destinations_output,
                'destinationsError': format_exception(rule_result.destinations_exception),
                'dedupOutput': rule_result.dedup_output,
                'dedupError': format_exception(rule_result.dedup_exception),
                'alertContextOutput': rule_result.alert_context,
                'alertContextError': format_exception(rule_result.alert_context_exception),
            }
        )

    response: Dict[str, Any] = {'results': results}
    return response


# pylint: disable=too-many-locals
def log_analysis(event: Dict[str, Any]) -> None:
    """Runs log analysis"""

    start = default_timer()
    log_type_to_data = _load_event(event)
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
                    # The analysis results can be either a. Rule matches b. Rule errors
                    if not analysis_result.error_message:
                        matches += 1
                    output_buffer.add_event(analysis_result)
    output_buffer.flush()
    end = default_timer()
    _LOGGER.info("Matched %d events in %s seconds", matches, end - start)


# Reads lambda events wrapping s3 notifications, returns dictionary containing mapping from log type to list of TextIOWrapper's
def _load_event(event: Dict[str, Any]) -> Dict[str, List[TextIOWrapper]]:
    log_type_to_data: Dict[str, List[TextIOWrapper]] = collections.defaultdict(list)
    for record in event['Records']:
        record_body = json.loads(record['body'])
        log_type = record['messageAttributes']['id']['stringValue']  # id attr holds log type
        for bucket, object_key in _load_s3_notifications(record_body['Records']):
            _LOGGER.debug("loading object from S3, bucket [%s], key [%s]", bucket, object_key)
            log_type_to_data[log_type].append(_load_contents(bucket, object_key))
    return log_type_to_data


# Reads S3 notifications and returns tuples of (bucket, key)
def _load_s3_notifications(records: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    events: List[Tuple[str, str]] = []
    for s3event in records:
        # https://docs.aws.amazon.com/AmazonS3/latest/dev/notification-content-structure.html
        bucket = s3event['s3']['bucket']['name']
        object_key = s3event['s3']['object']['key']
        events.append((bucket, object_key))
    return events


# Returns a TextIOWrapper for the S3 data. This makes sure that we don't have to keep all contents of S3 object in memory
def _load_contents(bucket: str, key: str) -> TextIOWrapper:
    response = S3_CLIENT.get_object(Bucket=bucket, Key=key)
    gzipped = GzipFile(None, 'rb', fileobj=response['Body'])
    return TextIOWrapper(gzipped)  # type: ignore
