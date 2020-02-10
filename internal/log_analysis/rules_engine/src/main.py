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
from timeit import default_timer
import json
from gzip import GzipFile
from io import TextIOWrapper
from typing import Any, Dict, List, Union

import boto3

from .engine import Engine
from .logging import get_logger
from .rule import Rule
from .sqs import send_to_sqs

s3_client = boto3.client('s3')
rules_engine = Engine()


def lambda_handler(event: Dict[str, Any], unused_context) -> Union[None, Dict[str, Any]]:
    start = default_timer()
    logger = get_logger()

    # Handle the direct evaluation of a single rule against some number of events
    if 'rules' in event:
        return direct_analysis(event)

    # Dictionary containing mapping from log type to list of TextIOWrapper's
    log_type_to_data: Dict[str, TextIOWrapper] = collections.defaultdict(list)

    for record in event['Records']:
        record_body = json.loads(record['body'])
        bucket = record_body['s3Bucket']
        object_key = record_body['s3ObjectKey']
        logger.info("loading object from S3, bucket [{}], key [{}]".format(bucket, object_key))
        log_type_to_data[record_body['id']].append(load_contents(bucket, object_key))

    # List containing tuple of (rule_id, event) for matched events
    matched: List = []

    for log_type, data_streams in log_type_to_data.items():
        for data_stream in data_streams:
            for data in data_stream:
                try: # Bad json data can cause exceptions to be thrown. Best effort: log and continue
                    for matched_rule in rules_engine.analyze(log_type, json.loads(data)):
                        matched.append((matched_rule, data))
                except Exception as err:  # pylint: disable=broad-except
                    logger.error("Error during matching: {}".format(err)) # do not log data!

    if len(matched) > 0:
        send_to_sqs(matched)

    end = default_timer()
    logger.info("Matched {} events in {} seconds".format(len(matched), end - start))

# Evaluates a single rule against a set of events, and returns the results
# Currently used for testing policies directly
def direct_analysis(event: Dict[str, Any]) -> Dict[str, Any]:
        # Since this is used for testing single rules, it should only ever have one rule
        if len(event['rules']) != 1:
            raise RuntimeError('exactly one rule expected, found {}'.format(len(event['rules'])))

        raw_rule = event['rules'][0]
        test_rule = Rule(raw_rule['id'], raw_rule['body'])
        results = {'events' : []}
        for single_event in event['events']:
            result = {
                'id': single_event['id'],
                'matched' : [],
                'notMatched': [],
                'errored': [],
            }
            matched = test_rule.run(single_event['data'])
            if matched is True:
                result['matched'] = [raw_rule['id']]
            elif matched is False:
                result['notMatched'] = [raw_rule['id']]
            else:
                result['errored'] = [{
                    'id' : raw_rule['id'],
                    'message': str(matched),
                    }]

            results['events'].append(result)

        return results

# Returns a TextIOWrapper for the S3 data. This makes sure that we don't have to keep all
# contents of S3 object in memory
def load_contents(bucket: str, key: str) -> TextIOWrapper:
    response = s3_client.get_object(Bucket=bucket, Key=key)
    gzipped = GzipFile(None, 'rb', fileobj=response['Body'])
    return TextIOWrapper(gzipped)
