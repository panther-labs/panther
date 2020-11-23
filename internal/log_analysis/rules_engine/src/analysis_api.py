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

import json
from typing import Any, Dict, List

import boto3


class AnalysisAPIClient:
    """Client for interacting with Analysis API."""

    def __init__(self) -> None:
        self.client = boto3.client('lambda')

    def get_enabled_rules(self) -> List[Dict[str, Any]]:
        """Gets information for all enabled rules."""
        # There should only be one page, but loop over them just in case
        list_input: Dict[str, Any] = {'listRules': {'enabled': True, 'page': 1, 'pageSize': 250}}

        result = []
        while True:
            response = self.client.invoke(FunctionName='panther-analysis-api', Payload=json.dumps(list_input).encode('utf-8'))
            gateway_response = json.loads(response['Payload'].read())

            if response.get('FunctionError') or gateway_response['statusCode'] != 200:
                raise RuntimeError('failed to list rules: ' + str(gateway_response))

            body = json.loads(gateway_response['body'])
            result.extend(body.get('rules', []))

            if body['paging']['thisPage'] == body['paging']['totalPages']:
                break

            list_input['listRules']['page'] += 1

        return result

    def get_enabled_data_models(self) -> List[Dict[str, Any]]:
        """Gets information for all enabled data models."""
        # There should only be one page, but loop over them just in case
        list_input: Dict[str, Any] = {'listDataModels': {'enabled': True, 'page': 1, 'pageSize': 250}}

        result = []
        while True:
            response = self.client.invoke(FunctionName='panther-analysis-api', Payload=json.dumps(list_input).encode('utf-8'))
            gateway_response = json.loads(response['Payload'].read())

            if response.get('FunctionError') or gateway_response['statusCode'] != 200:
                raise RuntimeError('failed to list models: ' + str(gateway_response))

            body = json.loads(gateway_response['body'])
            result.extend(body.get('models', []))

            if body['paging']['thisPage'] == body['paging']['totalPages']:
                break

            list_input['listDataModels']['page'] += 1

        return result
