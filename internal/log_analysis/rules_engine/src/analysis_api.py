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
        list_input: Dict[str, Any] = {
            'listRules':
                {
                    'enabled': True,
                    # select only the fields we need to minimize the size of the response
                    'fields': ['body', 'id', 'logTypes', 'outputIds', 'reports', 'severity', 'tags', 'versionId'],
                    'pageSize': 1000,
                }
        }
        page = 1
        total_pages = 1
        result = []

        while page <= total_pages:
            list_input['page'] = page
            response = self.client.invoke(FunctionName='panther-analysis-api', Payload=json.dumps(list_input).encode('utf-8'))
            body = json.loads(response['Payload'].read())

            if response.get('FunctionError'):
                raise RuntimeError('failed to list rules: ' + str(body))
            total_pages = body['paging']['totalPages']
            page += 1

            result.extend(body.get('rules', []))

        return result
