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


class OutputsAPIClient:
    """Client for interacting with Outputs API."""

    def __init__(self) -> None:
        self.client = boto3.client('lambda')

    def get_outputs(self) -> List[Dict[str, Any]]:
        """Gets information for all configured destinations."""
        get_input: Dict[str, Any] = {'getOutputs': {}}

        response = self.client.invoke(FunctionName='panther-outputs-api', Payload=json.dumps(get_input).encode('utf-8'))
        lambda_response = json.loads(response['Payload'].read())

        if response.get('FunctionError') or response.get('StatusCode') != 200:
            raise RuntimeError('failed to get outputs: ' + str(response))

        return lambda_response
