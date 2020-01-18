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

import json
import os
from typing import Dict, List

import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.session import Session


class AnalysisAPIClient:
    """Client for interacting with Analysis API."""

    def __init__(self) -> None:
        current_session = Session()
        region = current_session.get_config_variable('region')
        creds = current_session.get_credentials()
        self.signer = SigV4Auth(creds, 'execute-api', region)

        analysis_api_fqdn = os.environ.get('ANALYSIS_API_FQDN')
        analysis_api_path = os.environ.get('ANALYSIS_API_PATH')
        self.url = 'https://' + analysis_api_fqdn + '/' + analysis_api_path

    def get_enabled_rules(self) -> List[Dict[str, str]]:
        """Gets information for all enabled rules."""
        request = AWSRequest(method='GET', url=self.url + '/enabled', params={'type': 'RULE'})
        self.signer.add_auth(request)
        prepped_request = request.prepare()

        response = requests.get(prepped_request.url, headers=prepped_request.headers)
        response.raise_for_status()
        parsed_response = json.loads(response.text)
        return parsed_response['policies']
