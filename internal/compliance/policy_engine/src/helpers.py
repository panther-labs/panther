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
"""Utility functions provided to policies during execution."""
import boto3
import json


class BadLookup(Exception):
    pass


def resource_lookup(resource_id: str):
    lc = boto3.client('lambda')

    # Setup the request
    request_payload = {
        'resource': '/resource',
        'HTTPMethod': 'GET',
        'queryStringParameters': {
            'resourceId': resource_id,
        },
    }

    # Invoke the resources-api
    response = lc.invoke(
        FunctionName='panther-resources-api', InvocationType='RequestResponse', LogType='None', Payload=json.dumps(request_payload)
    )

    # These responses are small, so we just load the whole thing into memory
    response_payload = json.loads(response['Payload'].read())

    # The response HTTPStatusCode is always 200, so we check the payload statusCode for success
    if response_payload['statusCode'] != 200:
        raise BadLookup('status code: ' + str(response['statusCode']))

    body = json.loads(response_payload['body'])
    return body['attributes']
