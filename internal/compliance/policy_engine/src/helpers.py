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
from typing import Any, Dict
import boto3

TABLE = boto3.resource('dynamodb').Table('panther-resources')  # pylint: disable=no-member


class BadLookup(Exception):
    """Error returned when a resource lookup fails."""


class PantherBadInput(Exception):
    """Error returned when a Panther helper function is provided bad input."""


def get_s3_arn_by_name(name: str) -> str:
    """This function is used to construct an s3 bucket ARN from its name."""
    if name == '':
        raise PantherBadInput('s3 name cannot be blank')
    return 'arn:aws:s3:::' + name


def s3_lookup_by_name(name: str) -> Dict[str, Any]:
    """This function is used to get an S3 bucket resource from just its name."""
    return resource_lookup(get_s3_arn_by_name(name))


def dynamo_lookup(key: str) -> Dict[str, Any]:
    """Make a dynamodb GetItem API call."""
    return TABLE.get_item(Key={'id': key})


def resource_lookup(resource_id: str) -> Dict[str, Any]:
    """This function is used to get a resource from the resources-api based on its resourceID."""
    # Validate input so we can provide meaningful error messages to users
    if resource_id == '':
        raise PantherBadInput('resourceId cannot be blank')

    # Get the item from dynamo
    response = dynamo_lookup(resource_id)

    # Check if dynamo failed
    status_code = response['ResponseMetadata']['HTTPStatusCode']
    if status_code != 200:
        raise BadLookup('dynamodb - ' + str(status_code) + ' HTTPStatusCode')

    # Check if the item was found
    if 'Item' not in response:
        raise BadLookup(resource_id + ' not found')

    # Return just the attributes of the item
    return response['Item']['attributes']
