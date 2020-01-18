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

from typing import Any, Dict

from . import Remediation
from .exceptions import InvalidInput


def lambda_handler(event: Dict[str, Any], unused_context: Any) -> Dict[Any, Any]:
    """Main lambda handler use as the entry point for the application

    Args:
        event: Event object that contains the invocation payload. There are two type of events
        currently supported:
        1. 'listRemediations' event: The Lambda will return the available remediations
        and the parameters used by the remediation.
        2. 'remediate' event: The Lambda invokes the appropriate remediation.

        unused_context: AWS LambdaContext object

    Examples:
        {
          "action": "remediate",
          "payload": {
            "remediationId": "AWS.S3.EnableBucketLogging",
            "resource":
              {
                "Name": "my-bucket",
                "AccountId": "123456789012",
                "Region": "us-west-2",
              }
            ,
            "parameters": {
              "TargetBucket": "log-bucket",
              "TargetPrefix": "s3-access"
            }
          }
        }



        {
          "action": "listRemediations"
        }
    """
    if 'action' not in event:
        raise InvalidInput('Input missing "action" parameter')
    if event['action'] == 'listRemediations':
        return Remediation.get_all_remediations()
    if event['action'] == 'remediate':
        Remediation.get(event['payload']['remediationId'])().fix(event['payload'])
        return {}
    raise InvalidInput('Unknown action "{}"'.format(event['action']))
