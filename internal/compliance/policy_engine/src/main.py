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

import logging
import os
import shutil
import tempfile
from typing import Any, Dict

from . import engine

_LOGGER = logging.getLogger()
_LOGGER.setLevel('INFO')
_TMP = os.path.join(tempfile.gettempdir(), 'analysis')


def lambda_handler(lambda_event: Dict[str, Any], unused_context: Any) -> Dict[str, Any]:
    """Entry point for the policy engine.

    Args:
        lambda_event: {
            ###### Compliance Evaluation ######
            'policies': [
                {
                    'body': 'def policy(resource): ...',
                    'id': 'BucketEncryptionEnabled',
                    'resourceTypes': ['AWS.S3.Bucket']  # can be empty for all resource types
                }
            ],
            'resources': [
                {
                    'attributes': { ... resource attributes ... },
                    'id': 'arn:aws:s3:::my-bucket',
                    'type': 'AWS.S3.Bucket',
                    'mocks': { ... mock name : mock value ... },
                }
            ]
        }

    Returns:
        {
            ###### Compliance Evaluation ######
            'resources': [
                {
                    'id': 'arn:aws:s3:::my-bucket',
                    'errored': [  # policies which raised a runtime error
                        {
                            'id': 'policy-id-1',
                            'message': 'ZeroDivisionError'
                        }
                    ],
                    'failed': ['policy-id-2', 'policy-id-3'],  # policies which returned False
                    'passed': ['policy-id-3', 'policy-id-4'],  # policies which returned True
                }
            ]
        }
    """
    if lambda_event.get('resources') is not None and lambda_event.get('policies') is not None:
        _LOGGER.info('Scanning %d resources with %d compliance policies', len(lambda_event['resources']), len(lambda_event['policies']))
    else:
        raise ValueError('resources and policies much be specified')

    # Erase /tmp at the beginning of every invocation.
    if not os.path.exists(_TMP):
        os.makedirs(_TMP)

    for name in os.listdir(_TMP):
        path = os.path.join(_TMP, name)
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    # Save all policies to /tmp for easy import.
    for policy in lambda_event['policies']:
        # Sanitize filename: replace all special characters with underscores.
        safe_id = ''.join(x if _allowed_char(x) else '_' for x in policy['id'])
        path = os.path.join(_TMP, safe_id + '.py')
        if os.path.exists(path):
            raise NameError('policy with sanitized id {} already exists'.format(safe_id))
        with open(path, 'w') as py_file:
            py_file.write(policy['body'])
        policy['body'] = path  # Replace policy body with file path.

    return engine.analyze(lambda_event)


def _allowed_char(char: str) -> bool:
    """Return true if the character is part of a valid policy ID."""
    return char.isalnum() or char in {' ', '-', '.'}
