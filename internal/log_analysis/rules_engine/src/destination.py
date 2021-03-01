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
from typing import Any, Dict

from .logging import get_logger


class Destination:  # pylint: disable=too-many-instance-attributes
    """Panther destination and imported methods."""

    def __init__(self, config: Dict[str, Any]):
        """Create destination lookups

        Args:
            config: Dictionary that should have the folllowing keys:
                alertTypes: whitelist of alert types to send to this destination
                createdBy: user ID of the user that created the alert output
                creationTime: time in epoch seconds when the alert output was created
                displayName: user-provided name, e.g. "alert-channel"
                lastModifiedBy: user ID of the user that last modified the alert output last
                lastModifiedTime: time in epoch seconds when the alert output was last modified
                outputId: unique identifier corresponding to an alert output (table sort key)
                outputType: output class, e.g. "slack", "sns"
                outputConfig: configuration for the output
                defaultForSeverity: defined alert severities that will be forwarded through this output
        """
        self.logger = get_logger()
        # outputs contains alert output configuration
        # while we expect all of the fields, only outputId and displayName are relevant
        if not isinstance(config.get('outputId'), str):
            raise AssertionError('Field "outputId" of type str is required field')
        self.destination_id = config['outputId']

        if not isinstance(config.get('displayName'), str):
            raise AssertionError('Field "displayName" of type str is required field')
        self.destination_display_name = config['displayName']

        # fields we expect but not required
        self.destination_type = config.get('outputType')
        self.destination_created_by = config.get('createdBy')
        self.destination_creation_time = config.get('creationTime')
        self.destination_last_modified_by = config.get('lastModifiedBy')
        self.destination_last_modified_time = config.get('lastModifiedTime')
        self.destination_alert_types = config.get('alertTypes')

        # defaultForSeverity should yield a list of strings
        self.destination_default_for_severity = config.get('defaultForSeverity')

        # extract the configuration
        self.destination_output_config: Dict[str, Dict] = config.get('outputConfig', {})
