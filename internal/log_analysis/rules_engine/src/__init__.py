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
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

# pylint: disable=too-many-instance-attributes
@dataclass
class EventMatch:
    """Represents an event that matched a rule"""
    rule_id: str
    rule_version: str
    log_type: str
    dedup: str
    dedup_period_mins: int
    severity: str
    event: Dict[str, Any]
    title: Optional[str] = None


@dataclass
class AlertInfo:
    """Information about an alert"""
    alert_id: str
    alert_creation_time: datetime
    alert_update_time: datetime


@dataclass(frozen=True, eq=True)
class OutputGroupingKey:
    """Class representing the keys used for grouping output events to files"""
    rule_id: str
    log_type: str
    dedup: str

    def table_name(self) -> str:
        """ Output the name of the Glue table name for this log type"""
        return self.log_type.lower().replace('.', '_')


# pylint: disable=invalid-name
@dataclass
class OutputNotification:
    """The notification that will be send to the SNS topic when we create a new object in S3.

    This class will be serialized to JSON, thus following camelCase rather than snake_case
    """
    s3Bucket: str
    s3ObjectKey: str
    events: int
    bytes: int
    id: str
    type: str = 'RuleMatches'
