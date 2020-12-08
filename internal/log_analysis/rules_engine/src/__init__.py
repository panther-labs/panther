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

from dataclasses import dataclass, field
from datetime import datetime
from collections.abc import Mapping
from typing import Any, Dict, Optional, List


# pylint: disable=too-many-instance-attributes,unsubscriptable-object
@dataclass
class EngineResult:
    """Represents an event that matched a rule"""
    rule_id: str
    rule_version: str
    log_type: str
    dedup: str
    dedup_period_mins: int
    event: Mapping
    # error_message will be populated only if the rule threw an exception
    error_message: Optional[str] = None
    rule_tags: List[str] = field(default_factory=list)
    rule_reports: Dict[str, List[str]] = field(default_factory=dict)
    alert_context: Optional[str] = None
    # generated fields
    title: Optional[str] = None
    description: Optional[str] = None
    reference: Optional[str] = None
    severity: Optional[str] = None
    runbook: Optional[str] = None
    destinations: Optional[List[str]] = None


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
    is_rule_error: bool = False

    def table_name(self) -> str:
        """ Output the name of the Glue table name for this log type"""
        return self.log_type.lower().replace('.', '_')
