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
from typing import Any, Dict


@dataclass
class AnalysisMatch:
    """The result of an event analysis"""
    rule_id: str
    rule_version: str
    analysis_time: datetime
    log_type: str
    dedup: str
    event: Dict[str, Any]


@dataclass
class AlertInfo:
    """Information about an alert"""
    alert_id: str
    alert_creation_time: datetime
    alert_update_time: datetime


@dataclass
class OutputNotification:
    """Output notification"""
    s3Bucket: str
    s3ObjectKey: str
    events: int
    bytes: int
    id: str
    type: str = 'RuleOutput'

