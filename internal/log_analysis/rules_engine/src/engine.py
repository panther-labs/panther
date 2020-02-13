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

import collections
from datetime import datetime, timedelta
from timeit import default_timer
from typing import Any, List, Dict

from . import EventMatch
from .analysis_api import AnalysisAPIClient
from .logging import get_logger
from .rule import Rule, COMMON_MODULE_RULE_ID

_RULES_CACHE_DURATION = timedelta(minutes=5)
_ANALYSIS_CLIENT = AnalysisAPIClient()


class Engine:
    """The engine that runs Python rules."""
    logger = get_logger()

    def __init__(self) -> None:
        self._last_update = datetime.utcfromtimestamp(0)
        self._log_type_to_rules: Dict[str, List[Rule]] = collections.defaultdict(list)
        self._analysis_client = AnalysisAPIClient()
        self._populate_rules()

    def analyze(self,log_type: str, event: Dict[str, Any]) -> List[EventMatch]:
        """Analyze an event by running all the rules that apply to the log type.
        """
        if datetime.utcnow() - self._last_update > _RULES_CACHE_DURATION:
            self._populate_rules()

        matched: List[EventMatch] = []

        for rule in self._log_type_to_rules[log_type]:
            result = rule.run(event)
            if result.exception:
                self.logger.error(
                    'failed to run rule {} {} {}'.format(rule.rule_id, type(result).__name__, result.exception))
                continue
            if result.matched:
                matched.append(EventMatch(
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    log_type=log_type,
                    dedup=result.dedup,
                    event=event))

        return matched

    def _populate_rules(self) -> None:
        """Import all rules."""
        import_count = 0
        start = default_timer()
        rules = self._get_rules()
        end = default_timer()
        self.logger.info('Retrieved {} rules in {} seconds'.format(len(rules), end - start))
        start = default_timer()

        # Clear old rules
        self._log_type_to_rules.clear()

        # Importing common module. This module MAY hold code common to some rules and if it exists, it must be
        # imported before other rules. However, the presence of this rule is optional.
        for raw_rule in rules:
            if raw_rule['id'] == COMMON_MODULE_RULE_ID:
                Rule(
                    rule_id=raw_rule['id'],
                    rule_body=raw_rule['body'],
                    rule_version=raw_rule['versionId'])
                break

        for raw_rule in rules:
            if raw_rule['id'] == COMMON_MODULE_RULE_ID:
                # skip, should be already loaded above if present
                continue
            # update lookup table from log type to rule
            import_count = import_count + 1
            rule = Rule(
                rule_id=raw_rule['id'],
                rule_body=raw_rule['body'],
                rule_version=raw_rule['versionId'])
            for log_type in raw_rule['resourceTypes']:
                self._log_type_to_rules[log_type].append(rule)

        end = default_timer()
        self.logger.info('Imported {} rules in {} seconds'.format(import_count, end - start))
        self._last_update = datetime.utcnow()

    def _get_rules(self) -> List[Dict[str, str]]:
        """Retrieves all enabled rules.

        Returns:
            An array of Dict['id': rule_id, 'body': rule_body, ...] that contain all fields of a rule.
        """
        return self._analysis_client.get_enabled_rules()
