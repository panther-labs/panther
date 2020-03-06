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
from typing import Any, Dict, List

from . import EventMatch
from .analysis_api import AnalysisAPIClient
from .logging import get_logger
from .rule import Rule, COMMON_MODULE_RULE_ID

_RULES_CACHE_DURATION = timedelta(minutes=5)


class Engine:
    """The engine that runs Python rules."""
    logger = get_logger()

    def __init__(self, analysis_api: AnalysisAPIClient) -> None:
        self._last_update = datetime.utcfromtimestamp(0)
        self.log_type_to_rules: Dict[str, List[Rule]] = collections.defaultdict(list)
        self._analysis_client = analysis_api
        self._populate_rules()

    def analyze(self, log_type: str, event: Dict[str, Any]) -> List[EventMatch]:
        """Analyze an event by running all the rules that apply to the log type.
        """
        if datetime.utcnow() - self._last_update > _RULES_CACHE_DURATION:
            self._populate_rules()

        matched: List[EventMatch] = []

        for rule in self.log_type_to_rules[log_type]:
            result = rule.run(event)
            if result.exception:
                self.logger.error('failed to run rule %s %s %s', rule.rule_id, type(result).__name__, repr(result.exception))
                continue
            if result.matched:
                match = EventMatch(
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    log_type=log_type,
                    dedup=result.dedup_string,  # type: ignore
                    event=event,
                    severity=rule.rule_severity
                )
                matched.append(match)

        return matched

    def _populate_rules(self) -> None:
        """Import all rules."""
        import_count = 0
        start = default_timer()
        rules = self._get_rules()
        end = default_timer()
        self.logger.info('Retrieved %d rules in %s seconds', len(rules), end - start)
        start = default_timer()

        # Clear old rules
        self.log_type_to_rules.clear()

        # Importing common module. This module MAY hold code common to some rules and if it exists, it must be
        # imported before other rules. However, the presence of this rule is optional.
        for raw_rule in rules:
            if raw_rule.get('id') == COMMON_MODULE_RULE_ID:
                try:
                    Rule(
                        rule_id=raw_rule.get('id'),
                        rule_body=raw_rule.get('body'),
                        rule_severity=raw_rule.get('severity'),
                        rule_version=raw_rule.get('versionId')
                    )
                except Exception as err:  # pylint: disable=broad-except
                    self.logger.error('Failed to import rule %s', err)
                rules.remove(raw_rule)
                break

        for raw_rule in rules:
            try:
                rule = Rule(
                    rule_id=raw_rule.get('id'),
                    rule_body=raw_rule.get('body'),
                    rule_severity=raw_rule.get('severity'),
                    rule_version=raw_rule.get('versionId')
                )
            except Exception as err:  # pylint: disable=broad-except
                self.logger.error('Failed to import rule %s', err)
                continue

            import_count = import_count + 1
            # update lookup table from log type to rule
            for log_type in raw_rule['resourceTypes']:
                self.log_type_to_rules[log_type].append(rule)

        end = default_timer()
        self.logger.info('Imported %d rules in %d seconds', import_count, end - start)
        self._last_update = datetime.utcnow()

    def _get_rules(self) -> List[Dict[str, str]]:
        """Retrieves all enabled rules.

        Returns:
            An array of Dict['id': rule_id, 'body': rule_body, ...] that contain all fields of a rule.
        """
        return self._analysis_client.get_enabled_rules()
