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

import collections
from collections.abc import Mapping
from datetime import datetime, timedelta
from timeit import default_timer
from typing import Any, Dict, List

from . import EngineResult
from .analysis_api import AnalysisAPIClient
from .data_model import DataModel
from .enriched_event import EnrichedEvent
from .logging import get_logger
from .rule import Rule

_RULES_CACHE_DURATION = timedelta(minutes=5)


class Engine:
    """The engine that runs Python rules."""

    def __init__(self, analysis_api: AnalysisAPIClient) -> None:
        self.logger = get_logger()
        self._last_update = datetime.utcfromtimestamp(0)
        self.log_type_to_data_models: Dict[str, DataModel] = collections.defaultdict()
        self.log_type_to_rules: Dict[str, List[Rule]] = collections.defaultdict(list)
        self._analysis_client = analysis_api
        self._populate_rules()
        self._populate_data_models()

    def analyze(self, log_type: str, event: Mapping) -> List[EngineResult]:
        """Analyze an event by running all the rules that apply to the log type.
        """
        if datetime.utcnow() - self._last_update > _RULES_CACHE_DURATION:
            self._populate_rules()
            self._populate_data_models()

        engine_results: List[EngineResult] = []

        # enrich the event to have access to field by standard field name
        #  via the `udm` method
        if log_type in self.log_type_to_data_models:
            event = EnrichedEvent(event, self.log_type_to_data_models[log_type])

        for rule in self.log_type_to_rules[log_type]:
            self.logger.debug('running rule [%s]', rule.rule_id)
            result = rule.run(event, batch_mode=True)
            if result.errored:
                short_error_message = repr(result.rule_exception)
                error_type = type(result.rule_exception).__name__
                rule_error = EngineResult(
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    rule_tags=rule.rule_tags,
                    rule_reports=rule.rule_reports,
                    log_type=log_type,
                    dedup=error_type,
                    dedup_period_mins=1440,  # one day
                    event=event,
                    title=short_error_message,
                    error_message=result.error_message()
                )
                engine_results.append(rule_error)
            elif result.matched:
                match = EngineResult(
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    rule_tags=rule.rule_tags,
                    rule_reports=rule.rule_reports,
                    log_type=log_type,
                    dedup=result.dedup_output,  # type: ignore
                    dedup_period_mins=rule.rule_dedup_period_mins,
                    event=event,
                    title=result.title_output,
                    alert_context=result.alert_context
                )
                engine_results.append(match)

        return engine_results

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

        for raw_rule in rules:
            try:
                rule = Rule(raw_rule)
            except Exception as err:  # pylint: disable=broad-except
                self.logger.error('Failed to import rule %s. Error: [%s]', raw_rule.get('id'), err)
                continue

            import_count = import_count + 1
            # update lookup table from log type to rule
            for log_type in raw_rule['logTypes']:
                self.log_type_to_rules[log_type].append(rule)

        end = default_timer()
        self.logger.info('Imported %d rules in %d seconds', import_count, end - start)
        self._last_update = datetime.utcnow()

    def _populate_data_models(self) -> None:
        """Import all data models."""
        import_count = 0
        start = default_timer()
        data_models = self._get_data_models()
        end = default_timer()
        self.logger.info('Retrieved %d data models in %s seconds', len(data_models), end - start)
        start = default_timer()

        # Clear old data models
        self.log_type_to_data_models.clear()

        for raw_data_model in data_models:
            try:
                data_model = DataModel(raw_data_model)
            except Exception as err:  # pylint: disable=broad-except
                self.logger.error('Failed to import data model %s. Error: [%s]', raw_data_model.get('id'), err)
                continue

            import_count = import_count + 1
            # update lookup table from log type to data model
            # there should only be one data model per log type
            for log_type in raw_data_model['logTypes']:
                self.log_type_to_data_models[log_type] = data_model

        end = default_timer()
        self.logger.info('Imported %d data models in %d seconds', import_count, end - start)
        self._last_update = datetime.utcnow()

    def _get_rules(self) -> List[Dict[str, Any]]:
        """Retrieves all enabled rules.

        Returns:
            An array of Dict['id': rule_id, 'body': rule_body, ...] that contain all fields of a rule.
        """
        return self._analysis_client.get_enabled_rules()

    def _get_data_models(self) -> List[Dict[str, Any]]:
        """Retrieves all enabled data models.

        Returns:
            An array of Dict['id': data_model_id, 'body': body, 'mappings': [...] ...] that contain all fields of a data model.
        """
        return self._analysis_client.get_enabled_data_models()
