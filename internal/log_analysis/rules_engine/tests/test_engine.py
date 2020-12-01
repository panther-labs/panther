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

from unittest import TestCase, mock

from ..src import EngineResult
from ..src.engine import Engine


class TestEngine(TestCase):

    def test_loading_data_models(self) -> None:
        analysis_api = mock.MagicMock()
        analysis_api.get_enabled_data_models.return_value = [
            {
                'id': 'data_model_id',
                'logTypes': ['log'],
                'body': 'def get_source_ip(event):\n\treturn "source_ip"',
                'versionId': 'version',
                'mappings': [{
                    'name': 'destination_ip',
                    'path': 'dst_ip'
                }, {
                    'name': 'source_ip',
                    'method': 'get_source_ip'
                }]
            }
        ]
        engine = Engine(analysis_api)
        self.assertEqual(len(engine.log_type_to_data_models.keys()), 1)
        self.assertEqual(len(engine.log_type_to_data_models['log'].paths), 1)
        self.assertEqual(len(engine.log_type_to_data_models['log'].methods), 1)

    def test_loading_rules(self) -> None:
        analysis_api = mock.MagicMock()
        analysis_api.get_enabled_rules.return_value = [
            {
                'id': 'rule_id',
                'logTypes': ['log'],
                'body': 'def rule(event):\n\treturn True',
                'versionId': 'version'
            }
        ]
        engine = Engine(analysis_api)
        self.assertEqual(len(engine.log_type_to_rules), 1)
        self.assertEqual(len(engine.log_type_to_rules['log']), 1)
        self.assertEqual(engine.log_type_to_rules['log'][0].rule_id, 'rule_id')

    def test_analyze_rule_with_udm(self) -> None:
        analysis_api = mock.MagicMock()
        analysis_api.get_enabled_rules.return_value = [
            {
                'id': 'rule_id',
                'logTypes': ['log'],
                'body': 'def rule(event):\n\tif event.udm("destination"):\n\t\treturn True\n\treturn False',
                'versionId': 'version'
            }
        ]
        analysis_api.get_enabled_data_models.return_value = [
            {
                'id': 'data_model_id',
                'logTypes': ['log'],
                'versionId': 'version',
                'mappings': [{
                    'name': 'destination',
                    'path': 'is_dst'
                }]
            }
        ]
        log_entry = {'is_dst': True}
        engine = Engine(analysis_api)
        result = engine.analyze('log', log_entry)
        expected_event_matches = [
            EngineResult(
                rule_id='rule_id',
                rule_version='version',
                log_type='log',
                dedup='defaultDedupString:rule_id',
                dedup_period_mins=60,
                event=log_entry
            )
        ]
        self.assertEqual(result, expected_event_matches)

    def test_analyse_many_rules(self) -> None:
        analysis_api = mock.MagicMock()
        analysis_api.get_enabled_rules.return_value = [
            {
                'id': 'rule_id_1',
                'logTypes': ['log'],
                'body': 'def rule(event):\n\treturn True',
                'versionId': 'version',
                'dedupPeriodMinutes': 120,
                'tags': ['test-tag'],
                'reports': {
                    'key': ['value']
                }
            },  # This rule should match the event
            {
                'id': 'rule_id_2',
                'logTypes': ['log'],
                'body': 'def rule(event):\n\treturn False',
                'versionId': 'version'
            }  # This rule shouldn't match the event
        ]
        engine = Engine(analysis_api)
        result = engine.analyze('log', {})

        expected_event_matches = [
            EngineResult(
                rule_id='rule_id_1',
                rule_version='version',
                log_type='log',
                dedup='defaultDedupString:rule_id_1',
                dedup_period_mins=120,
                rule_tags=['test-tag'],
                rule_reports={'key': ['value']},
                event={}
            )
        ]
        self.assertEqual(result, expected_event_matches)

    def test_analyse_many_rules_one_throws_exception(self) -> None:
        analysis_api = mock.MagicMock()
        analysis_api.get_enabled_rules.return_value = [
            {
                'id': 'rule_id_1',
                'logTypes': ['log'],
                'body': 'def rule(event):\n\treturn True',
                'versionId': 'version'
            }, {
                'id': 'rule_id_2',
                'logTypes': ['log'],
                'body': 'def rule(event):\n\traise Exception("Found an issue")',
                'versionId': 'version'
            }, {
                'id': 'rule_id_3',
                'logTypes': ['log'],
                'body': 'def rule(event):\n\treturn True',
                'versionId': 'version'
            }
        ]
        engine = Engine(analysis_api)
        result = engine.analyze('log', {})

        expected_event_matches = [
            EngineResult(
                rule_id='rule_id_1',
                rule_version='version',
                log_type='log',
                dedup='defaultDedupString:rule_id_1',
                event={},
                dedup_period_mins=60
            ),
            EngineResult(
                rule_id='rule_id_2',
                rule_version='version',
                log_type='log',
                dedup='Exception',
                event={},
                dedup_period_mins=1440,
                error_message='Found an issue: rule_id_2.py, line 2, in rule    raise Exception("Found an issue")',
                title="Exception('Found an issue')"
            ),
            EngineResult(
                rule_id='rule_id_3',
                rule_version='version',
                log_type='log',
                dedup='defaultDedupString:rule_id_3',
                event={},
                dedup_period_mins=60
            )
        ]

        self.assertEqual(result, expected_event_matches)
