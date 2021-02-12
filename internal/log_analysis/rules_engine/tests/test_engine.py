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

    def test_analyze_single_rule_with_udm(self) -> None:
        analysis_api = mock.MagicMock()
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
        rule_body = 'def rule(event):\n\treturn event.udm("destination")'
        event = {'id': 'event_id', 'data': {'is_dst': True, 'p_log_type': 'log'}}
        rule = {'id': 'rule_id', 'body': rule_body}
        expected_response = {
            'id': 'event_id',
            'ruleId': 'rule_id',
            'genericError': None,
            'errored': False,
            'ruleOutput': True,
            'ruleError': None,
            'titleOutput': None,
            'titleError': None,
            'descriptionOutput': None,
            'descriptionError': None,
            'referenceOutput': None,
            'referenceError': None,
            'severityOutput': None,
            'severityError': None,
            'runbookOutput': None,
            'runbookError': None,
            'destinationsOutput': None,
            'destinationsError': None,
            'dedupOutput': 'defaultDedupString:rule_id',
            'dedupError': None,
            'alertContextOutput': None,
            'alertContextError': None
        }
        engine = Engine(analysis_api)
        result = engine.analyze_single_rule(rule, event)
        self.assertEqual(expected_response, result)

    def test_analyze_single_rule_with_udm_missing_log_type(self) -> None:
        analysis_api = mock.MagicMock()
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
        rule_body = 'def rule(event):\n\treturn event.udm("destination")'
        event = {'id': 'event_id', 'data': {'is_dst': True}}
        rule = {'id': 'rule_id', 'body': rule_body}
        expected_response = {
            'id': 'event_id',
            'ruleId': 'rule_id',
            'genericError': None,
            'errored': True,
            'ruleOutput': None,
            'ruleError': 'Exception: a data model hasn\'t been specified',
            'titleOutput': None,
            'titleError': None,
            'descriptionOutput': None,
            'descriptionError': None,
            'referenceOutput': None,
            'referenceError': None,
            'severityOutput': None,
            'severityError': None,
            'runbookOutput': None,
            'runbookError': None,
            'destinationsOutput': None,
            'destinationsError': None,
            'dedupOutput': 'defaultDedupString:rule_id',
            'dedupError': None,
            'alertContextOutput': None,
            'alertContextError': None
        }
        engine = Engine(analysis_api)
        result = engine.analyze_single_rule(rule, event)
        self.assertEqual(expected_response, result)

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
                dedup_period_mins=60,
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

    def test_modify_event(self) -> None:
        analysis_api = mock.MagicMock()
        analysis_api.get_enabled_rules.return_value = [
            {
                'id': 'rule_id_1',
                'logTypes': ['log'],
                'body': 'def rule(event):\n\tevent["key"]["nested_key"] = "not_value"\n\treturn True',
                'versionId': 'version'
            }
        ]
        engine = Engine(analysis_api)
        result = engine.analyze('log', {'key': {'nested_key': 'value'}})

        expected_event_matches = [
            EngineResult(
                rule_id='rule_id_1',
                rule_version='version',
                log_type='log',
                dedup='TypeError',
                error_message='\'ImmutableDict\' object does not support item assignment: rule_id_1.py, '
                'line 2, in rule    event["key"]["nested_key"] = "not_value"',
                event={'key': {
                    'nested_key': 'value'
                }},
                dedup_period_mins=60,
                title='TypeError("\'ImmutableDict\' object does not support item assignment")'
            )
        ]

        self.assertEqual(result, expected_event_matches)

    def test_analyze_single_rule_with_mocking(self) -> None:
        """ Tests a rule with defined mocking functions in rule and title -- covers both ways of importing a module. """

        analysis_api = mock.MagicMock()
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

        rule_body = [
            'import boto3', 'from datetime import date', 'from unittest.mock import MagicMock', 'def rule(event):',
            '\tassert isinstance(boto3, MagicMock)', '\tassert isinstance(date, MagicMock)', '\tassert isinstance(boto3.client, MagicMock)',
            '\ts3_client = boto3.client("s3")', '\tassert isinstance(s3_client, MagicMock)', '\tboto3.client.assert_called_once_with("s3")',
            '\tdt = date(2000, 1, 1)', '\tassert dt == "date_return_value"', '\tdate.assert_called_once_with(2000, 1, 1)', '\treturn True',
            'def alert_context(event):', '\treturn {}', 'def title(event):',
            '\treturn f"test_rule_with_mocking_{str(isinstance(boto3, MagicMock))}"'
        ]
        mocks = {
            'boto3': 'boto3_return_value',
            'date': 'date_return_value',
        }
        event = {'id': 'event_id', 'data': {'is_dst': True, 'p_log_type': 'log'}, 'mocks': mocks}
        rule = {'id': 'test_rule_with_mocking', 'body': '\n'.join(x for x in rule_body), 'versionId': 'versionId'}
        expected_result = {
            'id': 'event_id',
            'ruleId': "test_rule_with_mocking",
            'genericError': None,
            'errored': False,
            'ruleOutput': True,
            'ruleError': None,
            'titleOutput': 'test_rule_with_mocking_True',
            'titleError': None,
            'descriptionOutput': None,
            'descriptionError': None,
            'referenceOutput': None,
            'referenceError': None,
            'severityOutput': None,
            'severityError': None,
            'runbookOutput': None,
            'runbookError': None,
            'destinationsOutput': None,
            'destinationsError': None,
            'dedupOutput': 'test_rule_with_mocking_True',
            'dedupError': None,
            'alertContextOutput': '{}',
            'alertContextError': None,
        }

        engine = Engine(analysis_api)
        result = engine.analyze_single_rule(rule, event)
        self.assertEqual(expected_result, result)
