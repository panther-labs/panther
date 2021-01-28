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

from unittest import TestCase
import json

from ..src.rule import MAX_DEDUP_STRING_SIZE, MAX_GENERATED_FIELD_SIZE, Rule, RuleResult, TRUNCATED_STRING_SUFFIX
from ..src.enriched_event import PantherEvent


class TestRule(TestCase):  # pylint: disable=too-many-public-methods

    def test_create_rule_missing_id(self) -> None:
        exception = False
        try:
            Rule({'body': 'rule', 'versionId': 'version'})
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_create_rule_missing_body(self) -> None:
        exception = False
        try:
            Rule({'id': 'test_create_rule_missing_body', 'versionId': 'version'})
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_create_rule_missing_version(self) -> None:
        exception = False
        try:
            Rule({'id': 'test_create_rule_missing_version', 'body': 'rule'})
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_rule_default_dedup_time(self) -> None:
        rule_body = 'def rule(event):\n\treturn True'
        rule = Rule({'id': 'test_rule_default_dedup_time', 'body': rule_body, 'versionId': 'versionId'})

        self.assertEqual(60, rule.rule_dedup_period_mins)

    def test_rule_tags(self) -> None:
        rule_body = 'def rule(event):\n\treturn True'
        rule = Rule({'id': 'test_rule_default_dedup_time', 'body': rule_body, 'versionId': 'versionId', 'tags': ['tag2', 'tag1']})

        self.assertEqual(['tag1', 'tag2'], rule.rule_tags)

    def test_rule_reports(self) -> None:
        rule_body = 'def rule(event):\n\treturn True'
        rule = Rule(
            {
                'id': 'test_rule_default_dedup_time',
                'body': rule_body,
                'versionId': 'versionId',
                'reports': {
                    'key1': ['value2', 'value1'],
                    'key2': ['value1']
                }
            }
        )

        self.assertEqual({'key1': ['value1', 'value2'], 'key2': ['value1']}, rule.rule_reports)

    def test_create_rule_missing_method(self) -> None:
        exception = False
        rule_body = 'def another_method(event):\n\treturn False'
        try:
            Rule({'id': 'test_create_rule_missing_method', 'body': rule_body})
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_rule_matches(self) -> None:
        rule_body = 'def rule(event):\n\treturn True'
        rule = Rule({'id': 'test_rule_matches', 'body': rule_body, 'dedupPeriodMinutes': 100, 'versionId': 'test'})

        self.assertEqual('test_rule_matches', rule.rule_id)
        self.assertEqual(rule_body, rule.rule_body)
        self.assertEqual('test', rule.rule_version)
        self.assertEqual(100, rule.rule_dedup_period_mins)

        expected_rule = RuleResult(matched=True, dedup_output='defaultDedupString:test_rule_matches')
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None)))

    def test_rule_doesnt_match(self) -> None:
        rule_body = 'def rule(event):\n\treturn False'
        rule = Rule({'id': 'test_rule_doesnt_match', 'body': rule_body, 'versionId': 'versionId'})
        expected_rule = RuleResult(matched=False)
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None)))

    def test_rule_with_dedup(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn "testdedup"'
        rule = Rule({'id': 'test_rule_with_dedup', 'body': rule_body, 'versionId': 'versionId'})
        expected_rule = RuleResult(matched=True, dedup_output='testdedup')
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None)))

    def test_restrict_dedup_size(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn "".join("a" for i in range({}))'. \
            format(MAX_DEDUP_STRING_SIZE + 1)
        rule = Rule({'id': 'test_restrict_dedup_size', 'body': rule_body, 'versionId': 'versionId'})

        expected_dedup_string_prefix = ''.join('a' for _ in range(MAX_DEDUP_STRING_SIZE - len(TRUNCATED_STRING_SUFFIX)))
        expected_rule = RuleResult(matched=True, dedup_output=expected_dedup_string_prefix + TRUNCATED_STRING_SUFFIX)
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None)))

    def test_restrict_title_size(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\n' \
                    'def dedup(event):\n\treturn "test"\n' \
                    'def title(event):\n\treturn "".join("a" for i in range({}))'. \
            format(MAX_GENERATED_FIELD_SIZE + 1)
        rule = Rule({'id': 'test_restrict_title_size', 'body': rule_body, 'versionId': 'versionId'})

        expected_title_string_prefix = ''.join('a' for _ in range(MAX_GENERATED_FIELD_SIZE - len(TRUNCATED_STRING_SUFFIX)))
        expected_rule = RuleResult(matched=True, dedup_output='test', title_output=expected_title_string_prefix + TRUNCATED_STRING_SUFFIX)
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None)))

    def test_empty_dedup_result_to_default(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn ""'
        rule = Rule({'id': 'test_empty_dedup_result_to_default', 'body': rule_body, 'versionId': 'versionId'})

        expected_rule = RuleResult(matched=True, dedup_output='defaultDedupString:test_empty_dedup_result_to_default')
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None)))

    def test_rule_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\traise Exception("test")'
        rule = Rule({'id': 'test_rule_throws_exception', 'body': rule_body, 'versionId': 'versionId'})
        rule_result = rule.run(PantherEvent({}, None))
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_output)
        self.assertIsNotNone(rule_result.rule_exception)

    def test_invalid_python_syntax(self) -> None:
        rule_body = 'def rule(test):this is invalid python syntax'
        rule = Rule({'id': 'test_invalid_python_syntax', 'body': rule_body, 'versionId': 'versionId'})
        rule_result = rule.run(PantherEvent({}, None))
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_output)
        self.assertIsNone(rule_result.rule_exception)

        self.assertTrue(rule_result.errored)
        self.assertEqual(rule_result.error_type, "SyntaxError")
        self.assertIsNotNone(rule_result.short_error_message)
        self.assertIsNotNone(rule_result.error_message)

    def test_rule_invalid_rule_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn "test"'
        rule = Rule({'id': 'test_rule_invalid_rule_return', 'body': rule_body, 'versionId': 'versionId'})
        rule_result = rule.run(PantherEvent({}, None))
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_output)
        self.assertTrue(rule_result.errored)

        expected_short_msg = "Exception('rule [test_rule_invalid_rule_return] function [rule] returned [str], expected [bool]')"
        self.assertEqual(expected_short_msg, rule_result.short_error_message)
        self.assertEqual(rule_result.error_type, 'Exception')

    def test_dedup_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\traise Exception("test")'
        rule = Rule({'id': 'test_dedup_throws_exception', 'body': rule_body, 'versionId': 'versionId'})

        expected_rule = RuleResult(matched=True, dedup_output='defaultDedupString:test_dedup_throws_exception')
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None)))

    def test_dedup_exception_batch_mode(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\traise Exception("test")'
        rule = Rule({'id': 'test_dedup_throws_exception', 'body': rule_body, 'versionId': 'versionId'})

        actual = rule.run(PantherEvent({}, None), batch_mode=False)

        self.assertTrue(actual.matched)
        self.assertIsNotNone(actual.dedup_exception)
        self.assertTrue(actual.errored)

    def test_rule_invalid_dedup_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn {}'
        rule = Rule({'id': 'test_rule_invalid_dedup_return', 'body': rule_body, 'versionId': 'versionId'})

        expected_rule = RuleResult(matched=True, dedup_output='defaultDedupString:test_rule_invalid_dedup_return')
        self.assertEqual(expected_rule, rule.run(PantherEvent({}, None)))

    def test_rule_dedup_returns_empty_string(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn ""'
        rule = Rule({'id': 'test_rule_dedup_returns_empty_string', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(matched=True, dedup_output='defaultDedupString:test_rule_dedup_returns_empty_string')
        self.assertEqual(rule.run(PantherEvent({}, None)), expected_result)

    def test_rule_matches_with_title_without_dedup(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn "title"'
        rule = Rule({'id': 'test_rule_matches_with_title', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(matched=True, dedup_output='title', title_output='title')
        self.assertEqual(rule.run(PantherEvent({}, None)), expected_result)

    def test_rule_title_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\traise Exception("test")'
        rule = Rule({'id': 'test_rule_title_throws_exception', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(
            matched=True,
            dedup_output='test_rule_title_throws_exception',
            title_output='test_rule_title_throws_exception',
        )
        self.assertEqual(rule.run(PantherEvent({}, None)), expected_result)

    def test_rule_invalid_title_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn {}'
        rule = Rule({'id': 'test_rule_invalid_title_return', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(
            matched=True, dedup_output='test_rule_invalid_title_return', title_output='test_rule_invalid_title_return'
        )
        self.assertEqual(rule.run(PantherEvent({}, None)), expected_result)

    def test_rule_title_returns_empty_string(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn ""'
        rule = Rule({'id': 'test_rule_title_returns_empty_string', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(matched=True, dedup_output='defaultDedupString:test_rule_title_returns_empty_string', title_output='')
        self.assertEqual(expected_result, rule.run(PantherEvent({}, None)))

    def test_alert_context(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef alert_context(event):\n\treturn {"string": "string", "int": 1, "nested": {}}'
        rule = Rule({'id': 'test_alert_context', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(
            matched=True,
            dedup_output='defaultDedupString:test_alert_context',
            alert_context='{"string": "string", "int": 1, "nested": {}}'
        )
        self.assertEqual(expected_result, rule.run(PantherEvent({}, None)))

    def test_alert_context_invalid_return_value(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef alert_context(event):\n\treturn ""'
        rule = Rule({'id': 'test_alert_context_invalid_return_value', 'body': rule_body, 'versionId': 'versionId'})

        expected_alert_context = json.dumps(
            {
                '_error':
                    'Exception(\'rule [test_alert_context_invalid_return_value] function [alert_context] returned [str], expected [Mapping]\')'  # pylint: disable=C0301
            }
        )
        expected_result = RuleResult(
            matched=True, dedup_output='defaultDedupString:test_alert_context_invalid_return_value', alert_context=expected_alert_context
        )
        self.assertEqual(expected_result, rule.run(PantherEvent({}, None)))

    def test_alert_context_too_big(self) -> None:
        # Function should generate alert_context exceeding limit
        alert_context_function = 'def alert_context(event):\n' \
                                 '\ttest_dict = {}\n' \
                                 '\tfor i in range(300000):\n' \
                                 '\t\ttest_dict[str(i)] = "value"\n' \
                                 '\treturn test_dict'
        rule_body = 'def rule(event):\n\treturn True\n{}'.format(alert_context_function)
        rule = Rule({'id': 'test_alert_context_too_big', 'body': rule_body, 'versionId': 'versionId'})
        expected_alert_context = json.dumps(
            {'_error': 'alert_context size is [5588890] characters, bigger than maximum of [204800] characters'}
        )
        expected_result = RuleResult(
            matched=True, dedup_output='defaultDedupString:test_alert_context_too_big', alert_context=expected_alert_context
        )
        self.assertEqual(expected_result, rule.run(PantherEvent({}, None)))

    def test_alert_context_immutable_event(self) -> None:
        alert_context_function = 'def alert_context(event):\n' \
                                 '\treturn {"headers": event["headers"],\n' \
                                 '\t\t"get_params": event["query_string_args"]}'
        rule_body = 'def rule(event):\n\treturn True\n{}'.format(alert_context_function)
        rule = Rule({'id': 'test_alert_context_immutable_event', 'body': rule_body, 'versionId': 'versionId'})
        event = {'headers': {'User-Agent': 'Chrome'}, 'query_string_args': [{'a': '1'}, {'b': '2'}]}

        expected_alert_context = json.dumps({'headers': event['headers'], 'get_params': event['query_string_args']})
        expected_result = RuleResult(
            matched=True, dedup_output='defaultDedupString:test_alert_context_immutable_event', alert_context=expected_alert_context
        )
        self.assertEqual(expected_result, rule.run(PantherEvent(event, None)))

    def test_alert_context_returns_full_event(self) -> None:
        alert_context_function = 'def alert_context(event):\n\treturn event'
        rule_body = 'def rule(event):\n\treturn True\n{}'.format(alert_context_function)
        rule = Rule({'id': 'test_alert_context_returns_full_event', 'body': rule_body, 'versionId': 'versionId'})
        event = {'test': 'event'}

        expected_alert_context = json.dumps(event)
        expected_result = RuleResult(
            matched=True, dedup_output='defaultDedupString:test_alert_context_returns_full_event', alert_context=expected_alert_context
        )
        self.assertEqual(expected_result, rule.run(PantherEvent(event, None)))

    # Generated Fields Tests
    def test_rule_with_all_generated_fields(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\n' \
                    'def alert_context(event):\n\treturn {}\n' \
                    'def title(event):\n\treturn "test_rule_with_all_generated_fields"\n' \
                    'def description(event):\n\treturn "test description"\n' \
                    'def severity(event):\n\treturn "HIGH"\n' \
                    'def reference(event):\n\treturn "test reference"\n' \
                    'def runbook(event):\n\treturn "test runbook"\n' \
                    'def destinations(event):\n\treturn []'
        rule = Rule({'id': 'test_rule_with_all_generated_fields', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(
            matched=True,
            alert_context='{}',
            title_output='test_rule_with_all_generated_fields',
            dedup_output='test_rule_with_all_generated_fields',
            description_output='test description',
            severity_output='HIGH',
            reference_output='test reference',
            runbook_output='test runbook',
            destinations_output=[]
        )
        self.assertEqual(expected_result, rule.run(PantherEvent({}, None)))

    def test_rule_with_invalid_severity(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\n' \
                    'def alert_context(event):\n\treturn {}\n' \
                    'def title(event):\n\treturn "test_rule_with_invalid_severity"\n' \
                    'def severity(event):\n\treturn "CRITICAL-ISH"\n'
        rule = Rule({'id': 'test_rule_with_invalid_severity', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(
            matched=True,
            alert_context='{}',
            title_output='test_rule_with_invalid_severity',
            dedup_output='test_rule_with_invalid_severity',
            severity_output="INFO",
        )
        result = rule.run(PantherEvent({}, None))
        self.assertEqual(expected_result, result)

    def test_rule_with_valid_severity_case_insensitive(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\n' \
                    'def alert_context(event):\n\treturn {}\n' \
                    'def title(event):\n\treturn "test_rule_with_valid_severity_case_insensitive"\n' \
                    'def severity(event):\n\treturn "cRiTiCaL"\n'
        rule = Rule({'id': 'test_rule_with_valid_severity_case_insensitive', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(
            matched=True,
            alert_context='{}',
            title_output='test_rule_with_valid_severity_case_insensitive',
            dedup_output='test_rule_with_valid_severity_case_insensitive',
            severity_output="CRITICAL",
        )
        result = rule.run(PantherEvent({}, None))
        self.assertEqual(expected_result, result)
