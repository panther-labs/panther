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

from ..src.rule import MAX_DEDUP_STRING_SIZE, MAX_TITLE_SIZE, Rule, RuleResult, TRUNCATED_STRING_SUFFIX


class TestRule(TestCase):

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

        expected_rule = RuleResult(matched=True, dedup_string='defaultDedupString:test_rule_matches')
        self.assertEqual(expected_rule, rule.run({}))

    def test_rule_doesnt_match(self) -> None:
        rule_body = 'def rule(event):\n\treturn False'
        rule = Rule({'id': 'test_rule_doesnt_match', 'body': rule_body, 'versionId': 'versionId'})
        expected_rule = RuleResult(matched=False)
        self.assertEqual(expected_rule, rule.run({}))

    def test_rule_with_dedup(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn "testdedup"'
        rule = Rule({'id': 'test_rule_with_dedup', 'body': rule_body, 'versionId': 'versionId'})
        expected_rule = RuleResult(matched=True, dedup_string='testdedup')
        self.assertEqual(expected_rule, rule.run({}))

    def test_restrict_dedup_size(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn "".join("a" for i in range({}))'.\
            format(MAX_DEDUP_STRING_SIZE+1)
        rule = Rule({'id': 'test_restrict_dedup_size', 'body': rule_body, 'versionId': 'versionId'})

        expected_dedup_string_prefix = ''.join('a' for _ in range(MAX_DEDUP_STRING_SIZE - len(TRUNCATED_STRING_SUFFIX)))
        expected_rule = RuleResult(matched=True, dedup_string=expected_dedup_string_prefix + TRUNCATED_STRING_SUFFIX)
        self.assertEqual(expected_rule, rule.run({}))

    def test_restrict_title_size(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn "".join("a" for i in range({}))'. \
            format(MAX_TITLE_SIZE+1)
        rule = Rule({'id': 'test_restrict_title_size', 'body': rule_body, 'versionId': 'versionId'})

        expected_title_string_prefix = ''.join('a' for _ in range(MAX_TITLE_SIZE - len(TRUNCATED_STRING_SUFFIX)))
        expected_rule = RuleResult(
            matched=True,
            dedup_string='defaultDedupString:test_restrict_title_size',
            title=expected_title_string_prefix + TRUNCATED_STRING_SUFFIX
        )
        self.assertEqual(expected_rule, rule.run({}))

    def test_empty_dedup_result_to_default(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn ""'
        rule = Rule({'id': 'test_empty_dedup_result_to_default', 'body': rule_body, 'versionId': 'versionId'})

        expected_rule = RuleResult(matched=True, dedup_string='defaultDedupString:test_empty_dedup_result_to_default')
        self.assertEqual(expected_rule, rule.run({}))

    def test_rule_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\traise Exception("test")'
        rule = Rule({'id': 'test_rule_throws_exception', 'body': rule_body, 'versionId': 'versionId'})
        rule_result = rule.run({})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_string)
        self.assertIsNotNone(rule_result.exception)

    def test_rule_invalid_rule_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn "test"'
        rule = Rule({'id': 'test_rule_invalid_rule_return', 'body': rule_body, 'versionId': 'versionId'})
        rule_result = rule.run({})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_string)
        self.assertIsNotNone(rule_result.exception)

    def test_dedup_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\traise Exception("test")'
        rule = Rule({'id': 'test_dedup_throws_exception', 'body': rule_body, 'versionId': 'versionId'})

        expected_rule = RuleResult(matched=True, dedup_string='defaultDedupString:test_dedup_throws_exception')
        self.assertEqual(expected_rule, rule.run({}))

    def test_rule_invalid_dedup_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn {}'
        rule = Rule({'id': 'test_rule_invalid_dedup_return', 'body': rule_body, 'versionId': 'versionId'})

        expected_rule = RuleResult(matched=True, dedup_string='defaultDedupString:test_rule_invalid_dedup_return')
        self.assertEqual(expected_rule, rule.run({}))

    def test_rule_dedup_returns_empty_string(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn ""'
        rule = Rule({'id': 'test_rule_dedup_returns_empty_string', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(matched=True, dedup_string='defaultDedupString:test_rule_dedup_returns_empty_string')
        self.assertEqual(rule.run({}), expected_result)

    def test_rule_matches_with_title(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn "title"'
        rule = Rule({'id': 'test_rule_matches_with_title', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(matched=True, dedup_string='defaultDedupString:test_rule_matches_with_title', title='title')
        self.assertEqual(rule.run({}), expected_result)

    def test_rule_title_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\traise Exception("test")'
        rule = Rule({'id': 'test_rule_title_throws_exception', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(matched=True, dedup_string='defaultDedupString:test_rule_title_throws_exception')
        self.assertEqual(rule.run({}), expected_result)

    def test_rule_invalid_title_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn {}'
        rule = Rule({'id': 'test_rule_invalid_title_return', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(matched=True, dedup_string='defaultDedupString:test_rule_invalid_title_return')
        self.assertEqual(rule.run({}), expected_result)

    def test_rule_title_returns_empty_string(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn ""'
        rule = Rule({'id': 'test_rule_title_returns_empty_string', 'body': rule_body, 'versionId': 'versionId'})

        expected_result = RuleResult(matched=True, dedup_string='defaultDedupString:test_rule_title_returns_empty_string')
        self.assertEqual(rule.run({}), expected_result)
