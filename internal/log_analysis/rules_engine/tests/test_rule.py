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

from unittest import TestCase

from ..src.rule import MAX_DEDUP_STRING_SIZE, MAX_TITLE_SIZE, Rule, RuleResult, TRUNCATED_STRING_SUFFIX


class TestRule(TestCase):

    def test_create_rule_missing_id(self) -> None:
        exception = False
        try:
            Rule(rule_id=None, rule_body='rule', rule_severity='INFO', rule_version='version')
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_create_rule_missing_body(self) -> None:
        exception = False
        try:
            Rule(rule_id='test_create_rule_missing_body', rule_body=None, rule_severity='INFO', rule_version='version')
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_create_rule_missing_version(self) -> None:
        exception = False
        try:
            Rule(rule_id='test_create_rule_missing_version', rule_body='rule', rule_severity='INFO', rule_version=None)
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_create_rule_missing_severity(self) -> None:
        exception = False
        try:
            Rule(rule_id='test_create_rule_missing_severity', rule_body='rule', rule_severity=None, rule_version='version')
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_create_rule_missing_method(self) -> None:
        exception = False
        rule_body = 'def another_method(event):\n\treturn False'
        try:
            Rule(rule_id='test_create_rule_missing_method', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_rule_matches(self) -> None:
        rule_body = 'def rule(event):\n\treturn True'
        rule = Rule(rule_id='test_rule_matches', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        expected_rule = RuleResult(matched=True, dedup_string='test_rule_matches')
        self.assertEqual(expected_rule, rule.run({}))

    def test_rule_doesnt_match(self) -> None:
        rule_body = 'def rule(event):\n\treturn False'
        rule = Rule(rule_id='test_rule_doesnt_match', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        expected_rule = RuleResult(matched=False)
        self.assertEqual(rule.run({}), expected_rule)

    def test_rule_with_dedup(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn "testdedup"'
        rule = Rule(rule_id='test_rule_with_dedup', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        expected_rule = RuleResult(matched=True, dedup_string='testdedup')
        self.assertEqual(rule.run({}), expected_rule)

    def test_restrict_dedup_size(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn "".join("a" for i in range({}))'.\
            format(MAX_DEDUP_STRING_SIZE+1)
        rule = Rule(rule_id='test_restrict_dedup_size', rule_body=rule_body, rule_severity='INFO', rule_version='version')

        expected_dedup_string_prefix = ''.join('a' for _ in range(MAX_DEDUP_STRING_SIZE - len(TRUNCATED_STRING_SUFFIX)))
        expected_rule = RuleResult(matched=True, dedup_string=expected_dedup_string_prefix + TRUNCATED_STRING_SUFFIX)
        self.assertEqual(rule.run({}), expected_rule)

    def test_restrict_title_size(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn "".join("a" for i in range({}))'. \
            format(MAX_TITLE_SIZE+1)
        rule = Rule(rule_id='test_restrict_title_size', rule_body=rule_body, rule_severity='INFO', rule_version='version')

        expected_title_string_prefix = ''.join('a' for _ in range(MAX_TITLE_SIZE - len(TRUNCATED_STRING_SUFFIX)))
        expected_rule = RuleResult(
            matched=True, dedup_string='test_restrict_title_size', title=expected_title_string_prefix + TRUNCATED_STRING_SUFFIX
        )
        self.assertEqual(rule.run({}), expected_rule)

    def test_empty_dedup_result_to_default(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn ""'
        rule = Rule(rule_id='test_empty_dedup_result_to_default', rule_body=rule_body, rule_severity='INFO', rule_version='version')

        expected_rule = RuleResult(matched=True, dedup_string='test_empty_dedup_result_to_default')
        self.assertEqual(rule.run({}), expected_rule)

    def test_rule_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\traise Exception("test")'
        rule = Rule(rule_id='test_rule_throws_exception', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        rule_result = rule.run({})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_string)
        self.assertIsNotNone(rule_result.exception)

    def test_rule_invalid_rule_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn "test"'
        rule = Rule(rule_id='test_rule_invalid_rule_return', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        rule_result = rule.run({})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_string)
        self.assertIsNotNone(rule_result.exception)

    def test_dedup_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\traise Exception("test")'
        rule = Rule(rule_id='test_dedup_throws_exception', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        rule_result = rule.run({})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_string)
        self.assertIsNotNone(rule_result.exception)

    def test_rule_invalid_dedup_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn {}'
        rule = Rule(rule_id='test_rule_invalid_dedup_return', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        rule_result = rule.run({})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_string)
        self.assertIsNotNone(rule_result.exception)

    def test_rule_dedup_returns_empty_string(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn ""'
        rule = Rule(rule_id='test_rule_dedup_returns_empty_string', rule_body=rule_body, rule_severity='INFO', rule_version='version')

        expected_result = RuleResult(matched=True, dedup_string='test_rule_dedup_returns_empty_string')
        self.assertEqual(rule.run({}), expected_result)

    def test_rule_matches_with_title(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn "title"'
        rule = Rule(rule_id='test_rule_matches_with_title', rule_body=rule_body, rule_severity='INFO', rule_version='version')

        expected_result = RuleResult(matched=True, dedup_string='test_rule_matches_with_title', title='title')
        self.assertEqual(rule.run({}), expected_result)

    def test_rule_title_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\traise Exception("test")'
        rule = Rule(rule_id='test_rule_title_throws_exception', rule_body=rule_body, rule_severity='INFO', rule_version='version')

        rule_result = rule.run({})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.title)
        self.assertIsNone(rule_result.dedup_string)
        self.assertIsNotNone(rule_result.exception)

    def test_rule_invalid_title_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn {}'
        rule = Rule(rule_id='test_rule_invalid_title_return', rule_body=rule_body, rule_severity='INFO', rule_version='version')

        rule_result = rule.run({})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.title)
        self.assertIsNone(rule_result.dedup_string)
        self.assertIsNotNone(rule_result.exception)

    def test_rule_title_returns_empty_string(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef title(event):\n\treturn ""'
        rule = Rule(rule_id='test_rule_title_returns_empty_string', rule_body=rule_body, rule_severity='INFO', rule_version='version')

        expected_result = RuleResult(matched=True, dedup_string='test_rule_title_returns_empty_string')
        self.assertEqual(rule.run({}), expected_result)
