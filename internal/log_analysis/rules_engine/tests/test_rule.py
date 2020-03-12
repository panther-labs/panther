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

from ..src.rule import MAX_DEDUP_STRING_SIZE, Rule, RuleResult


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
            Rule(rule_id='id', rule_body=None, rule_severity='INFO', rule_version='version')
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_create_rule_missing_version(self) -> None:
        exception = False
        try:
            Rule(rule_id='id', rule_body='rule', rule_severity='INFO', rule_version=None)
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_create_rule_missing_severity(self) -> None:
        exception = False
        try:
            Rule(rule_id='id', rule_body='rule', rule_severity=None, rule_version='version')
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_create_rule_missing_method(self) -> None:
        exception = False
        rule_body = 'def another_method(event):\n\treturn False'
        try:
            Rule(rule_id='id', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_rule_matches(self) -> None:
        rule_body = 'def rule(event):\n\treturn True'
        rule = Rule(rule_id='id', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        expected_rule = RuleResult(matched=True, dedup_string='id')
        self.assertEqual(rule.run({}), expected_rule)

    def test_rule_doesnt_match(self) -> None:
        rule_body = 'def rule(event):\n\treturn False'
        rule = Rule(rule_id='id', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        expected_rule = RuleResult(matched=False)
        self.assertEqual(rule.run({}), expected_rule)

    def test_rule_with_dedup(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn "testdedup"'
        rule = Rule(rule_id='id', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        expected_rule = RuleResult(matched=True, dedup_string='testdedup')
        self.assertEqual(rule.run({}), expected_rule)

    def test_restrict_dedup_size(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn "".join("a" for i in range({}))'.\
            format(MAX_DEDUP_STRING_SIZE+1)
        rule = Rule(rule_id='id', rule_body=rule_body, rule_severity='INFO', rule_version='version')

        expected_dedup_string = ''.join('a' for _ in range(MAX_DEDUP_STRING_SIZE))
        expected_rule = RuleResult(matched=True, dedup_string=expected_dedup_string)
        self.assertEqual(rule.run({}), expected_rule)

    def test_empty_dedup_result_to_default(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn ""'
        rule = Rule(rule_id='id', rule_body=rule_body, rule_severity='INFO', rule_version='version')

        expected_rule = RuleResult(matched=True, dedup_string='id')
        self.assertEqual(rule.run({}), expected_rule)

    def test_rule_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\traise Exception("test")'
        rule = Rule(rule_id='id', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        rule_result = rule.run({})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_string)
        self.assertIsNotNone(rule_result.exception)

    def test_rule_invalid_rule_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn "test"'
        rule = Rule(rule_id='id', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        rule_result = rule.run({})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_string)
        self.assertIsNotNone(rule_result.exception)

    def test_dedup_throws_exception(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\traise Exception("test")'
        rule = Rule(rule_id='id', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        rule_result = rule.run({})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_string)
        self.assertIsNotNone(rule_result.exception)

    def test_rule_invalid_dedup_return(self) -> None:
        rule_body = 'def rule(event):\n\treturn True\ndef dedup(event):\n\treturn {}'
        rule = Rule(rule_id='id', rule_body=rule_body, rule_severity='INFO', rule_version='version')
        rule_result = rule.run({})
        self.assertIsNone(rule_result.matched)
        self.assertIsNone(rule_result.dedup_string)
        self.assertIsNotNone(rule_result.exception)
