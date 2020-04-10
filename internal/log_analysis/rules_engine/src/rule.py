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

import os
import sys
import tempfile
from dataclasses import dataclass
from importlib import util as import_util
from pathlib import Path
from typing import Any, Dict, Optional, Callable

from .logging import get_logger

_RULE_FOLDER = os.path.join(tempfile.gettempdir(), 'rules')

# Rule with ID 'aws_globals' contains common Python logic used by other rules
COMMON_MODULE_RULE_ID = 'aws_globals'

# Maximum size for a dedup string
MAX_DEDUP_STRING_SIZE = 1000

# Maximum size for a title
MAX_TITLE_SIZE = 1000

TRUNCATED_STRING_SUFFIX = '... (truncated)'

DEFAULT_RULE_DEDUP_PERIOD_MINS = 60


@dataclass
class RuleResult:
    """Class containing the result of running a rule"""
    exception: Optional[Exception] = None
    matched: Optional[bool] = None
    dedup_string: Optional[str] = None
    title: Optional[str] = None


# pylint: disable=too-many-instance-attributes
class Rule:
    """Panther rule metadata and imported module."""
    logger = get_logger()

    def __init__(self, config: Dict[str, Any]):
        """Create new rule from a dict.

        Args:
            config: Dictionary that we expect to have the following keys:
                rule_id: Unique rule identifier
                body: The rule body
                (Optional) version: The version of the rule
                (Optional) dedup_period_mins: The period during which the events will be deduplicated
        """
        if not ('id' in config) or not isinstance(config['id'], str):
            raise AssertionError('Field "id" of type str is required field')
        self.rule_id = config['id']

        if not ('body' in config) or not isinstance(config['body'], str):
            raise AssertionError('Field "body" of type str is required field')
        self.rule_body = config['body']

        if not ('versionId' in config) or not isinstance(config['versionId'], str):
            raise AssertionError('Field "versionId" of type str is required field')
        self.rule_version = config['versionId']

        if not ('dedupPeriodMinutes' in config) or not isinstance(config['dedupPeriodMinutes'], int):
            self.rule_dedup_period_mins = DEFAULT_RULE_DEDUP_PERIOD_MINS
        else:
            self.rule_dedup_period_mins = config['dedupPeriodMinutes']

        self._store_rule()
        self._module = self._import_rule_as_module()

        if not hasattr(self._module, 'rule'):
            raise AssertionError("rule needs to have a method named 'rule'")

        if hasattr(self._module, 'dedup'):
            self._has_dedup = True
        else:
            self._has_dedup = False

        self._default_dedup_string = 'defaultDedupString:{}'.format(self.rule_id)

        if hasattr(self._module, 'title'):
            self._has_title = True
        else:
            self._has_title = False

    def run(self, event: Dict[str, Any]) -> RuleResult:
        """Analyze a log line with this rule and return True, False, or an error."""

        dedup_string: Optional[str] = None
        title: Optional[str] = None
        try:
            rule_result = self._run_command(self._module.rule, event, bool)
            if rule_result:
                dedup_string = self._get_dedup(event)
                title = self._get_title(event)
        except Exception as err:  # pylint: disable=broad-except
            return RuleResult(exception=err)
        return RuleResult(matched=rule_result, dedup_string=dedup_string, title=title)

    def _get_dedup(self, event: Dict[str, Any]) -> str:
        if not self._has_dedup:
            # If no dedup function defined, return default dedup string
            return self._default_dedup_string
        try:
            dedup_string = self._run_command(self._module.dedup, event, str)
        except Exception as err:  # pylint: disable=broad-except
            self.logger.warning('dedup method raised exception. Defaulting dedup string to "%s". Exception: %s', self.rule_id, err)
            return self._default_dedup_string

        if dedup_string:
            if len(dedup_string) > MAX_DEDUP_STRING_SIZE:
                # If dedup_string exceeds max size, truncate it
                self.logger.warning(
                    'maximum dedup string size is [%d] characters. Dedup string for rule with ID '
                    '[%s] is [%d] characters. Truncating.', MAX_DEDUP_STRING_SIZE, self.rule_id, len(dedup_string)
                )
                num_characters_to_keep = MAX_DEDUP_STRING_SIZE - len(TRUNCATED_STRING_SUFFIX)
                return dedup_string[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX
            return dedup_string
        # If dedup string was the empty string, return default dedup string
        return self._default_dedup_string

    def _get_title(self, event: Dict[str, Any]) -> Optional[str]:
        if not self._has_title:
            return None
        try:
            title_string = self._run_command(self._module.title, event, str)
        except Exception as err:  # pylint: disable=broad-except
            self.logger.warning('title method raised exception. Using default. Exception: %s', err)
            return None

        if title_string:
            if len(title_string) > MAX_TITLE_SIZE:
                # If title exceeds max size, truncate it
                self.logger.warning(
                    'maximum title string size is [%d] characters. Title for rule with ID '
                    '[%s] is [%d] characters. Truncating.', MAX_TITLE_SIZE, self.rule_id, len(title_string)
                )
                num_characters_to_keep = MAX_TITLE_SIZE - len(TRUNCATED_STRING_SUFFIX)
                return title_string[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX
            return title_string
        # If title is empty string, return None
        return None

    def _store_rule(self) -> None:
        """Stores rule to disk."""
        path = _rule_id_to_path(self.rule_id)
        self.logger.debug('storing rule in path %s', path)

        # Create dir if it doesn't exist
        Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as py_file:
            py_file.write(self.rule_body)

    def _import_rule_as_module(self) -> Any:
        """Dynamically import a Python module from a file.

        See also: https://docs.python.org/3/library/importlib.html#importing-a-source-file-directly
        """

        path = _rule_id_to_path(self.rule_id)
        spec = import_util.spec_from_file_location(self.rule_id, path)
        mod = import_util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        self.logger.debug('imported module %s from path %s', self.rule_id, path)
        if self.rule_id == COMMON_MODULE_RULE_ID:
            self.logger.debug('imported global module %s from path %s', self.rule_id, path)
            # Importing it as a shared module
            sys.modules[self.rule_id] = mod
        return mod

    def _run_command(self, function: Callable, event: Dict[str, Any], expected_type: Any) -> Any:
        result = function(event)
        if not isinstance(result, expected_type):
            raise Exception(
                'rule [{}] fuction [{}] returned [{}], expected [{}]'.format(
                    self.rule_id, function.__name__,
                    type(result).__name__, expected_type.__name__
                )
            )
        return result


def _rule_id_to_path(rule_id: str) -> str:
    """Method returns the file path where the rule will be stored"""
    safe_id = ''.join(x if _allowed_char(x) else '_' for x in rule_id)
    path = os.path.join(_RULE_FOLDER, safe_id + '.py')
    return path


def _allowed_char(char: str) -> bool:
    """Return true if the character is part of a valid rule ID."""
    return char.isalnum() or char in {' ', '-', '.'}
