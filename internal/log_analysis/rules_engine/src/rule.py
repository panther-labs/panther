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

import json
import os
import tempfile
from dataclasses import dataclass
from importlib import util as import_util
from pathlib import Path
from typing import Any, Dict, Optional, Callable

from .logging import get_logger

_RULE_FOLDER = os.path.join(tempfile.gettempdir(), 'rules')

# Maximum size for a dedup string
MAX_DEDUP_STRING_SIZE = 1000

# Maximum size for a title
MAX_TITLE_SIZE = 1000
MAX_ALERT_CONTEXT_SIZE = 200 * 1000  # 200kb

TRUNCATED_STRING_SUFFIX = '... (truncated)'

DEFAULT_RULE_DEDUP_PERIOD_MINS = 60


@dataclass
class RuleResult:
    """Class containing the result of running a rule"""
    exception: Optional[Exception] = None
    matched: Optional[bool] = None
    dedup_string: Optional[str] = None
    title: Optional[str] = None
    alert_context: Optional[str] = None


# pylint: disable=too-many-instance-attributes
class Rule:
    """Panther rule metadata and imported module."""

    # pylint: disable=too-many-branches
    def __init__(self, config: Dict[str, Any]):
        """Create new rule from a dict.

        Args:
            config: Dictionary that we expect to have the following keys:
                rule_id: Unique rule identifier
                body: The rule body
                (Optional) version: The version of the rule
                (Optional) dedup_period_mins: The period during which the events will be deduplicated
        """
        self.logger = get_logger()
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

        if not ('tags' in config) or not isinstance(config['tags'], list):
            self.rule_tags = list()
        else:
            config['tags'].sort()
            self.rule_tags = config['tags']

        if 'reports' not in config:
            self.rule_reports = dict()
        else:
            # Reports are Dict[str, List[str]]
            # Sorting the List before setting it
            for values in config['reports'].values():
                values.sort()
            self.rule_reports = config['reports']

        self._store_rule()
        self._module = self._import_rule_as_module()

        if not hasattr(self._module, 'rule'):
            raise AssertionError("rule needs to have a method named 'rule'")

        if hasattr(self._module, 'title'):
            self._has_title = True
        else:
            self._has_title = False

        if hasattr(self._module, 'dedup'):
            self._has_dedup = True
        else:
            self._has_dedup = False

        if hasattr(self._module, 'alert_context'):
            self._has_alert_context = True
        else:
            self._has_alert_context = False

        self._default_dedup_string = 'defaultDedupString:{}'.format(self.rule_id)

    def run(self, event: Dict[str, Any], raise_title_dedup: bool = False) -> RuleResult:
        """
        Analyze a log line with this rule and return True, False, or an error.
        :param event: The event to run the rule against
        :param raise_title_dedup: Whether to raise exceptions from title() and dedup() or use default values
        """

        dedup_string: Optional[str] = None
        title: Optional[str] = None
        alert_context: Optional[str] = None
        try:
            rule_result = self._run_command(self._module.rule, event, bool)
            if rule_result:
                use_default_on_exception = not raise_title_dedup
                title = self._get_title(event, use_default_on_exception)
                dedup_string = self._get_dedup(event, title, use_default_on_exception)
                alert_context = self._get_alert_context(event, use_default_on_exception)
        except Exception as err:  # pylint: disable=broad-except
            return RuleResult(exception=err)
        return RuleResult(matched=rule_result, dedup_string=dedup_string, title=title, alert_context=alert_context)

    # Returns the dedup string for this rule match
    # If the rule match had a custom title, use the title as a deduplication string
    # If no title and no dedup function is defined, return the default dedup string.
    def _get_dedup(self, event: Dict[str, Any], title: Optional[str], use_default_on_exception: bool = True) -> str:
        if not self._has_dedup:
            if title:
                # If no dedup function is defined but the rule had a title, use the title as dedup string
                return title
            # If no dedup function defined, return default dedup string
            return self._default_dedup_string

        try:
            dedup_string = self._run_command(self._module.dedup, event, str)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.warning('dedup method raised exception. Defaulting dedup string to "%s". Exception: %s', self.rule_id, err)
                return self._default_dedup_string
            raise

        if not dedup_string:
            # If dedup string is None or empty, return the default dedup string
            return self._default_dedup_string

        if len(dedup_string) > MAX_DEDUP_STRING_SIZE:
            # If dedup_string exceeds max size, truncate it
            self.logger.warning(
                'maximum dedup string size is [%d] characters. Dedup string for rule with ID '
                '[%s] is [%d] characters. Truncating.', MAX_DEDUP_STRING_SIZE, self.rule_id, len(dedup_string)
            )
            num_characters_to_keep = MAX_DEDUP_STRING_SIZE - len(TRUNCATED_STRING_SUFFIX)
            return dedup_string[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX

        return dedup_string

    def _get_title(self, event: Dict[str, Any], use_default_on_exception: bool = True) -> Optional[str]:
        if not self._has_title:
            return None

        try:
            title_string = self._run_command(self._module.title, event, str)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.warning('title method raised exception. Using default. Exception: %s', err)
                return None
            raise

        if len(title_string) > MAX_TITLE_SIZE:
            # If title exceeds max size, truncate it
            self.logger.warning(
                'maximum title string size is [%d] characters. Title for rule with ID '
                '[%s] is [%d] characters. Truncating.', MAX_TITLE_SIZE, self.rule_id, len(title_string)
            )
            num_characters_to_keep = MAX_TITLE_SIZE - len(TRUNCATED_STRING_SUFFIX)
            return title_string[:num_characters_to_keep] + TRUNCATED_STRING_SUFFIX

        return title_string

    def _get_alert_context(self, event: Dict[str, Any], use_default_on_exception: bool = True) -> Optional[str]:
        if not self._has_alert_context:
            return None

        try:
            alert_context = self._run_command(self._module.alert_context, event, dict)
            serialized_alert_context = json.dumps(alert_context)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                self.logger.warning('alert_context method raised exception. Using default. Exception: %s', err)
                return None
            raise

        if len(serialized_alert_context) > MAX_ALERT_CONTEXT_SIZE:
            # If title exceeds max size, use default
            self.logger.warning(
                'maximum alert_context size is [%d] characters. alert_context for rule with ID '
                '[%s] is [%d] characters. Using default', MAX_ALERT_CONTEXT_SIZE, self.rule_id, len(serialized_alert_context)
            )
            return None

        return serialized_alert_context

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
        return mod

    def _run_command(self, function: Callable, event: Dict[str, Any], expected_type: Any) -> Any:
        result = function(event)
        if not isinstance(result, expected_type):
            raise Exception(
                'rule [{}] function [{}] returned [{}], expected [{}]'.format(
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
