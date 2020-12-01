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
import re
import tempfile
from collections.abc import Mapping
import traceback
from dataclasses import dataclass
from typing import Any, Optional, Callable

from .logging import get_logger
from .util import id_to_path, import_file_as_module, store_modules

_RULE_FOLDER = os.path.join(tempfile.gettempdir(), 'rules')

# Maximum size for a dedup string
MAX_DEDUP_STRING_SIZE = 1000

# Maximum size for a title
MAX_TITLE_SIZE = 1000
# The limit for DDB is 400kb per item (we store this one in DDB) and the limit for SQS/SNS is 256KB.
# The limit of 200kb is an approximation - the other fields included in the request will be less than the remaining 56kb
MAX_ALERT_CONTEXT_SIZE = 200 * 1024  # 200kb

ALERT_CONTEXT_ERROR_KEY = "_error"

TRUNCATED_STRING_SUFFIX = '... (truncated)'

DEFAULT_RULE_DEDUP_PERIOD_MINS = 60


# pylint: disable=too-many-instance-attributes
@dataclass
class RuleResult:
    """Class containing the result of running a rule"""

    setup_exception: Optional[Exception] = None

    matched: Optional[bool] = None  # rule output
    rule_exception: Optional[Exception] = None

    dedup_output: Optional[str] = None
    dedup_exception: Optional[Exception] = None

    title_output: Optional[str] = None
    title_exception: Optional[Exception] = None

    alert_context: Optional[str] = None
    alert_context_exception: Optional[Exception] = None

    @property
    def error_type(self) -> Optional[str]:
        """Returns the type of the exception, None if there was no error"""
        if self.setup_exception:
            exception = self.setup_exception
        elif self.rule_exception:
            exception = self.rule_exception
        else:
            return None
        return type(exception).__name__

    @property
    def short_error_message(self) -> Optional[str]:
        """Returns short error message, None if there was no error"""
        if self.setup_exception:
            exception = self.setup_exception
        elif self.rule_exception:
            exception = self.rule_exception
        else:
            return None
        return repr(exception)

    @property
    def error_message(self) -> Optional[str]:
        """Returns formatted error message with traceback"""
        if self.setup_exception:
            exception = self.setup_exception
        elif self.rule_exception:
            exception = self.rule_exception
        else:
            return None

        trace = traceback.format_tb(exception.__traceback__)
        # we only take last element of trace which will show the rule file name and line of the error, for example:
        #    division by zero: AlwaysFail.py, line 4, in rule 1/0
        file_trace = trace[len(trace) - 1].strip().replace("\n", "")
        # this looks like: File "/tmp/rules/AlwaysFail.py", line 4, in rule 1/0 BUT we want just the file name
        return str(exception) + ": " + re.sub(r'File.*/(.*[.]py)"', r'\1', file_trace)

    @property
    def errored(self) -> bool:
        """Returns whether any of the rule functions raised an error"""
        return bool(
            self.rule_exception or self.title_exception or self.dedup_exception or self.alert_context_exception or self.setup_exception
        )


# pylint: disable=too-many-instance-attributes
class Rule:
    """Panther rule metadata and imported module."""

    # pylint: disable=too-many-branches
    def __init__(self, config: Mapping):
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

        self._setup_exception = None
        try:
            self._module = self._import_rule_as_module()
            if not hasattr(self._module, 'rule'):
                raise AssertionError("rule needs to have a method named 'rule'")
        except Exception as err:  # pylint: disable=broad-except
            self._setup_exception = err
            return

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

    def run(self, event: Mapping, batch_mode: bool = True) -> RuleResult:
        """
        Analyze a log line with this rule and return True, False, or an error.
        :param event: The event to run the rule against
        :param batch_mode: Whether the rule runs as part of the log analysis or as part of a simple rule test.
        In batch mode, title/dedup functions are not checked if the rule won't trigger an alert and also title()/dedup()
        won't raise exceptions, so that an alert won't be missed.
        """
        rule_result = RuleResult()
        # If there was an error setting up the rule
        # return early
        if self._setup_exception:
            rule_result.setup_exception = self._setup_exception
            return rule_result

        try:
            rule_result.matched = self._run_command(self._module.rule, event, bool)
        except Exception as err:  # pylint: disable=broad-except
            rule_result.rule_exception = err

        if batch_mode and not rule_result.matched:
            # In batch mode (log analysis), there is no need to run the title/dedup functions
            # if the rule isn't going to trigger an alert
            return rule_result

        try:
            rule_result.title_output = self._get_title(event, use_default_on_exception=batch_mode)
        except Exception as err:  # pylint: disable=broad-except
            rule_result.title_exception = err

        try:
            rule_result.dedup_output = self._get_dedup(event, rule_result.title_output, use_default_on_exception=batch_mode)
        except Exception as err:  # pylint: disable=broad-except
            rule_result.dedup_exception = err

        try:
            rule_result.alert_context = self._get_alert_context(event, use_default_on_exception=batch_mode)
        except Exception as err:  # pylint: disable=broad-except
            rule_result.alert_context_exception = err

        return rule_result

    # Returns the dedup string for this rule match
    # If the rule match had a custom title, use the title as a deduplication string
    # If no title and no dedup function is defined, return the default dedup string.
    def _get_dedup(self, event: Mapping, title: Optional[str], use_default_on_exception: bool = True) -> str:
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

    def _get_title(self, event: Mapping, use_default_on_exception: bool = True) -> Optional[str]:
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

    def _get_alert_context(self, event: Mapping, use_default_on_exception: bool = True) -> Optional[str]:
        if not self._has_alert_context:
            return None

        try:
            alert_context = self._run_command(self._module.alert_context, event, dict)
            serialized_alert_context = json.dumps(alert_context)
        except Exception as err:  # pylint: disable=broad-except
            if use_default_on_exception:
                return json.dumps({ALERT_CONTEXT_ERROR_KEY: repr(err)})
            raise

        if len(serialized_alert_context) > MAX_ALERT_CONTEXT_SIZE:
            # If context exceeds max size, return empty one
            alert_context_error = 'alert_context size is [{}] characters, bigger than maximum of [{}] characters'.format(
                len(serialized_alert_context), MAX_ALERT_CONTEXT_SIZE
            )
            return json.dumps({ALERT_CONTEXT_ERROR_KEY: alert_context_error})

        return serialized_alert_context

    def _store_rule(self) -> None:
        """Stores rule to disk."""
        path = id_to_path(_RULE_FOLDER, self.rule_id)
        self.logger.debug('storing rule in path %s', path)
        store_modules(path, self.rule_body)

    def _import_rule_as_module(self) -> Any:
        """Dynamically import a Python module from a file.

        See also: https://docs.python.org/3/library/importlib.html#importing-a-source-file-directly
        """
        path = id_to_path(_RULE_FOLDER, self.rule_id)
        mod = import_file_as_module(path, self.rule_id)
        self.logger.debug('imported module %s from path %s', self.rule_id, path)
        return mod

    def _run_command(self, function: Callable, event: Mapping, expected_type: Any) -> Any:
        result = function(event)
        if not isinstance(result, expected_type):
            raise Exception(
                'rule [{}] function [{}] returned [{}], expected [{}]'.format(
                    self.rule_id, function.__name__,
                    type(result).__name__, expected_type.__name__
                )
            )
        return result
