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


@dataclass
class RuleResult:
    """Class containing the result of running a rule"""
    exception: Optional[Exception] = None
    matched: Optional[bool] = None
    dedup_string: Optional[str] = None


class Rule:
    """Panther rule metadata and imported module."""
    logger = get_logger()

    def __init__(self, rule_id: Optional[str], rule_body: Optional[str], rule_severity: Optional[str], rule_version: Optional[str]):
        """Create new rule.

        Args:
            rule_id: Unique rule identifier
            rule_body: The rule body
            rule_severity: The severity of the rule
            rule_version: The version of the rule
        """
        if not rule_id or not rule_body or not rule_severity or not rule_version:
            raise AssertionError('id, body, severity and version are required fields')
        self.rule_id = rule_id
        self.rule_body = rule_body
        self.rule_severity = rule_severity

        self._store_rule()
        self._module = self._import_rule_as_module()

        if not rule_version:
            self.rule_version = 'default'
        else:
            self.rule_version = rule_version

        if not hasattr(self._module, 'rule'):
            raise AssertionError("rule needs to have a method named 'rule'")

        if hasattr(self._module, 'dedup'):
            self._has_dedup = True
        else:
            self._has_dedup = False

    def run(self, event: Dict[str, Any]) -> RuleResult:
        """Analyze a log line with this rule and return True, False, or an error."""

        dedup_string: Optional[str] = None
        try:
            rule_result = _run_command(self._module.rule, event, bool)
            if rule_result and self._has_dedup:
                dedup_string = _run_command(self._module.dedup, event, str)
                if dedup_string and len(dedup_string) > MAX_DEDUP_STRING_SIZE:
                    self.logger.warning(
                        'maximum dedup string size is [%d] characters. Dedup string for rule with ID '
                        '[%s] is [%d] characters. Truncating.', MAX_DEDUP_STRING_SIZE, self.rule_id, len(dedup_string)
                    )
                    dedup_string = dedup_string[:MAX_DEDUP_STRING_SIZE]
        except Exception as err:  # pylint: disable=broad-except
            return RuleResult(exception=err)

        # If users haven't specified a dedup function return a default value
        if rule_result and not dedup_string:
            dedup_string = self.rule_id
        return RuleResult(matched=rule_result, dedup_string=dedup_string)

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


def _run_command(function: Callable, event: Dict[str, Any], expected_type: Any) -> Any:
    result = function(event)
    if not isinstance(result, expected_type):
        raise Exception(
            'rule fuction [{}] returned [{}], expected [{}]'.format(function.__name__,
                                                                    type(result).__name__, expected_type.__name__)
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
