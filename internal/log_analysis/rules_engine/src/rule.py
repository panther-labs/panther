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
from typing import Any, Dict

from .logging import get_logger

_RULE_FOLDER = os.path.join(tempfile.gettempdir(), 'rules')

# Rule with ID 'aws_globals' contains common Python logic used by other rules
COMMON_MODULE_RULE_ID = 'aws_globals'


@dataclass
class RuleResult:
    exception: Exception = None
    matched: bool = None
    dedup: str = None


class Rule:
    """Panther rule metadata and imported module."""
    logger = get_logger()

    def __init__(self, rule_id: str, rule_body: str, rule_version: str):
        """Import rule contents from disk.

        Args:
            rule_id: Unique rule identifier
            rule_body: The rule body
        """
        self.rule_id = rule_id
        self.rule_version = rule_version

        self._import_error = None
        try:
            self.store_rule(rule_id, rule_body)
            self._module = self.import_rule_as_module(rule_id)
        except Exception as err:  # pylint: disable=broad-except
            self._import_error = err

    def store_rule(self, rule_id: str, rule_body: str) -> None:
        """Stores rule to disk."""
        path = self.rule_id_to_path(rule_id)
        self.logger.debug('storing rule in path {}'.format(path))

        ## Create dir if it doesn't exist
        Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as py_file:
            py_file.write(rule_body)

    def import_rule_as_module(self, rule_id: str) -> Any:
        """Dynamically import a Python module from a file.

        See also: https://docs.python.org/3/library/importlib.html#importing-a-source-file-directly
        """

        path = self.rule_id_to_path(rule_id)
        spec = import_util.spec_from_file_location(rule_id, path)
        mod = import_util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        self.logger.debug('imported module {} from path {}'.format(rule_id, path))
        if rule_id == COMMON_MODULE_RULE_ID:
            self.logger.debug('imported global module {} from path {}'.format(rule_id, path))
            # Importing it as a shared module
            sys.modules[rule_id] = mod
        return mod

    def rule_id_to_path(self, rule_id: str) -> str:
        safe_id = ''.join(x if self.allowed_char(x) else '_' for x in rule_id)
        path = os.path.join(_RULE_FOLDER, safe_id + '.py')
        return path

    def allowed_char(self, char: str) -> bool:
        """Return true if the character is part of a valid rule ID."""
        return char.isalnum() or char in {' ', '-', '.'}

    def run(self, event: Dict[str, Any]) -> RuleResult:
        """Analyze a log line with this rule and return True, False, or an error."""
        if self._import_error:
            return RuleResult(exception=self._import_error)

        try:
            # Python source should have a method called "rule"
            matched = self._module.rule(event)
        except Exception as err:  # pylint: disable=broad-except
            return RuleResult(exception=err)

        if not isinstance(matched, bool):
            e = Exception('rule returned {}, expected bool'.format(type(matched).__name__))
            return RuleResult(exception=e)

        return RuleResult(matched=matched, dedup="default")
