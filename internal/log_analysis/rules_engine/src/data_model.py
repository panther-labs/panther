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
import tempfile
from importlib import util as import_util
from pathlib import Path
from typing import Any, Callable, Dict, List

from jsonpath_ng import Fields, parse

from .logging import get_logger

_DATAMODEL_FOLDER = os.path.join(tempfile.gettempdir(), 'datamodels')

# constants used to extract data from data model
NAME = 'name'
PATH = 'path'
METHOD = 'method'


class DataModel:
    """Panther data model and imported methods."""

    def __init__(self, config: Dict[str, Any]):
        """Create data model lookups

        Args:
            config: Dictionary that should have the folllowing keys:
                id: unique data model id
                mappings: list of log type fields to standard field conversions
                version: the version of the data model
                (Optional) body: python body associated with the mappings
        """
        self.logger = get_logger()
        # data models contains logtype to schema definitions
        if not isinstance(config.get('id'), str):
            raise AssertionError('Field "id" of type str is required field')
        self.data_model_id = config['id']

        # mappings are required
        if not isinstance(config.get('mappings'), list):
            raise AssertionError('Field "mappings" of type list')
        self.paths: Dict[str, Fields] = dict()  # setup paths mappings
        self.methods: Dict[str, Callable] = dict()  # setup method mappings

        # body is optional in a data model
        self.body = ''
        if 'body' in config:
            if not isinstance(config.get('body'), str):
                raise AssertionError('Field "body" of type str')
            self.body = config['body']

        if not isinstance(config.get('versionId'), str):
            raise AssertionError('Field "versionId" of type str is required field')
        self.version = config['versionId']

        self._store_data_models()
        self._module = self._import_data_model_as_module()
        self._extract_mappings(config['mappings'])

    def _extract_mappings(self, source_mappings: List[Dict[str, str]]) -> None:
        for mapping in source_mappings:
            if NAME not in mapping:
                raise AssertionError('DataModel [{}] is missing required field: [{}]'.format(self.data_model_id, NAME))
            if PATH in mapping:
                # we are dealing with a string field or a jsonpath
                self.paths[mapping[NAME]] = parse(mapping[PATH])
            elif METHOD in mapping:
                # we are dealing with a method
                if not hasattr(self._module, mapping[METHOD]):
                    raise AssertionError('DataModel is missing method named [{}]'.format(mapping[METHOD]))
                self.methods[mapping[NAME]] = getattr(self._module, mapping[METHOD])
            else:
                raise AssertionError('DataModel [{}] is missing a field or method for [{}]'.format(self.data_model_id, mapping[NAME]))

    def _import_data_model_as_module(self) -> Any:
        """Dynamically import a Python module from a file.

        See also: https://docs.python.org/3/library/importlib.html#importing-a-source-file-directly
        """

        path = _data_model_id_to_path(self.data_model_id)
        spec = import_util.spec_from_file_location(self.data_model_id, path)
        mod = import_util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        self.logger.info('imported module %s from path %s', self.data_model_id, path)
        return mod

    def _store_data_models(self) -> None:
        """Stores data models to disk."""
        path = _data_model_id_to_path(self.data_model_id)
        self.logger.info('storing data model in path %s', path)

        # Create dir if it doesn't exist
        Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as py_file:
            py_file.write(self.body)


def _data_model_id_to_path(data_model_id: str) -> str:
    """Method returns the file path where the data model will be stored"""
    safe_id = ''.join(x if _allowed_char(x) else '_' for x in data_model_id)
    path = os.path.join(_DATAMODEL_FOLDER, safe_id + '.py')
    return path


def _allowed_char(char: str) -> bool:
    """Return true if the character is part of a valid data model ID."""
    return char.isalnum() or char in {' ', '-', '.'}
