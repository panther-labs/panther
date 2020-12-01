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

from collections.abc import Mapping
from typing import Any, Iterator

from .data_model import DataModel
from .logging import get_logger


class EnrichedEvent(Mapping):
    """Panther enriched event with unified data model (udm) access."""

    def __init__(self, event: Mapping, data_model: DataModel):
        """Create data model lookups

        Args:
            event: Dictionary representing the event
            data_model: the data model used for the LogType associated with this event
        """
        self.logger = get_logger()
        self._data = event
        self.data_model = data_model

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def udm(self, key: str) -> Any:
        """Converts standard data model field to logtype field"""
        # access values via standardized fields
        if key in self.data_model.paths:
            # we are dealing with a jsonpath
            json_path = self.data_model.paths.get(key)
            if json_path:
                matches = json_path.find(self._data)
                if len(matches) == 1:
                    return matches[0].value
                if len(matches) > 1:
                    raise Exception(
                        'JSONPath [{}] in DataModel [{}], matched multiple fields.'.format(json_path, self.data_model.data_model_id)
                    )
        if key in self.data_model.methods:
            # we are dealing with method
            method = self.data_model.methods.get(key)
            if callable(method):
                return method(self._data)
        # no matches, return None by default
        return None
