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
from typing import Any, Optional

from .data_model import DataModel
from .immutable import ImmutableDict, json_encoder


class PantherEvent(ImmutableDict):  # pylint: disable=R0901
    """Panther enriched event with unified data model (udm) access."""

    def __init__(self, event: Mapping, data_model: Optional[DataModel]):
        """Create data model lookups

        Args:
            event: Dictionary representing the event.
            data_model: the data model used for the LogType associated with this event
        """
        super().__init__(event)
        self.data_model = data_model

    def udm(self, key: str) -> Any:
        """Converts standard data model field to logtype field"""
        if not self.data_model:
            raise Exception("a data model hasn't been specified")
        # access values via standardized fields
        if key in self.data_model.paths:
            # we are dealing with a jsonpath
            json_path = self.data_model.paths.get(key)
            if json_path:
                matches = json_path.find(self._container)
                if len(matches) == 1:
                    return self._ensure_immutable(matches[0].value)
                if len(matches) > 1:
                    raise Exception(
                        'JSONPath [{}] in DataModel [{}], matched multiple fields.'.format(json_path, self.data_model.data_model_id)
                    )
        if key in self.data_model.methods:
            # we are dealing with method
            method = self.data_model.methods.get(key)
            if callable(method):
                return self._ensure_immutable(method(self._ensure_immutable(self._container)))
        # no matches, return None by default
        return None

    json_encoder = json_encoder
