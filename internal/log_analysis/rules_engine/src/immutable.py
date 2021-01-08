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

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence


class ImmutableContainerMixin(ABC):
    """Base class for immutable collections"""

    _conversions = {}

    @classmethod
    @abstractmethod
    def mutable_type(cls):
        pass

    def mutable_arguments(cls):
        return {}

    def __init_subclass__(cls, **kwargs):
        cls.register(cls.mutable_type())

    def __init__(self, container):
        self._container = self._shallow_copy(container)
        self._conversions = tuple(self.__class__._conversions.items())
        self._registered_types = tuple(klass for klass, _ in self._conversions)

    @abstractmethod
    def _shallow_copy(self, obj):
        pass

    @classmethod
    def register(cls, klass):
        cls._conversions[klass] = cls

    def __getitem__(self, item):
        value = self._container[item]
        if isinstance(value, self._registered_types):
            for mutable_type, immutable_type in self._conversions:
                if isinstance(value, mutable_type):
                    value = immutable_type(value, **self.mutable_arguments())
        return value

    def __repr__(self):
        return f'{self.__class__.__name__}({self._container})'

    def __len__(self) -> int:
        return self._container.__len__()

    def __iter__(self):
        return iter(self._container)


class ImmutableDict(ImmutableContainerMixin, Mapping):

    @classmethod
    def mutable_type(cls):
        return dict

    def _shallow_copy(self, obj):
        return obj.copy()


class ImmutableList(ImmutableContainerMixin, Sequence):

    @classmethod
    def mutable_type(cls):
        return list

    def _shallow_copy(self, obj):
        return tuple(obj)
