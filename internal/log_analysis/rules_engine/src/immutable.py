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
from copy import deepcopy
from typing import Any, Dict, Iterator, Type, no_type_check


class ImmutableContainerMixin(ABC):
    """Base class for immutable collections"""

    _CONVERSIONS: Dict[Any, Any] = {}

    @classmethod
    @abstractmethod
    def mutable_type(cls) -> Any:
        """Specify the mutable type that corresponds to this immutable container class"""

    @classmethod
    @no_type_check
    def register(cls) -> None:
        """Register the corresponding mutable type for this class"""
        cls._CONVERSIONS[cls.mutable_type()] = cls

    def __init__(self, container: Any):
        self._container = self._shallow_copy(container)
        self._registered_conversions = tuple(self.__class__._CONVERSIONS.items())
        self._registered_types = tuple(klass for klass, _ in self._registered_conversions)

    @abstractmethod
    def _shallow_copy(self, obj: Any) -> Any:
        """Creates a shallow copy of the given object"""

    def copy(self) -> Any:
        """
        Returns a deep copy of the wrapped container object, which is mutable.
        Useful for interoperability with dependencies that perform their own type-checking,
        or when mutation is necessary.
        NOTE: Deep-copying has a performance overhead, so use only when necessary.
        """
        return self.mutable_type()(deepcopy(self._container))

    @no_type_check
    def __getitem__(self, item):
        value = self._ensure_immutable(self._container[item])
        return value

    def _ensure_immutable(self, value: Any) -> Any:
        if isinstance(value, self._registered_types):
            for mutable_type, immutable_type in self._registered_conversions:
                if isinstance(value, mutable_type):
                    value = immutable_type(value)
                    break
        return value

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self._container})'

    def __len__(self) -> int:
        return self._container.__len__()

    def __iter__(self) -> Iterator:
        return iter(self._ensure_immutable(element) for element in self._container)


class ImmutableDict(ImmutableContainerMixin, Mapping):  # pylint: disable=R0901
    """Read-only dictionary data type"""

    @classmethod
    def mutable_type(cls) -> Type[dict]:
        return dict

    def _shallow_copy(self, obj: dict) -> dict:
        return obj.copy()

    def to_dict(self) -> dict:
        """
        Create a deep copy as a mutable dictionary.
        """
        return self.copy()


class ImmutableList(ImmutableContainerMixin, Sequence):  # pylint: disable=R0901
    """Read-only sequence data type"""

    @classmethod
    def mutable_type(cls) -> Type[list]:
        return list

    def _shallow_copy(self, obj: list) -> tuple:
        return tuple(obj)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, self.__class__):
            return self._container == other._container

        if isinstance(other, (tuple, list)):
            # Allow comparison with lists and tuples
            return len(self._container) == len(other) and \
                   self._container == tuple(other)

        return False

    def as_list(self) -> list:
        """
        Create a deep copy as a mutable list.
        """
        return self.copy()


ImmutableList.register()
ImmutableDict.register()


def json_encoder(obj: Any) -> Any:
    """
    Custom encoder for immutable objects

    :param obj: the object for JSON serialization
    :return: a JSON-serializable object
    """
    if isinstance(obj, ImmutableContainerMixin):
        return obj._container  # pylint: disable=W0212
    raise TypeError
