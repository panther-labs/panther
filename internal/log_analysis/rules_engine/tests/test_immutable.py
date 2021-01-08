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

from unittest import TestCase

from ..src.immutable import ImmutableDict, ImmutableList


class TestImmutableDict(TestCase):

    def setUp(self) -> None:
        self.initial_dict = {'t': 10, 'a': [{'b': 1, 'c': 2}], 'd': {'e': {'f': True}}}
        self.immutable_dict = ImmutableDict(self.initial_dict)

    def test_assignment_not_allowed(self) -> None:
        with self.assertRaises(TypeError):
            # pylint: disable=E1137
            self.immutable_dict['a'] = 1  # type: ignore

    def test_original_dict_not_mutated(self) -> None:
        _ = self.immutable_dict['a']
        self.assertEqual(self.initial_dict, self.immutable_dict._container)

    def test_raises_error_for_non_existent_key(self) -> None:
        with self.assertRaises(KeyError):
            _ = self.immutable_dict['a-non-existent-key']

    def test_getitem(self) -> None:
        self.assertEqual(self.immutable_dict['t'], self.initial_dict['t'])

    def test_nested_access(self) -> None:
        self.assertEqual(self.immutable_dict['a'][0]['b'], 1)
        self.assertEqual(self.immutable_dict['d']['e']['f'], True)


class TestImmutableList(TestCase):

    def setUp(self) -> None:
        self.initial_list = ['a', 'b', 'c']
        self.immutable_list = ImmutableList(self.initial_list)

    def test_raises_error_on_non_existent_index(self) -> None:
        with self.assertRaises(IndexError):
            _ = self.immutable_list[10]

    def test_assignment_not_allowed(self) -> None:
        with self.assertRaises(TypeError):
            # pylint: disable=E1137
            self.immutable_list[0] = 'd'  # type: ignore

    def test_getitem(self) -> None:
        self.assertEqual(self.immutable_list[0], self.initial_list[0])
