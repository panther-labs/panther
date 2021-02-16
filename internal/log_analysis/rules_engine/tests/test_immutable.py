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

from copy import deepcopy
import json
from unittest import TestCase

from ..src.immutable import ImmutableDict, ImmutableList, json_encoder


class TestImmutableDict(TestCase):

    def setUp(self) -> None:
        self.initial_dict = {'t': 10, 'a': [{'b': 1, 'c': 2}], 'd': {'e': {'f': True}}}
        self.immutable_dict = ImmutableDict(self.initial_dict)

    def test_assignment_not_allowed(self) -> None:
        with self.assertRaises(TypeError):
            # pylint: disable=E1137
            self.immutable_dict['a'] = 1  # type: ignore

    def test_nested_assignment_not_allowed(self) -> None:
        with self.assertRaises(TypeError):
            # pylint: disable=E1137
            self.immutable_dict['d']['e']['f'] = False

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

    def test_equality(self) -> None:
        # Equality with dict
        self.assertEqual(self.immutable_dict, self.initial_dict)
        # Equality with another instance
        equal_dict = deepcopy(self.initial_dict)
        other_immutable_dict = ImmutableDict(equal_dict)
        self.assertEqual(other_immutable_dict, self.immutable_dict)

    def test_shallow_copy(self) -> None:
        self.assertEqual(self.immutable_dict._container, self.initial_dict)
        self.assertIsNot(self.immutable_dict._container, self.initial_dict)

    def test_get(self) -> None:
        self.assertIsInstance(self.immutable_dict.get('d'), ImmutableDict)
        self.assertIsInstance(self.immutable_dict.get('a'), ImmutableList)

    def test_ensure_immutable(self) -> None:
        initial_dict = {'a': [[1, 2], [3, 4]], 'b': {'c': {'d': 1}}, 't': 10, 'e': {'f': [{'g': 90}]}}
        immutable_dict = ImmutableDict(initial_dict)
        # List of lists with immutable elements
        self.assertIsInstance(immutable_dict['a'], ImmutableList)
        self.assertIsInstance(immutable_dict['a'][0], ImmutableList)
        self.assertEqual(immutable_dict['a'][0][1], 2)
        # Two-level nested dictionary
        self.assertIsInstance(immutable_dict['b'], ImmutableDict)
        self.assertIsInstance(immutable_dict['b']['c'], ImmutableDict)
        self.assertEqual(immutable_dict['b']['c']['d'], 1)
        # Plain immutable object at top-level
        self.assertIsInstance(immutable_dict['t'], int)
        self.assertEqual(immutable_dict['t'], 10)
        # Two-level dictionary with nested list as value
        self.assertIsInstance(immutable_dict['e']['f'], ImmutableList)
        self.assertIsInstance(immutable_dict['e']['f'][0], ImmutableDict)
        self.assertEqual(immutable_dict['e']['f'][0]['g'], 90)

    def test_copy(self) -> None:
        initial_dict = {'a': True, 'b': {'c': {'e': True, 'd': [{'g': False}]}}}
        immutable_dict = ImmutableDict(initial_dict)
        dict_copy = immutable_dict.copy()
        self.assertIsNot(dict_copy, initial_dict)
        self.assertIsNot(dict_copy['b'], initial_dict['b'])
        self.assertEqual(dict_copy['b'], initial_dict['b'])
        self.assertIsInstance(dict_copy['b'], dict)
        self.assertIsInstance(dict_copy['b']['c'], dict)
        self.assertIsInstance(dict_copy['b']['c']['d'], list)
        self.assertIsNot(dict_copy['b']['c']['d'], initial_dict['b']['c']['d'])  # type: ignore
        dict_copy['h'] = False
        self.assertIs(dict_copy['h'], False)


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

    def test_equality(self) -> None:
        # List
        self.assertEqual(self.initial_list, self.immutable_list)
        # Tuple
        self.assertEqual(tuple(self.initial_list), self.immutable_list)
        # Same class
        self.assertEqual(ImmutableList(self.initial_list.copy()), self.immutable_list)

    def test_shallow_copy(self) -> None:
        self.assertEqual(list(self.immutable_list._container), self.initial_list)
        self.assertIsNot(self.immutable_list._container, self.initial_list)

    def test_ensure_immutable(self) -> None:
        initial_list = [[1, 2], [3, 4], {'a': {'b': 1}}]
        immutable_list = ImmutableList(initial_list)
        self.assertIsInstance(immutable_list[0], ImmutableList)
        self.assertIsInstance(immutable_list[2], ImmutableDict)
        self.assertIsInstance(immutable_list[2]['a'], ImmutableDict)

    def test_iteration_returns_immutable_objects(self) -> None:
        data = [{'b': {'c': True}}, {'d': {'c': False}}]
        immutable_list = ImmutableList(data)
        iterated_list = list(immutable_list)
        self.assertIsNot(iterated_list[0], data[0])
        self.assertIsNot(iterated_list[1], data[1])
        self.assertIsNot(iterated_list[0]['b'], data[0]['b'])
        self.assertIsInstance(iterated_list[0]['b'], ImmutableDict)

    def test_copy(self) -> None:
        initial_list = [{'b': {'c': True}}, {'d': {'c': False}}]
        immutable_list = ImmutableList(initial_list)
        list_copy = immutable_list.copy()
        self.assertIsNot(list_copy, initial_list)
        self.assertIsNot(list_copy[0], initial_list[0])
        self.assertEqual(list_copy[0], initial_list[0])
        self.assertIsInstance(list_copy[0], dict)
        list_copy.append({'e': False})
        self.assertIs(list_copy[-1]['e'], False)


class TestImmutableNestedList(TestCase):

    def setUp(self) -> None:
        self.initial_dict = {'a': [1, 2]}
        self.immutable_dict = ImmutableDict(self.initial_dict)

    def test_assignment_not_allowed(self) -> None:
        with self.assertRaises(TypeError):
            self.immutable_dict['a'][0] = 100

    def test_original_dict_not_mutated(self) -> None:
        _ = self.immutable_dict['a'][0]
        self.assertEqual(self.initial_dict, self.immutable_dict._container)

    def test_raises_error_for_non_existent_index(self) -> None:
        with self.assertRaises(IndexError):
            _ = self.immutable_dict['a'][2]


class TestJSONSerialization(TestCase):

    def test_immutable_list(self) -> None:
        initial_list = [1, 2, 3]
        immutable_list = ImmutableList(initial_list)
        self.assertEqual(json.dumps(initial_list), json.dumps(immutable_list, default=json_encoder))

    def test_immutable_dict(self) -> None:
        initial_dict = {'a': [1, 2, 3], 'b': {'c': True}}
        immutable_dict = ImmutableDict(initial_dict)
        self.assertEqual(json.dumps(initial_dict), json.dumps(immutable_dict, default=json_encoder))

    def test_raises_type_error_for_nonserializable_object(self) -> None:
        with self.assertRaises(TypeError):
            json.dumps({'test_case': TestCase}, default=json_encoder)
