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
from jsonpath_ng import Fields

from ..src.data_model import DataModel


class TestDataModel(TestCase):  # pylint: disable=too-many-public-methods

    def test_create_data_model_missing_id(self) -> None:
        exception = False
        try:
            DataModel(
                {
                    'body': 'rule',
                    'versionId': 'version',
                    'mappings': [{
                        'name': 'destination_ip',
                        'field': 'dst_ip'
                    }, {
                        'name': 'source_ip',
                        'method': 'get_source_ip'
                    }]
                }
            )
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_create_data_model_missing_body(self) -> None:
        exception = False
        try:
            DataModel({'id': 'data.model.id', 'versionId': 'version', 'mappings': [{'name': 'destination_ip', 'path': 'dst_ip'}]})
        except AssertionError:
            exception = True
        # body is optional for DataModels
        self.assertFalse(exception)

    def test_create_data_model_missing_version(self) -> None:
        exception = False
        try:
            DataModel(
                {
                    'body': 'def method(event):\n    return True',
                    'id': 'data.model.id',
                    'mappings': [{
                        'name': 'destination_ip',
                        'field': 'dst_ip'
                    }, {
                        'name': 'source_ip',
                        'method': 'get_source_ip'
                    }]
                }
            )
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_create_data_model_missing_method(self) -> None:
        exception = False
        data_model_body = 'def another_method(event):\n\treturn "hello"'
        try:
            DataModel(
                {
                    'id': 'data.model.id',
                    'body': data_model_body,
                    'mappings': [{
                        'name': 'destination_ip',
                        'field': 'dst_ip'
                    }, {
                        'name': 'source_ip',
                        'method': 'get_source_ip'
                    }]
                }
            )
        except AssertionError:
            exception = True

        self.assertTrue(exception)

    def test_data_model_field(self) -> None:
        data_model_body = 'def get_source_ip(event):\n\treturn "source_ip"'
        data_model_mappings = [{'name': 'destination_ip', 'path': 'dst_ip'}, {'name': 'source_ip', 'method': 'get_source_ip'}]
        data_model = DataModel({'id': 'data.model.id', 'body': data_model_body, 'versionId': 'version', 'mappings': data_model_mappings})

        self.assertEqual('data.model.id', data_model.data_model_id)
        self.assertEqual(data_model_body, data_model.body)
        self.assertEqual('version', data_model.version)

        expected_path_value = Fields('dst_ip')
        self.assertEqual(expected_path_value, data_model.paths['destination_ip'])

    def test_data_model_method(self) -> None:
        data_model_body = 'def get_source_ip(event):\n\treturn "source_ip"'
        data_model_mappings = [{'name': 'destination_ip', 'path': 'dst_ip'}, {'name': 'source_ip', 'method': 'get_source_ip'}]
        data_model = DataModel({'id': 'data.model.id', 'body': data_model_body, 'versionId': 'version', 'mappings': data_model_mappings})
        expected_result = 'source_ip'
        self.assertTrue(callable(data_model.methods['source_ip']))
        self.assertEqual(expected_result, data_model.methods['source_ip']({}))

    def test_data_model_method_throws_exception(self) -> None:
        exception = False
        data_model_body = 'def get_source_ip(event):\n\traise NameError("Found an issue")'
        data_model_mappings = [{'name': 'destination_ip', 'path': 'dst_ip'}, {'name': 'source_ip', 'method': 'get_source_ip'}]
        data_model = DataModel({'id': 'data.model.id', 'body': data_model_body, 'versionId': 'version', 'mappings': data_model_mappings})
        try:
            data_model.methods['source_ip']({})
        except NameError:
            exception = True
        self.assertTrue(exception)
