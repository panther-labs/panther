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
from unittest import TestCase

from ..src.data_model import DataModel
from ..src.enriched_event import PantherEvent
from ..src.immutable import ImmutableList, ImmutableDict


class TestEnrichedEvent(TestCase):

    def test_udm_missing_key(self) -> None:
        event = {'dst_ip': '1.1.1.1', 'dst_port': '2222'}
        data_model = DataModel(
            {
                'body': 'def get_source_ip(event):\n\treturn None',
                'versionId': 'version',
                'mappings': [{
                    'name': 'destination_ip',
                    'path': 'dst_ip'
                }, {
                    'name': 'source_ip',
                    'method': 'get_source_ip'
                }],
                'id': 'data_model_id'
            }
        )
        enriched_event = PantherEvent(event, data_model)
        self.assertEqual(enriched_event.udm('missing_key'), None)

    def test_udm_method(self) -> None:
        event = {'dst_ip': '1.1.1.1', 'dst_port': '2222'}
        data_model = DataModel(
            {
                'body': 'def get_source_ip(event):\n\treturn "1.2.3.4"',
                'versionId': 'version',
                'mappings': [{
                    'name': 'destination_ip',
                    'path': 'dst_ip'
                }, {
                    'name': 'source_ip',
                    'method': 'get_source_ip'
                }],
                'id': 'data_model_id'
            }
        )
        enriched_event = PantherEvent(event, data_model)
        self.assertEqual(enriched_event.udm('source_ip'), '1.2.3.4')

    def test_udm_path(self) -> None:
        event = {'dst_ip': '1.1.1.1', 'dst_port': '2222'}
        data_model = DataModel(
            {
                'body': 'def get_source_ip(event):\n\treturn "1.2.3.4"',
                'versionId': 'version',
                'mappings': [{
                    'name': 'destination_ip',
                    'path': 'dst_ip'
                }, {
                    'name': 'source_ip',
                    'method': 'get_source_ip'
                }],
                'id': 'data_model_id'
            }
        )
        enriched_event = PantherEvent(event, data_model)
        self.assertEqual(enriched_event.udm('destination_ip'), '1.1.1.1')
        # test path with '.' in it
        event = {'destination.ip': '1.1.1.1', 'dst_port': '2222'}
        data_model = DataModel(
            {
                'versionId': 'version',
                'mappings': [{
                    'name': 'destination_ip',
                    'path': '\"destination.ip\"'
                }],
                'id': 'data_model_id'
            }
        )
        enriched_event = PantherEvent(event, data_model)
        self.assertEqual(enriched_event.udm('destination_ip'), '1.1.1.1')

    def test_udm_json_path(self) -> None:
        event = {'dst': {'ip': '1.1.1.1', 'port': '2222'}}
        data_model = DataModel(
            {
                'body': 'def get_source_ip(event):\n\treturn "1.2.3.4"',
                'versionId': 'version',
                'mappings': [{
                    'name': 'destination_ip',
                    'path': '$.dst.ip'
                }, {
                    'name': 'source_ip',
                    'method': 'get_source_ip'
                }],
                'id': 'data_model_id'
            }
        )
        enriched_event = PantherEvent(event, data_model)
        self.assertEqual(enriched_event.udm('destination_ip'), '1.1.1.1')

    def test_udm_complex_json_path(self) -> None:
        event = {'events': [{'parameters': [{'name': 'USER_EMAIL', 'value': 'user@example.com'}]}]}
        data_model = DataModel(
            {
                'body': 'def get_source_ip(event):\n\treturn "1.2.3.4"',
                'versionId': 'version',
                'mappings':
                    [
                        {
                            'name': 'email',
                            'path': '$.events[*].parameters[?(@.name == "USER_EMAIL")].value'
                        }, {
                            'name': 'source_ip',
                            'method': 'get_source_ip'
                        }
                    ],
                'id': 'data_model_id'
            }
        )
        enriched_event = PantherEvent(event, data_model)
        self.assertEqual(enriched_event.udm('email'), 'user@example.com')

    def test_udm_multiple_matches(self) -> None:
        exception = False
        event = {'dst': {'ip': '1.1.1.1', 'port': '2222'}}
        data_model = DataModel(
            {
                'body': 'def get_source_ip(event):\n\treturn "1.2.3.4"',
                'versionId': 'version',
                'mappings': [{
                    'name': 'destination_ip',
                    'path': '$.dst.*'
                }, {
                    'name': 'source_ip',
                    'method': 'get_source_ip'
                }],
                'id': 'data_model_id'
            }
        )
        enriched_event = PantherEvent(event, data_model)
        try:
            enriched_event.udm('destination_ip')
        except Exception:  # pylint: disable=broad-except
            exception = True
        self.assertTrue(exception)

    def test_udm_method_cannot_mutate_event(self) -> None:
        event = {'src_ip': '', 'extra': {'t': 10}, 'dst': {'ip': '1.2.3.4'}}
        event_copy = deepcopy(event)
        data_model = DataModel(
            {
                'body':
                    'def get_source_ip(event):'
                    '\n\tif event["src_ip"] == "":'
                    '\n\t\tevent["src_ip"] = None'
                    '\n\tif event["extra"]["t"] == 10:'
                    '\n\t\tevent["extra"]["t"] = 11'
                    '\n\treturn (event["src_ip"], event["extra"]["t"])',
                'versionId': 'version',
                'mappings': [{
                    'name': 'destination_ip',
                    'path': '$.dst.*'
                }, {
                    'name': 'source_ip',
                    'method': 'get_source_ip'
                }],
                'id': 'data_model_id'
            }
        )
        enriched_event = PantherEvent(event, data_model)
        with self.assertRaises(TypeError):
            enriched_event.udm('source_ip')
        self.assertEqual(event_copy, event)

    def test_assignment_not_allowed_on_getitem_access(self) -> None:
        # No DataModel given
        event = {'dst': {'ip': '1.1.1.1', 'port': '2222'}, 'extra': [{'t': 10}]}
        enriched_event = PantherEvent(event, None)
        with self.assertRaises(TypeError):
            # pylint: disable=E1137
            enriched_event['dst'] = 1  # type: ignore
        self.assertIsInstance(enriched_event['dst'], ImmutableDict)
        with self.assertRaises(TypeError):
            # pylint: disable=E1137
            enriched_event['dst']['ip'] = 1
        self.assertIsInstance(enriched_event['extra'], ImmutableList)
        self.assertIsInstance(enriched_event['extra'][0], ImmutableDict)

    def test_assignment_not_allowed_on_udm_access(self) -> None:
        event = {'dst_ip': '1.1.1.1', 'dst_port': '2222', 'extra': {'timestamp': 1, 'array': [1, 2]}}
        data_model = DataModel(
            {
                'versionId': 'version',
                'mappings': [{
                    'name': 'destination_ip',
                    'path': 'dst_ip'
                }, {
                    'name': 'extra_fields',
                    'path': 'extra'
                }],
                'id': 'data_model_id'
            }
        )
        enriched_event = PantherEvent(event, data_model)
        self.assertEqual(ImmutableDict(event['extra']), enriched_event.udm('extra_fields'))
        self.assertIsInstance(enriched_event.udm('extra_fields'), ImmutableDict)
        self.assertIsInstance(enriched_event.udm('extra_fields')['array'], ImmutableList)
        with self.assertRaises(TypeError):
            enriched_event.udm('extra_fields')['timestamp'] = 10

    def test_nested_list_immutability(self) -> None:
        event = {'headers': [{'User-Agent': 'Chrome', 'Host': 'google.com'}]}
        enriched_event = PantherEvent(event, None)
        self.assertIsInstance(enriched_event['headers'], ImmutableList)
        self.assertIsInstance(enriched_event['headers'][0], ImmutableDict)
