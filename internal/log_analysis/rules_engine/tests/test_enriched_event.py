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

from ..src.data_model import DataModel
from ..src.enriched_event import EnrichedEvent


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
        enriched_event = EnrichedEvent(event, data_model)
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
        enriched_event = EnrichedEvent(event, data_model)
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
        enriched_event = EnrichedEvent(event, data_model)
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
        enriched_event = EnrichedEvent(event, data_model)
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
        enriched_event = EnrichedEvent(event, data_model)
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
        enriched_event = EnrichedEvent(event, data_model)
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
        enriched_event = EnrichedEvent(event, data_model)
        try:
            enriched_event.udm('destination_ip')
        except Exception:  # pylint: disable=broad-except
            exception = True
        self.assertTrue(exception)
