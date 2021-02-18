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

from ..src.destination import Destination


class TestDestination(TestCase):  # pylint: disable=too-many-public-methods

    def test_create_destination_missing_display_name(self) -> None:
        exception = False
        exception_str = ''
        expected_exception_str = 'Field "displayName" of type str is required field'
        try:
            Destination(
                {
                    "alertTypes": ["RULE", "RULE_ERROR", "POLICY"],
                    "createdBy": "12345678-9012-3456-7890-123456789012",
                    "creationTime": "2021-01-13T21:29:27Z",
                    "lastModifiedBy": "12345678-9012-3456-7890-123456789012",
                    "lastModifiedTime": "2021-01-13T21:29:27Z",
                    "outputId": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
                    "outputType": "sns",
                    "outputConfig": {
                        "sns": {
                            "topicArn": "arn:aws:sns:us-east-1:123456789012:test"
                        }
                    },
                    "defaultForSeverity": []
                }
            )
        except AssertionError as err:
            exception = True
            exception_str = str(err)

        self.assertTrue(exception)
        self.assertEqual(expected_exception_str, exception_str)

    def test_create_destination_missing_output_id(self) -> None:
        exception = False
        exception_str = ''
        expected_exception_str = 'Field "outputId" of type str is required field'
        try:
            Destination(
                {
                    "alertTypes": ["RULE", "RULE_ERROR", "POLICY"],
                    "createdBy": "12345678-9012-3456-7890-123456789012",
                    "creationTime": "2021-01-13T21:29:27Z",
                    "displayName": "Test",
                    "lastModifiedBy": "12345678-9012-3456-7890-123456789012",
                    "lastModifiedTime": "2021-01-13T21:29:27Z",
                    "outputType": "sns",
                    "outputConfig": {
                        "sns": {
                            "topicArn": "arn:aws:sns:us-east-1:123456789012:test"
                        }
                    },
                    "defaultForSeverity": []
                }
            )
        except AssertionError as err:
            exception = True
            exception_str = str(err)

        self.assertTrue(exception)
        self.assertEqual(expected_exception_str, exception_str)

    def test_optional_fields_missing(self) -> None:
        exception = False
        try:
            Destination({
                "outputId": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
                "displayName": "Test",
            })
        except:  # pylint: disable=bare-except
            exception = True
        self.assertFalse(exception)

    def test_create_valid_destination(self) -> None:
        exception = False
        try:
            Destination(
                {
                    "alertTypes": ["RULE", "RULE_ERROR", "POLICY"],
                    "createdBy": "12345678-9012-3456-7890-123456789012",
                    "creationTime": "2021-01-13T21:29:27Z",
                    "displayName": "Test",
                    "lastModifiedBy": "12345678-9012-3456-7890-123456789012",
                    "lastModifiedTime": "2021-01-13T21:29:27Z",
                    "outputId": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
                    "outputType": "sns",
                    "outputConfig": {
                        "sns": {
                            "topicArn": "arn:aws:sns:us-east-1:123456789012:test"
                        }
                    },
                    "defaultForSeverity": [],
                }
            )
        except AssertionError:
            exception = True

        self.assertFalse(exception)
