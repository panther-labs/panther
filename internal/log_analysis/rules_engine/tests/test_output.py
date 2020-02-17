import os
from unittest import TestCase, mock

from ..src.output import MatchedEventsBuffer
from ..src import EventMatch


@mock.patch.object('alert_merger', '._DDB_TABLE_NAME', return_value='tablename')
class TestMatchedEventsBuffer(TestCase):
    @mock.patch.object('alert_merger', '._DDB_TABLE_NAME', return_value='tablename')
    def test_add_event(self) -> None:
        buffer = MatchedEventsBuffer()
        event_match = EventMatch('rule_id', 'rule_version', 'log_type', 'dedup', {})
        buffer.add_event(event_match)
        buffer.flush()
