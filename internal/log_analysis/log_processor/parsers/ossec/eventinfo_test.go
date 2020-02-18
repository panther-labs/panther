package ossec

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/stretchr/testify/require"
)

func TestEventInfo(t *testing.T) {
	//nolint:lll
	log := `{"rule":{"level":5,"comment":"Syslogd restarted.","sidid":1005,"group":"syslog,errors,"},"id":"1510376401.0","TimeStamp":1510376401000,"location":"/var/log/messages","full_log":"Nov 11 00:00:01 ix syslogd[72090]: restart","hostname":"ix","program_name":"syslogd"}`

	expectedTime := time.Unix(1510376401, 0).UTC()

	expectedEvent := &EventInfo{
		Rule: &Rule{
			Level:   aws.Int(5),
			Comment: aws.String("Syslogd restarted."),
			SIDID:   aws.Int(1005),
			Group:   aws.String("syslog,errors,"),
		},
		ID:          aws.String("1510376401.0"),
		Timestamp:   (*timestamp.UnixMillisecond)(&expectedTime),
		Location:    aws.String("/var/log/messages"),
		FullLog:     aws.String("Nov 11 00:00:01 ix syslogd[72090]: restart"),
		Hostname:    aws.String("ix"),
		ProgramName: aws.String("syslogd"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("OSSEC.EventInfo")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkEventInfo(t, log, expectedEvent)
}

func TestEventInfoType(t *testing.T) {
	parser := &EventInfoParser{}
	require.Equal(t, "OSSEC.EventInfo", parser.LogType())
}

func checkEventInfo(t *testing.T, log string, expectedEvent *EventInfo) {
	parser := &EventInfoParser{}
	events := parser.Parse(log)
	require.Equal(t, 1, len(events))
	event := events[0].(*EventInfo)

	// rowid changes each time
	require.Greater(t, len(*event.PantherRowID), 0) // ensure something is there.
	expectedEvent.PantherRowID = event.PantherRowID

	require.Equal(t, expectedEvent, event)
}
