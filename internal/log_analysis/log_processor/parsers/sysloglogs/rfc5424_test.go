package sysloglogs

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
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
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var parserRFC5424 parsers.LogParser

func TestRFC5424(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))
	syslogRFC5424 := &RFC5424Parser{}
	parserRFC5424 = syslogRFC5424.New()

	t.Run("Version4", testRFC5424Version4)
	t.Run("NoTimestmap", testRFC5424NoTimestmap)
	t.Run("NoStructuredDataNoProcID", testRFC5424NoStructuredDataNoProcID)
	t.Run("NoStructuredDataNoMsgID", testRFC5424NoStructuredDataNoMsgID)
	t.Run("WithStructuredData", testRFC5424WithStructuredData)
	t.Run("StructuredDataOnly", testRFC5424StructuredDataOnly)
}

func testRFC5424Version4(t *testing.T) {
	//nolint:lll
	log := `<165>4 2018-10-11T22:14:15.003Z mymach.it e - 1 [ex@32473 iut="3"] An application event log entry...`

	expectedTime, _ := time.Parse(time.RFC3339, "2018-10-11T22:14:15.003Z")

	expectedEvent := &RFC5424{
		Priority:  aws.Uint8(165),
		Facility:  aws.Uint8(20),
		Severity:  aws.Uint8(5),
		Version:   aws.Uint16(4),
		Timestamp: (*timestamp.RFC3339)(&expectedTime),
		Hostname:  aws.String("mymach.it"),
		Appname:   aws.String("e"),
		ProcID:    nil,
		MsgID:     aws.String("1"),
		Message:   aws.String("An application event log entry..."),
		StructuredData: &map[string]map[string]string{
			"ex@32473": {
				"iut": "3",
			},
		},
	}

	expectedEvent.AppendAnyDomainNamePtrs(expectedEvent.Hostname)

	// panther fields
	expectedEvent.PantherLogType = aws.String("Syslog.RFC5424")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC5424(t, log, expectedEvent)
}

func testRFC5424NoTimestmap(t *testing.T) {
	//nolint:lll
	log := `<165>4 - mymach.it e - 1 [ex@32473 iut="3"] An application event log entry...`

	expectedEvent := &RFC5424{
		Priority:  aws.Uint8(165),
		Facility:  aws.Uint8(20),
		Severity:  aws.Uint8(5),
		Version:   aws.Uint16(4),
		Timestamp: nil,
		Hostname:  aws.String("mymach.it"),
		Appname:   aws.String("e"),
		ProcID:    nil,
		MsgID:     aws.String("1"),
		Message:   aws.String("An application event log entry..."),
		StructuredData: &map[string]map[string]string{
			"ex@32473": {
				"iut": "3",
			},
		},
	}

	expectedEvent.AppendAnyDomainNamePtrs(expectedEvent.Hostname)

	// panther fields
	expectedEvent.PantherLogType = aws.String("Syslog.RFC5424")
	expectedEvent.PantherEventTime = nil

	checkRFC5424(t, log, expectedEvent)
}

func testRFC5424NoStructuredDataNoProcID(t *testing.T) {
	//nolint:lll
	log := `<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8`

	expectedTime, _ := time.Parse(time.RFC3339, "2003-10-11T22:14:15.003Z")

	expectedEvent := &RFC5424{
		Priority:       aws.Uint8(34),
		Facility:       aws.Uint8(4),
		Severity:       aws.Uint8(2),
		Version:        aws.Uint16(1),
		Timestamp:      (*timestamp.RFC3339)(&expectedTime),
		Hostname:       aws.String("mymachine.example.com"),
		Appname:        aws.String("su"),
		ProcID:         nil,
		MsgID:          aws.String("ID47"),
		Message:        aws.String("BOM'su root' failed for lonvick on /dev/pts/8"),
		StructuredData: nil,
	}

	expectedEvent.AppendAnyDomainNamePtrs(expectedEvent.Hostname)

	// panther fields
	expectedEvent.PantherLogType = aws.String("Syslog.RFC5424")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC5424(t, log, expectedEvent)
}

func testRFC5424NoStructuredDataNoMsgID(t *testing.T) {
	//nolint:lll
	log := `<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.`

	expectedTime, _ := time.Parse(time.RFC3339, "2003-08-24T05:14:15.000003-07:00")

	expectedEvent := &RFC5424{
		Priority:       aws.Uint8(165),
		Facility:       aws.Uint8(20),
		Severity:       aws.Uint8(5),
		Version:        aws.Uint16(1),
		Timestamp:      (*timestamp.RFC3339)(&expectedTime),
		Hostname:       aws.String("192.0.2.1"),
		Appname:        aws.String("myproc"),
		ProcID:         aws.String("8710"),
		MsgID:          nil,
		Message:        aws.String("%% It's time to make the do-nuts."),
		StructuredData: nil,
	}

	expectedEvent.AppendAnyIPAddressPtr(expectedEvent.Hostname)

	// panther fields
	expectedEvent.PantherLogType = aws.String("Syslog.RFC5424")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC5424(t, log, expectedEvent)
}

func testRFC5424WithStructuredData(t *testing.T) {
	//nolint:lll
	log := `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMAn application event log entry...`

	expectedTime, _ := time.Parse(time.RFC3339, "2003-10-11T22:14:15.003Z")

	expectedEvent := &RFC5424{
		Priority:  aws.Uint8(165),
		Facility:  aws.Uint8(20),
		Severity:  aws.Uint8(5),
		Version:   aws.Uint16(1),
		Timestamp: (*timestamp.RFC3339)(&expectedTime),
		Hostname:  aws.String("mymachine.example.com"),
		Appname:   aws.String("evntslog"),
		ProcID:    nil,
		MsgID:     aws.String("ID47"),
		Message:   aws.String("BOMAn application event log entry..."),
		StructuredData: &map[string]map[string]string{
			"exampleSDID@32473": {
				"iut":         "3",
				"eventSource": "Application",
				"eventID":     "1011",
			},
		},
	}

	expectedEvent.AppendAnyDomainNamePtrs(expectedEvent.Hostname)

	// panther fields
	expectedEvent.PantherLogType = aws.String("Syslog.RFC5424")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC5424(t, log, expectedEvent)
}

func testRFC5424StructuredDataOnly(t *testing.T) {
	//nolint:lll
	log := `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][examplePriority@32473 class="high"]`

	expectedTime, _ := time.Parse(time.RFC3339, "2003-10-11T22:14:15.003Z")

	expectedEvent := &RFC5424{
		Priority:  aws.Uint8(165),
		Facility:  aws.Uint8(20),
		Severity:  aws.Uint8(5),
		Version:   aws.Uint16(1),
		Timestamp: (*timestamp.RFC3339)(&expectedTime),
		Hostname:  aws.String("mymachine.example.com"),
		Appname:   aws.String("evntslog"),
		ProcID:    nil,
		MsgID:     aws.String("ID47"),
		Message:   nil,
		StructuredData: &map[string]map[string]string{
			"exampleSDID@32473": {
				"iut":         "3",
				"eventSource": "Application",
				"eventID":     "1011",
			},
			"examplePriority@32473": {
				"class": "high",
			},
		},
	}

	expectedEvent.AppendAnyDomainNamePtrs(expectedEvent.Hostname)

	// panther fields
	expectedEvent.PantherLogType = aws.String("Syslog.RFC5424")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC5424(t, log, expectedEvent)
}

func TestRFC5424Type(t *testing.T) {
	parser := &RFC5424Parser{}
	require.Equal(t, "Syslog.RFC5424", parser.LogType())
}

func checkRFC5424(t *testing.T, log string, expectedEvent *RFC5424) {
	expectedEvent.SetEvent(expectedEvent)
	logs, err := parserRFC5424.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), logs, err)
}
