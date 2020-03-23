package sysloglogs

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
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var parserRFC3164 parsers.LogParser

func TestRFC3164(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))
	syslogRFC3164 := &RFC3164Parser{}
	parserRFC3164 = syslogRFC3164.New()

	t.Run("Simple", testRFC3164Simple)
	t.Run("WithRFC3339Timestamp", testRFC3164WithRFC3339Timestamp)
	t.Run("Example1", testRFC3164Example1)
	t.Run("Example2", testRFC3164Example2)
	t.Run("Example3", testRFC3164Example3)
}

func testRFC3164Simple(t *testing.T) {
	//nolint:lll
	log := `<13>Dec  2 16:31:03 host app: Test`

	expectedTime := time.Date(time.Now().UTC().Year(), 12, 2, 16, 31, 03, 0, time.UTC)

	expectedEvent := &RFC3164{
		Priority:  aws.Uint8(13),
		Facility:  aws.Uint8(1),
		Severity:  aws.Uint8(5),
		Timestamp: (*timestamp.RFC3339)(&expectedTime),
		Hostname:  aws.String("host"),
		Appname:   aws.String("app"),
		ProcID:    nil,
		MsgID:     nil,
		Message:   aws.String("Test"),
	}

	expectedEvent.AppendAnyDomainNamePtrs(expectedEvent.Hostname)

	// panther fields
	expectedEvent.PantherLogType = aws.String("Syslog.RFC3164")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC3164(t, log, expectedEvent)
}

func testRFC3164WithRFC3339Timestamp(t *testing.T) {
	//nolint:lll
	log := `<28>2019-12-02T16:49:23+02:00 host app[23410]: Test`

	expectedTime, _ := time.Parse(time.RFC3339, "2019-12-02T16:49:23+02:00")

	expectedEvent := &RFC3164{
		Priority:  aws.Uint8(28),
		Facility:  aws.Uint8(3),
		Severity:  aws.Uint8(4),
		Timestamp: (*timestamp.RFC3339)(&expectedTime),
		Hostname:  aws.String("host"),
		Appname:   aws.String("app"),
		ProcID:    aws.String("23410"),
		MsgID:     nil,
		Message:   aws.String("Test"),
	}

	expectedEvent.AppendAnyDomainNamePtrs(expectedEvent.Hostname)

	// panther fields
	expectedEvent.PantherLogType = aws.String("Syslog.RFC3164")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC3164(t, log, expectedEvent)
}

// Example1 from https://tools.ietf.org/html/rfc3164#section-5.4
func testRFC3164Example1(t *testing.T) {
	//nolint:lll
	log := `<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8`

	expectedTime := time.Date(time.Now().UTC().Year(), 10, 11, 22, 14, 15, 0, time.UTC)

	expectedEvent := &RFC3164{
		Priority:  aws.Uint8(34),
		Facility:  aws.Uint8(4),
		Severity:  aws.Uint8(2),
		Timestamp: (*timestamp.RFC3339)(&expectedTime),
		Hostname:  aws.String("mymachine"),
		Appname:   aws.String("su"),
		ProcID:    nil,
		MsgID:     nil,
		Message:   aws.String("'su root' failed for lonvick on /dev/pts/8"),
	}

	expectedEvent.AppendAnyDomainNamePtrs(expectedEvent.Hostname)

	// panther fields
	expectedEvent.PantherLogType = aws.String("Syslog.RFC3164")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC3164(t, log, expectedEvent)
}

// Example2 from https://tools.ietf.org/html/rfc3164#section-5.4
func testRFC3164Example2(t *testing.T) {
	//nolint:lll
	log := `<13>Feb  5 17:32:18 10.0.0.99 Use the BFG!`

	expectedTime := time.Date(time.Now().UTC().Year(), 2, 5, 17, 32, 18, 0, time.UTC)

	expectedEvent := &RFC3164{
		Priority:  aws.Uint8(13),
		Facility:  aws.Uint8(1),
		Severity:  aws.Uint8(5),
		Timestamp: (*timestamp.RFC3339)(&expectedTime),
		Hostname:  aws.String("10.0.0.99"),
		Appname:   nil,
		ProcID:    nil,
		MsgID:     nil,
		Message:   aws.String("Use the BFG!"),
	}

	expectedEvent.AppendAnyIPAddressPtrs(expectedEvent.Hostname)

	// panther fields
	expectedEvent.PantherLogType = aws.String("Syslog.RFC3164")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC3164(t, log, expectedEvent)
}

// Example3 from https://tools.ietf.org/html/rfc3164#section-5.4
func testRFC3164Example3(t *testing.T) {
	//nolint:lll
	log := `<165>Aug 24 05:34:00 CST 1987 mymachine myproc[10]: %% It's time to make the do-nuts %%`

	expectedTime := time.Date(time.Now().UTC().Year(), 8, 24, 5, 34, 0, 0, time.UTC)

	expectedEvent := &RFC3164{
		Priority:  aws.Uint8(165),
		Facility:  aws.Uint8(20),
		Severity:  aws.Uint8(5),
		Timestamp: (*timestamp.RFC3339)(&expectedTime),
		Hostname:  aws.String("CST"),
		Appname:   nil,
		ProcID:    nil,
		MsgID:     nil,
		Message:   aws.String("1987 mymachine myproc[10]: %% It's time to make the do-nuts %%"),
	}

	expectedEvent.AppendAnyDomainNamePtrs(expectedEvent.Hostname)

	// panther fields
	expectedEvent.PantherLogType = aws.String("Syslog.RFC3164")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC3164(t, log, expectedEvent)
}

func TestRFC3164Type(t *testing.T) {
	parser := &RFC3164Parser{}
	require.Equal(t, "Syslog.RFC3164", parser.LogType())
}

func checkRFC3164(t *testing.T, log string, expectedEvent *RFC3164) {
	testutil.EqualPantherLog(t, expectedEvent.Log(), parserRFC3164.Parse(log))
}
