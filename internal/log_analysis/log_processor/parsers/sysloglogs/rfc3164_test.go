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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/logs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestRFC3164Simple(t *testing.T) {
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
	testutil.CheckPantherEvent(t, expectedEvent, TypeRFC3164, expectedEvent.Timestamp.UTC(),
		logs.DomainName("host"),
	)
	testutil.CheckParser(t, log, TypeRFC3164, expectedEvent)
}

func TestRFC3164WithRFC3339Timestamp(t *testing.T) {
	//nolint:lll
	log := `<28>2019-12-02T16:49:23+02:00 host app[23410]: Test`

	tm, _ := time.Parse(time.RFC3339, "2019-12-02T16:49:23+02:00")

	event := &RFC3164{
		Priority:  aws.Uint8(28),
		Facility:  aws.Uint8(3),
		Severity:  aws.Uint8(4),
		Timestamp: (*timestamp.RFC3339)(&tm),
		Hostname:  aws.String("host"),
		Appname:   aws.String("app"),
		ProcID:    aws.String("23410"),
		MsgID:     nil,
		Message:   aws.String("Test"),
	}
	testutil.CheckPantherEvent(t, event, TypeRFC3164, event.Timestamp.UTC(),
		logs.DomainName("host"),
	)
	testutil.CheckParser(t, log, TypeRFC3164, event)
}

// Example1 from https://tools.ietf.org/html/rfc3164#section-5.4
func TestRFC3164Example1(t *testing.T) {
	//nolint:lll
	log := `<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8`

	tm := time.Date(time.Now().UTC().Year(), 10, 11, 22, 14, 15, 0, time.UTC)

	event := &RFC3164{
		Priority:  aws.Uint8(34),
		Facility:  aws.Uint8(4),
		Severity:  aws.Uint8(2),
		Timestamp: (*timestamp.RFC3339)(&tm),
		Hostname:  aws.String("mymachine"),
		Appname:   aws.String("su"),
		ProcID:    nil,
		MsgID:     nil,
		Message:   aws.String("'su root' failed for lonvick on /dev/pts/8"),
	}
	testutil.CheckPantherEvent(t, event, TypeRFC3164, event.Timestamp.UTC(),
		logs.DomainName("mymachine"),
	)
	testutil.CheckParser(t, log, TypeRFC3164, event)
}

// Example2 from https://tools.ietf.org/html/rfc3164#section-5.4
func TestRFC3164Example2(t *testing.T) {
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

	testutil.CheckPantherEvent(t, expectedEvent, TypeRFC3164, expectedEvent.Timestamp.UTC(),
		logs.IPAddress("10.0.0.99"),
	)
	testutil.CheckParser(t, log, TypeRFC3164, expectedEvent)
}

// Example3 from https://tools.ietf.org/html/rfc3164#section-5.4
func TestRFC3164Example3(t *testing.T) {
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

	testutil.CheckPantherEvent(t, expectedEvent, TypeRFC3164, expectedEvent.Timestamp.UTC(),
		logs.DomainName("CST"),
	)
	testutil.CheckParser(t, log, TypeRFC3164, expectedEvent)
}
