package fluentdsyslogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestRFC5424(t *testing.T) {
	// nolint:lll
	log := `{"pri": 16, "host": "192.168.0.1", "ident": "fluentd", "pid": "11111", "msgid": "ID24224", "extradata": "[exampleSDID@20224 iut=\"3\" eventSource=\"Application\" eventID=\"11211\"]","message": "[error] Syslog test", "tag":"syslog.authpriv.info","time":"2020-03-23 16:14:06 +0000"}`

	expectedTime := time.Date(2020, 3, 23, 16, 14, 6, 0, time.UTC)
	expectedRFC5424 := &RFC5424{
		Priority:  aws.Uint8(16),
		Hostname:  aws.String("192.168.0.1"),
		Ident:     aws.String("fluentd"),
		ProcID:    (*numerics.Integer)(aws.Int(11111)),
		MsgID:     aws.String("ID24224"),
		ExtraData: aws.String("[exampleSDID@20224 iut=\"3\" eventSource=\"Application\" eventID=\"11211\"]"),
		Message:   aws.String("[error] Syslog test"),
		Tag:       aws.String("syslog.authpriv.info"),
		Timestamp: (*timestamp.FluentdTimestamp)(&expectedTime),
	}

	// panther fields
	expectedRFC5424.PantherLogType = aws.String("Fluentd.Syslog5424")
	expectedRFC5424.AppendAnyIPAddressPtr(expectedRFC5424.Hostname)
	expectedRFC5424.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkRFC5424(t, log, expectedRFC5424)
}

func TestRFC5424Domain(t *testing.T) {
	// nolint:lll
	log := `{"pri": 16, "host": "ip-192-168-0-1", "ident": "fluentd", "pid": "11111", "msgid": "ID24224", "extradata": "[exampleSDID@20224 iut=\"3\" eventSource=\"Application\" eventID=\"11211\"]","message": "[error] Syslog test", "tag":"syslog.authpriv.info","time":"2020-03-23 16:14:06 +0000"}`

	expectedTime := time.Date(2020, 3, 23, 16, 14, 6, 0, time.UTC)
	expectedRFC5424 := &RFC5424{
		Priority:  aws.Uint8(16),
		Hostname:  aws.String("ip-192-168-0-1"),
		Ident:     aws.String("fluentd"),
		ProcID:    (*numerics.Integer)(aws.Int(11111)),
		MsgID:     aws.String("ID24224"),
		ExtraData: aws.String("[exampleSDID@20224 iut=\"3\" eventSource=\"Application\" eventID=\"11211\"]"),
		Message:   aws.String("[error] Syslog test"),
		Tag:       aws.String("syslog.authpriv.info"),
		Timestamp: (*timestamp.FluentdTimestamp)(&expectedTime),
	}

	// panther fields
	expectedRFC5424.PantherLogType = aws.String("Fluentd.Syslog5424")
	expectedRFC5424.AppendAnyDomainNamePtrs(expectedRFC5424.Hostname)
	expectedRFC5424.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkRFC5424(t, log, expectedRFC5424)
}

func TestRFC5424TypeType(t *testing.T) {
	parser := &RFC5424Parser{}
	require.Equal(t, "Fluentd.Syslog5424", parser.LogType())
}

func checkRFC5424(t *testing.T, log string, expectedEvent *RFC5424) {
	expectedEvent.SetEvent(expectedEvent)
	parser := &RFC5424Parser{}
	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
