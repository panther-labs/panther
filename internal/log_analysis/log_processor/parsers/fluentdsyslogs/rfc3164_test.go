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

func TestRFC3164(t *testing.T) {
	// nolint:lll
	log := `{"pri":6,"host":"ip-172-31-84-73","pid":"11111","ident":"sudo","message":"pam_unix(sudo:session): session closed for user root","tag":"syslog.authpriv.info","time":"2020-03-23 16:14:06 +0000"}`

	expectedTime := time.Date(2020, 3, 23, 16, 14, 6, 0, time.UTC)
	expectedRFC3164 := &RFC3164{
		Priority:  aws.Uint8(6),
		Hostname:  aws.String("ip-172-31-84-73"),
		Ident:     aws.String("sudo"),
		ProcID:    (*numerics.Integer)(aws.Int(11111)),
		Message:   aws.String("pam_unix(sudo:session): session closed for user root"),
		Tag:       aws.String("syslog.authpriv.info"),
		Timestamp: (*timestamp.FluentdTimestamp)(&expectedTime),
	}

	// panther fields
	expectedRFC3164.PantherLogType = aws.String("Fluentd.Syslog3164")
	expectedRFC3164.AppendAnyDomainNamePtrs(expectedRFC3164.Hostname)
	expectedRFC3164.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC3164(t, log, expectedRFC3164)
}

func TestRFC3164WithoutPriority(t *testing.T) {
	// nolint:lll
	log := `{"host":"ip-172-31-91-66","ident":"systemd-timesyncd","message":"Network configuration changed, trying to establish connection.","tag":"syslog.cron.info","time":"2020-03-23 16:14:06 +0000"}`

	expectedTime := time.Date(2020, 3, 23, 16, 14, 6, 0, time.UTC)
	expectedEvent := &RFC3164{
		Hostname:  aws.String("ip-172-31-91-66"),
		Ident:     aws.String("systemd-timesyncd"),
		Message:   aws.String("Network configuration changed, trying to establish connection."),
		Tag:       aws.String("syslog.cron.info"),
		Timestamp: (*timestamp.FluentdTimestamp)(&expectedTime),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Fluentd.Syslog3164")
	expectedEvent.AppendAnyDomainNamePtrs(expectedEvent.Hostname)
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC3164(t, log, expectedEvent)
}

func TestRFC3164SSHMessage(t *testing.T) {
	// nolint:lll
	log := `{"host":"ip-172-31-33-197","ident":"sshd","pid":"5433","message":"Accepted publickey for ubuntu from 150.18.226.10 port 54717 ssh2: RSA SHA256:u...","tag":"syslog.auth.info","time":"2020-04-19 20:20:05 +0000"}`

	expectedTime := time.Date(2020, 4, 19, 20, 20, 5, 0, time.UTC)
	expectedEvent := &RFC3164{
		Hostname:  aws.String("ip-172-31-33-197"),
		Ident:     aws.String("sshd"),
		ProcID:    (*numerics.Integer)(aws.Int(5433)),
		Message:   aws.String("Accepted publickey for ubuntu from 150.18.226.10 port 54717 ssh2: RSA SHA256:u..."),
		Tag:       aws.String("syslog.auth.info"),
		Timestamp: (*timestamp.FluentdTimestamp)(&expectedTime),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Fluentd.Syslog3164")
	expectedEvent.AppendAnyDomainNamePtrs(expectedEvent.Hostname)
	expectedEvent.AppendAnyIPAddressInFieldPtr(expectedEvent.Message)
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)

	checkRFC3164(t, log, expectedEvent)
}

func TestRFC3164TypeType(t *testing.T) {
	parser := &RFC3164Parser{}
	require.Equal(t, "Fluentd.Syslog3164", parser.LogType())
}

func checkRFC3164(t *testing.T, log string, expectedEvent *RFC3164) {
	expectedEvent.SetEvent(expectedEvent)
	parser := &RFC3164Parser{}
	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
