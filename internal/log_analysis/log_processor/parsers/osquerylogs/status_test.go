package osquerylogs

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

func TestStatusLog(t *testing.T) {
	//nolint:lll
	log := `{"hostIdentifier":"jacks-mbp.lan","calendarTime":"Tue Nov 5 06:08:26 2018 UTC","unixTime":"1535731040","severity":"0","filename":"scheduler.cpp","line":"83","message":"Executing scheduled query pack_incident-response_arp_cache: select * from arp_cache;","version":"3.2.6","decorations":{"host_uuid":"37821E12-CC8A-5AA3-A90C-FAB28A5BF8F9","username":"user"},"log_type":"status"}`

	expectedTime := time.Unix(1541398106, 0).UTC()
	expectedEvent := &Status{
		HostIdentifier: aws.String("jacks-mbp.lan"),
		CalendarTime:   (*timestamp.ANSICwithTZ)(&expectedTime),
		UnixTime:       (*numerics.Integer)(aws.Int(1535731040)),
		Severity:       (*numerics.Integer)(aws.Int(0)),
		Filename:       aws.String("scheduler.cpp"),
		Line:           (*numerics.Integer)(aws.Int(83)),
		Message:        aws.String("Executing scheduled query pack_incident-response_arp_cache: select * from arp_cache;"),
		Version:        aws.String("3.2.6"),
		LogType:        aws.String("status"),
		Decorations: map[string]string{
			"host_uuid": "37821E12-CC8A-5AA3-A90C-FAB28A5BF8F9",
			"username":  "user",
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Osquery.Status")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	expectedEvent.AppendAnyDomainNames("jacks-mbp.lan")

	checkOsQueryStatusLog(t, log, expectedEvent)
}

func TestStatusLogNoLogType(t *testing.T) {
	//nolint:lll
	log := `{"hostIdentifier":"jaguar.local","calendarTime":"Tue Nov 5 06:08:26 2018 UTC","unixTime":"1535731040","severity":"0","filename":"tls.cpp","line":"253","message":"TLS/HTTPS POST request to URI: https://fleet.runpanther.tools:443/api/v1/osquery/log","version":"4.1.2","decorations":{"host_uuid":"97D8254F-7D98-56AE-91DB-924545EFXXXX","hostname":"jaguar.local"}}`

	expectedTime := time.Unix(1541398106, 0).UTC()
	expectedEvent := &Status{
		HostIdentifier: aws.String("jaguar.local"),
		CalendarTime:   (*timestamp.ANSICwithTZ)(&expectedTime),
		UnixTime:       (*numerics.Integer)(aws.Int(1535731040)),
		Severity:       (*numerics.Integer)(aws.Int(0)),
		Filename:       aws.String("tls.cpp"),
		Line:           (*numerics.Integer)(aws.Int(253)),
		Message:        aws.String("TLS/HTTPS POST request to URI: https://fleet.runpanther.tools:443/api/v1/osquery/log"),
		Version:        aws.String("4.1.2"),
		Decorations: map[string]string{
			"host_uuid": "97D8254F-7D98-56AE-91DB-924545EFXXXX",
			"hostname":  "jaguar.local",
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Osquery.Status")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	expectedEvent.AppendAnyDomainNames("jaguar.local")

	checkOsQueryStatusLog(t, log, expectedEvent)
}

func TestOsQueryStatusLogType(t *testing.T) {
	parser := &StatusParser{}
	require.Equal(t, "Osquery.Status", parser.LogType())
}

func checkOsQueryStatusLog(t *testing.T, log string, expectedEvent *Status) {
	expectedEvent.SetEvent(expectedEvent)
	parser := &StatusParser{}
	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
