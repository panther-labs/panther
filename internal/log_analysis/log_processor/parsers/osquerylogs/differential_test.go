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

func TestDifferentialLog(t *testing.T) {
	//nolint:lll
	log := `{"name":"pack_incident-response_mounts","hostIdentifier":"Quans-MacBook-Pro-2.local","calendarTime":"Tue Nov 5 06:08:26 2018 UTC","unixTime":"1572934106","epoch":"0","counter":"62","logNumericsAsNumbers":"false","decorations":{"host_uuid":"F919E9BF-0BF1-5456-8F6C-335243AEA537"},"columns":{"blocks":"61202533"},"action":"added","log_type":"result"}`

	expectedTime := time.Unix(1541398106, 0).UTC()
	expectedEvent := &Differential{
		Action:               aws.String("added"),
		Name:                 aws.String("pack_incident-response_mounts"),
		Epoch:                (*numerics.Integer)(aws.Int(0)),
		HostIdentifier:       aws.String(("Quans-MacBook-Pro-2.local")),
		UnixTime:             (*numerics.Integer)(aws.Int(1572934106)),
		LogNumericsAsNumbers: aws.Bool(false),
		LogType:              aws.String("result"),
		CalendarTime:         (*timestamp.ANSICwithTZ)(&expectedTime),
		Columns: map[string]string{
			"blocks": "61202533",
		},
		Counter: (*numerics.Integer)(aws.Int(62)),
		Decorations: map[string]string{
			"host_uuid": "F919E9BF-0BF1-5456-8F6C-335243AEA537",
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Osquery.Differential")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	expectedEvent.AppendAnyDomainNames("Quans-MacBook-Pro-2.local")

	checkOsQueryDifferentialLog(t, log, expectedEvent)
}

func TestDifferentialLogWithExtraIps(t *testing.T) {
	//nolint:lll
	log := `{"name":"pack_incident-response_mounts","hostIdentifier":"Quans-MacBook-Pro-2.local","calendarTime":"Tue Nov 5 06:08:26 2018 UTC","unixTime":"1572934106","epoch":"0","counter":"62","logNumericsAsNumbers":"false","decorations":{"host_uuid":"F919E9BF-0BF1-5456-8F6C-335243AEA537"},"columns":{"blocks":"61202533", "local_address":"192.168.1.1", "remote_address":"192.168.1.2"},"action":"added","log_type":"result"}`

	expectedTime := time.Unix(1541398106, 0).UTC()
	expectedEvent := &Differential{
		Action:               aws.String("added"),
		Name:                 aws.String("pack_incident-response_mounts"),
		Epoch:                (*numerics.Integer)(aws.Int(0)),
		HostIdentifier:       aws.String(("Quans-MacBook-Pro-2.local")),
		UnixTime:             (*numerics.Integer)(aws.Int(1572934106)),
		LogNumericsAsNumbers: aws.Bool(false),
		LogType:              aws.String("result"),
		CalendarTime:         (*timestamp.ANSICwithTZ)(&expectedTime),
		Columns: map[string]string{
			"blocks":         "61202533",
			"local_address":  "192.168.1.1",
			"remote_address": "192.168.1.2",
		},
		Counter: (*numerics.Integer)(aws.Int(62)),
		Decorations: map[string]string{
			"host_uuid": "F919E9BF-0BF1-5456-8F6C-335243AEA537",
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Osquery.Differential")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	expectedEvent.AppendAnyDomainNames("Quans-MacBook-Pro-2.local")
	expectedEvent.AppendAnyIPAddress("192.168.1.1")
	expectedEvent.AppendAnyIPAddress("192.168.1.2")

	checkOsQueryDifferentialLog(t, log, expectedEvent)
}

func TestDifferentialLogWithoutLogNumericAsNumbers(t *testing.T) {
	//nolint:lll
	log := `{"action":"added","calendarTime":"Tue Nov 5 06:08:26 2018 UTC","columns":{"build_distro":"10.12"},"counter":"255","decorations":{"host_uuid":"37821E12-CC8A-5AA3-A90C-FAB28A5BF8F9" },"epoch":"0","hostIdentifier":"host.lan","log_type":"result","name":"pack_osquery-monitoring_osquery_info","unixTime":"1536682461"}`

	expectedTime := time.Unix(1541398106, 0).UTC()
	expectedEvent := &Differential{
		Action:         aws.String("added"),
		Name:           aws.String("pack_osquery-monitoring_osquery_info"),
		Epoch:          (*numerics.Integer)(aws.Int(0)),
		HostIdentifier: aws.String(("host.lan")),
		UnixTime:       (*numerics.Integer)(aws.Int(1536682461)),
		LogType:        aws.String("result"),
		CalendarTime:   (*timestamp.ANSICwithTZ)(&expectedTime),
		Columns: map[string]string{
			"build_distro": "10.12",
		},
		Counter: (*numerics.Integer)(aws.Int(255)),
		Decorations: map[string]string{
			"host_uuid": "37821E12-CC8A-5AA3-A90C-FAB28A5BF8F9",
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Osquery.Differential")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	expectedEvent.AppendAnyDomainNames("host.lan")

	checkOsQueryDifferentialLog(t, log, expectedEvent)
}

func TestDifferentialLogWithoutLogType(t *testing.T) {
	//nolint:lll
	log := `{"name":"pack/incident-response/listening_ports","hostIdentifier":"jaguar.local","calendarTime":"Tue Nov 5 06:08:26 2018 UTC","unixTime":"1536682461","epoch":0,"counter":33,"numerics":false,"decorations":{"host_uuid":"97D8254F-7D98-56AE-91DB-924545EFXXXX","hostname":"jaguar.local"},"columns":{"address":"0.0.0.0","family":"2","fd":"20","path":"","pid":"75165","port":"55596","protocol":"17","socket":"3276877798114717479"},"action":"added"}`
	expectedTime := time.Unix(1541398106, 0).UTC()
	expectedEvent := &Differential{
		Action:         aws.String("added"),
		Name:           aws.String("pack/incident-response/listening_ports"),
		Epoch:          (*numerics.Integer)(aws.Int(0)),
		HostIdentifier: aws.String(("jaguar.local")),
		UnixTime:       (*numerics.Integer)(aws.Int(1536682461)),
		CalendarTime:   (*timestamp.ANSICwithTZ)(&expectedTime),
		Columns: map[string]string{
			"address":  "0.0.0.0",
			"family":   "2",
			"fd":       "20",
			"path":     "",
			"pid":      "75165",
			"port":     "55596",
			"protocol": "17",
			"socket":   "3276877798114717479",
		},
		Counter: (*numerics.Integer)(aws.Int(33)),
		Decorations: map[string]string{
			"host_uuid": "97D8254F-7D98-56AE-91DB-924545EFXXXX",
			"hostname":  "jaguar.local",
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Osquery.Differential")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	expectedEvent.AppendAnyDomainNames("jaguar.local")

	checkOsQueryDifferentialLog(t, log, expectedEvent)
}

func TestOsQueryDifferentialLogType(t *testing.T) {
	parser := &DifferentialParser{}
	require.Equal(t, "Osquery.Differential", parser.LogType())
}

func checkOsQueryDifferentialLog(t *testing.T, log string, expectedEvent *Differential) {
	expectedEvent.SetEvent(expectedEvent)
	parser := &DifferentialParser{}
	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
