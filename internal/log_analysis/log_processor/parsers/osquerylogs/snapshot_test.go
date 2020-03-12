package osquerylogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestSnapshotLog(t *testing.T) {
	//nolint:lll
	log := `{"action": "snapshot","snapshot": [{"parent": "0","path": "/sbin/launchd","pid": "1"}],"name": "process_snapshot","hostIdentifier": "hostname.local","calendarTime": "Tue Nov 5 06:08:26 2018 UTC","unixTime": "1462228052","epoch": "314159265","counter": "1","numerics": false}`

	expectedTime := time.Unix(1541398106, 0).UTC()
	expectedEvent := &Snapshot{
		Action:         aws.String("snapshot"),
		Name:           aws.String("process_snapshot"),
		Epoch:          aws.Int(314159265),
		HostIdentifier: aws.String(("hostname.local")),
		UnixTime:       aws.Int(1462228052),
		CalendarTime:   (*timestamp.ANSICwithTZ)(&expectedTime),
		Counter:        aws.Int(1),
		Snapshot: []map[string]string{
			{
				"parent": "0",
				"path":   "/sbin/launchd",
				"pid":    "1",
			},
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Osquery.Snapshot")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	expectedEvent.AppendAnyDomainNames("hostname.local")

	checkOsQuerySnapshotLog(t, log, expectedEvent)
}

func TestOsQuerySnapshotLogType(t *testing.T) {
	parser := &SnapshotParser{}
	require.Equal(t, "Osquery.Snapshot", parser.LogType())
}

func checkOsQuerySnapshotLog(t *testing.T, log string, expectedEvent *Snapshot) {
	parser := &SnapshotParser{}
	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}
