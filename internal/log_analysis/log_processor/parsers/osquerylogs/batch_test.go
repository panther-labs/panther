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

func TestBatchLog(t *testing.T) {
	//nolint:lll
	log := `{"diffResults": {"added": [ { "name": "osqueryd", "path": "/usr/local/bin/osqueryd", "pid": "97830" } ],"removed": [ { "name": "osqueryd", "path": "/usr/local/bin/osqueryd", "pid": "97650" } ] },"name": "processes", "hostname": "hostname.local", "calendarTime": "Tue Nov 5 06:08:26 2018 UTC","unixTime": "1412123850", "epoch": "314159265", "counter": "1" }`

	expectedTime := time.Unix(1541398106, 0).UTC()
	expectedEvent := &Batch{
		CalendarTime: (*timestamp.ANSICwithTZ)(&expectedTime),
		Name:         aws.String("processes"),
		Epoch:        aws.Int(314159265),
		Hostname:     aws.String(("hostname.local")),
		UnixTime:     aws.Int(1412123850),
		Counter:      aws.Int(1),
		DiffResults: &BatchDiffResults{
			Added: []map[string]string{
				{
					"name": "osqueryd",
					"path": "/usr/local/bin/osqueryd",
					"pid":  "97830",
				},
			},
			Removed: []map[string]string{
				{
					"name": "osqueryd",
					"path": "/usr/local/bin/osqueryd",
					"pid":  "97650",
				},
			},
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Osquery.Batch")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	expectedEvent.AppendAnyDomainNames("hostname.local")

	checkOsQueryBatcLog(t, log, expectedEvent)
}

func TestOsQueryBatchLogType(t *testing.T) {
	parser := &BatchParser{}
	require.Equal(t, "Osquery.Batch", parser.LogType())
}

func checkOsQueryBatcLog(t *testing.T, log string, expectedEvent *Batch) {
	parser := &BatchParser{}
	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}
