package juniperlogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestMWSParser_Parse(t *testing.T) {
	t.Run("Service with component", func(t *testing.T) {
		log := `Mar 19 18:42:38 my-jwas-instance [INFO][mws-cluster-services][db-cleanup] Database cleanup completed. Removed record count: 0`
		now := time.Now()
		tm := expectedTestDate(time.Date(now.Year(), time.March, 19, 18, 42, 38, 0, time.UTC))
		event := MWS{
			Timestamp:        timestamp.RFC3339(tm),
			Hostname:         "my-jwas-instance",
			LogLevel:         aws.String("INFO"),
			ServiceName:      "mws-cluster-services",
			ServiceComponent: aws.String("db-cleanup"),
			Message:          "Database cleanup completed. Removed record count: 0",
		}
		event.SetCoreFields(TypeMWS, (*timestamp.RFC3339)(&tm), &event)
		testutil.CheckPantherParser(t, log, NewMWSParser(), &event.PantherLog)
	})
	t.Run("UI", func(t *testing.T) {
		log := `Mar 19 19:42:16 my-jwas-instance [mws-ui]: spawned uWSGI worker 1 (pid: 11209, cores: 1)`
		now := time.Now()
		tm := expectedTestDate(time.Date(now.Year(), time.March, 19, 19, 42, 16, 0, time.UTC))
		event := MWS{
			Timestamp:   timestamp.RFC3339(tm),
			Hostname:    "my-jwas-instance",
			ServiceName: "mws-ui",
			Message:     "spawned uWSGI worker 1 (pid: 11209, cores: 1)",
		}
		event.SetCoreFields(TypeMWS, (*timestamp.RFC3339)(&tm), &event)
		testutil.CheckPantherParser(t, log, NewMWSParser(), &event.PantherLog)
	})
	t.Run("Service without component", func(t *testing.T) {
		log := `Mar 19 20:18:26 my-jwas-instance [INFO][mws-security-engine] Server startup in 3080 ms`
		now := time.Now()
		tm := expectedTestDate(time.Date(now.Year(), time.March, 19, 20, 18, 26, 0, time.UTC))
		event := MWS{
			Timestamp:   timestamp.RFC3339(tm),
			Hostname:    "my-jwas-instance",
			LogLevel:    aws.String("INFO"),
			ServiceName: "mws-security-engine",
			Message:     "Server startup in 3080 ms",
		}
		event.SetCoreFields(TypeMWS, (*timestamp.RFC3339)(&tm), &event)
		testutil.CheckPantherParser(t, log, NewMWSParser(), &event.PantherLog)
	})
}
