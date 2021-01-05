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

func TestAuditParserParse(t *testing.T) {
	t.Run("Login", func(t *testing.T) {
		log := `Jan 22 16:14:23 my-jwas [mws-audit][INFO] [mykonos] [10.10.0.117] Logged in successfully`
		now := time.Now()
		tm := expectedTestDate(time.Date(now.Year(), 1, 22, 16, 14, 23, 0, time.UTC))
		event := Audit{
			Timestamp: timestamp.RFC3339(tm),
			Hostname:  "my-jwas",
			LogLevel:  "INFO",
			Username:  aws.String("mykonos"),
			LoginIP:   aws.String("10.10.0.117"),
			Message:   "Logged in successfully",
		}

		event.SetCoreFields(TypeAudit, (*timestamp.RFC3339)(&tm), &event)
		event.AppendAnyIPAddress("10.10.0.117")
		testutil.CheckPantherParser(t, log, NewAuditParser(), &event.PantherLog)
	})
	t.Run("Response deactivation", func(t *testing.T) {
		// nolint:lll
		log := `Jan 23 19:16:22 my-jwas [mws-audit][INFO] [ea77722a8516b0d1135abb19b1982852] Deactivate response 1832840420318015488`
		now := time.Now()
		tm := expectedTestDate(time.Date(now.Year(), 1, 23, 19, 16, 22, 0, time.UTC))
		event := Audit{
			Timestamp: timestamp.RFC3339(tm),
			Hostname:  "my-jwas",
			LogLevel:  "INFO",
			APIKey:    aws.String("ea77722a8516b0d1135abb19b1982852"),
			Message:   "Deactivate response 1832840420318015488",
		}

		event.SetCoreFields(TypeAudit, (*timestamp.RFC3339)(&tm), &event)
		testutil.CheckPantherParser(t, log, NewAuditParser(), &event.PantherLog)
	})
	t.Run("Configuration change", func(t *testing.T) {
		// nolint:lll
		log := `Feb 14 19:02:54 my-jwas [mws-audit][INFO][mykonos] Changed configuration parameters: services.spotlight.enabled, services.spotlight.server_address`
		now := time.Now()
		tm := expectedTestDate(time.Date(now.Year(), 2, 14, 19, 2, 54, 0, time.UTC))
		event := Audit{
			Timestamp: timestamp.RFC3339(tm),
			Hostname:  "my-jwas",
			LogLevel:  "INFO",
			Username:  aws.String("mykonos"),
			Message:   "Changed configuration parameters: services.spotlight.enabled, services.spotlight.server_address",
		}

		event.SetCoreFields(TypeAudit, (*timestamp.RFC3339)(&tm), &event)
		testutil.CheckPantherParser(t, log, NewAuditParser(), &event.PantherLog)
	})
}
