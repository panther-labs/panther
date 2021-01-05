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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestPostgresParser_Parse(t *testing.T) {
	// nolint:lll
	log := `Feb 24 14:58:08 webappsecure postgres[7694]: [10-1] 42701 530b5e00.1e0e ERROR: column "requests" of relation "sessiongroup" already exists`
	now := time.Now()
	tm := expectedTestDate(time.Date(now.Year(), time.February, 24, 14, 58, 8, 0, time.UTC))
	event := Postgres{
		Timestamp:    timestamp.RFC3339(tm),
		Hostname:     "webappsecure",
		PID:          7694,
		GroupIDMajor: 10,
		GroupIDMinor: 1,
		SQLErrorCode: "42701",
		SessionID:    "530b5e00.1e0e",
		MessageType:  "ERROR",
		Message:      `column "requests" of relation "sessiongroup" already exists`,
	}
	event.SetCoreFields(TypePostgres, (*timestamp.RFC3339)(&tm), &event)
	testutil.CheckPantherParser(t, log, NewPostgresParser(), &event.PantherLog)
}
