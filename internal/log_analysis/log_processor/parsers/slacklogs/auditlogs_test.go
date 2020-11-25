package slacklogs

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

func TestAuditParser(t *testing.T) {
	// nolint:lll
	log := `{
         "id":"0123a45b-6c7d-8900-e12f-3456789gh0i1",
         "date_create":1521214343,
         "action":"user_login",
         "actor":{
            "type":"user",
            "user":{
               "id":"W123AB456",
               "name":"Charlie Parker",
               "email":"bird@slack.com"
            }
         },
         "entity":{
            "type":"user",
            "user":{
               "id":"W123AB456",
               "name":"Charlie Parker",
               "email":"bird@slack.com"
            }
         },
         "context":{
            "location":{
               "type":"enterprise",
               "id":"E1701NCCA",
               "name":"Birdland",
               "domain":"birdland"
            },
            "ua":"Mozilla\/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/64.0.3282.186 Safari\/537.36",
            "ip_address":"1.23.45.678"
         }
    }`
	tm := time.Date(2018, 3, 16, 15, 32, 23, 0, time.UTC)
	event := AuditLog{
		ID:         "0123a45b-6c7d-8900-e12f-3456789gh0i1",
		DateCreate: timestamp.UnixFloat(tm),
		Action:     "user_login",
		Actor: Actor{
			Type: "user",
			User: User{
				ID:    "W123AB456",
				Name:  "Charlie Parker",
				Email: "bird@slack.com",
			},
		},
		Entity: Entity{
			Type: "user",
			User: &User{
				ID:    "W123AB456",
				Name:  "Charlie Parker",
				Email: "bird@slack.com",
			},
		},
		Context: Context{
			UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36",
			IPAddress: "1.23.45.678",
			Location: Location{
				Type:   "enterprise",
				ID:     "E1701NCCA",
				Name:   "Birdland",
				Domain: "birdland",
			},
		},
	}
	event.SetCoreFields(TypeAuditLogs, (*timestamp.RFC3339)(&tm), &event)
	event.AppendAnyIPAddress(event.Context.IPAddress)
	testutil.CheckPantherParser(t, log, &AuditParser{}, &event.PantherLog)
}
