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

func TestAccessParser_Parse(t *testing.T) {
	log := testutil.MustReadFileString(`testdata/access_samples.log`)
	now := time.Now()
	tm1 := expectedTestDate(time.Date(now.Year(), time.March, 19, 21, 11, 47, 0, time.UTC))
	event1 := Access{
		Timestamp:     timestamp.RFC3339(tm1),
		Hostname:      `webappsecure`,
		LogLevel:      `INFO`,
		Thread:        `se-request-6`,
		RequestKey:    `da5a23dd-8367-476e-97ca-d734ab56244d`,
		PacketType:    `REQUEST`,
		PacketStage:   `PRE`,
		ProxyClientIP: `127.0.0.1`,
		URL:           `http://zach-vm.jwas.jsec.net:80/genericelectronics`,
	}
	event1.SetCoreFields(TypeAccess, (*timestamp.RFC3339)(&tm1), &event1)
	event1.AppendAnyIPAddress(`127.0.0.1`)
	tm2 := expectedTestDate(time.Date(now.Year(), time.March, 19, 19, 48, 14, 0, time.UTC))
	event2 := Access{
		Timestamp:     timestamp.RFC3339(tm2),
		Hostname:      `webappsecure`,
		LogLevel:      `INFO`,
		Thread:        `se-request-25`,
		RequestKey:    `12521298-13f1-4019-8e21-c6046cf2dac7`,
		PacketType:    `REQUEST`,
		PacketStage:   `POST`,
		ProxyClientIP: `127.0.0.1`,
		URL:           `http://10.20.0.53:80/`,
	}
	event2.SetCoreFields(TypeAccess, (*timestamp.RFC3339)(&tm2), &event2)
	event2.AppendAnyIPAddress(`127.0.0.1`)
	tm3 := expectedTestDate(time.Date(now.Year(), time.March, 19, 19, 48, 14, 0, time.UTC))
	event3 := Access{
		Timestamp:     timestamp.RFC3339(tm3),
		Hostname:      `webappsecure`,
		LogLevel:      `INFO`,
		Thread:        `se-request-13`,
		RequestKey:    `cfde0089-2b93-4bad-a8f5-555ac29ef4b6`,
		PacketType:    `REQUEST`,
		PacketStage:   `POST`,
		ProxyClientIP: `127.0.0.1`,
		URL:           `http://10.20.0.53:80/`,
	}
	event3.SetCoreFields(TypeAccess, (*timestamp.RFC3339)(&tm3), &event3)
	event3.AppendAnyIPAddress(`127.0.0.1`)
	testutil.CheckPantherMultiline(t, log, NewAccessParser(), &event1.PantherLog, &event2.PantherLog, &event3.PantherLog)
}
