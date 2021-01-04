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

// nolint: lll
func TestFirewallParserTCP(t *testing.T) {
	log := `Mar 19 18:49:32 myjwas kernel: IPTABLES Dropped: IN=eth0 OUT= MAC=00:0c:29:cf:4d:c8:2c:21:72:c6:99:08:08:00 SRC=10.10.0.117 DST=10.20.0.53 LEN=40 TOS=0x00 PREC=0x00 TTL=63 ID=51749 DF PROTO=TCP SPT=51093 DPT=5000 WINDOW=0 RES=0x00 RST URGP=0`
	now := time.Now()
	tm := expectedTestDate(time.Date(now.Year(), 3, 19, 18, 49, 32, 0, time.UTC))
	event := Firewall{
		Timestamp: timestamp.RFC3339(tm),
		Event:     "Dropped",
		Hostname:  "myjwas",
		IPTables: IPTables{
			MACAddress:      "00:0c:29:cf:4d:c8:2c:21:72:c6:99:08:08:00",
			Input:           "eth0",
			SourceIP:        "10.10.0.117",
			SourcePort:      51093,
			DestinationIP:   "10.20.0.53",
			DestinationPort: 5000,
			PacketLength:    40,
			TypeOfService:   "0x00",
			Precedence:      "0x00",
			PacketTTL:       63,
			PacketID:        51749,
			Protocol:        "TCP",
			WindowSize:      0,
			RST:             true,
			DoNotFragment:   true,
		},
	}
	event.SetCoreFields(TypeFirewall, &event.Timestamp, &event)
	event.AppendAnyIPAddress("10.10.0.117")
	event.AppendAnyIPAddress("10.20.0.53")
	testutil.CheckPantherParser(t, log, NewFirewallParser(), &event.PantherLog)
}
