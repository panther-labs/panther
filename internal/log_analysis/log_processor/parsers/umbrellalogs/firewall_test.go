package umbrellalogs

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

//nolint:lll
func TestCloudFirewallParser(t *testing.T) {
	log := `"2019-01-14 18:03:46","[211039844]","Passive Monitor","CDFW Tunnel Device","OUTBOUND","1","84","172.17.3.4","","146.112.255.129","","ams1.edc","12","ALLOW"`
	tm := time.Date(2019, 1, 14, 18, 03, 46, 0, time.UTC)
	event := CloudFirewall{
		Timestamp:       timestamp.RFC3339(tm),
		OriginID:        "[211039844]",
		Identity:        "Passive Monitor",
		IdentityType:    "CDFW Tunnel Device",
		Direction:       "OUTBOUND",
		IPProtocol:      1,
		PacketSize:      84,
		SourceIP:        "172.17.3.4",
		SourcePort:      0,
		DestinationIP:   "146.112.255.129",
		DestinationPort: 0,
		DataCenter:      "ams1.edc",
		RuleID:          "12",
		Verdict:         "ALLOW",
	}
	event.SetCoreFields(TypeCloudFirewall, (*timestamp.RFC3339)(&tm), &event)
	event.AppendAnyIPAddress("172.17.3.4")
	event.AppendAnyIPAddress("146.112.255.129")
	testutil.CheckPantherParser(t, log, NewCloudFirewallParser(), &event.PantherLog)
}
