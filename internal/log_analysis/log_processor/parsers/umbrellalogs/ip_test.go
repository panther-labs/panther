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
func TestIPParser(t *testing.T) {
	log := `"2017-10-02 19:58:12","TheComputerName","198.198.198.1","55605","107.152.24.219","443","Unauthorized IP Tunnel Access","Roaming Computers"`
	tm := time.Date(2017, 10, 2, 19, 58, 12, 0, time.UTC)
	event := IP{
		Timestamp:       timestamp.RFC3339(tm),
		Identity:        "TheComputerName",
		SourceIP:        "198.198.198.1",
		SourcePort:      55605,
		DestinationIP:   "107.152.24.219",
		DestinationPort: 443,
		Categories:      []string{"Unauthorized IP Tunnel Access"},
		IdentityTypes:   []string{"Roaming Computers"},
	}
	event.SetCoreFields(TypeIP, (*timestamp.RFC3339)(&tm), &event)
	event.AppendAnyIPAddress("198.198.198.1")
	event.AppendAnyIPAddress("107.152.24.219")
	testutil.CheckPantherParser(t, log, NewIPParser(), &event.PantherLog)
}
