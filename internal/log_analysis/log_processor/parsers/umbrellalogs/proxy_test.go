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

// nolint:lll
func TestProxyParser(t *testing.T) {
	log := `"2017-10-02 23:52:53","TheComputerName","ActiveDirectoryUserName,ADSite,Network","192.192.192.135","1.1.1.91","1.1.1.92","","ALLOWED","http://google.com/the.js","www.google.com","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36","200","562","1489","1500","","","","","","","","Networks"`
	tm := time.Date(2017, 10, 02, 23, 52, 53, 0, time.UTC)
	event := Proxy{
		Timestamp: timestamp.RFC3339(tm),
		Identity:  "TheComputerName",
		Identities: []string{
			"ActiveDirectoryUserName",
			"ADSite",
			"Network",
		},
		InternalIP:       "192.192.192.135",
		ExternalIP:       "1.1.1.91",
		DestinationIP:    "1.1.1.92",
		Verdict:          "ALLOWED",
		URL:              "http://google.com/the.js",
		Referer:          "www.google.com",
		UserAgent:        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
		StatusCode:       200,
		RequestSize:      562,
		ResponseSize:     1489,
		ResponseBodySize: 1500,
		IdentityType:     "Networks",
	}
	event.SetCoreFields(TypeProxy, (*timestamp.RFC3339)(&tm), &event)
	event.AppendAnyIPAddress("192.192.192.135")
	event.AppendAnyIPAddress("1.1.1.91")
	event.AppendAnyIPAddress("1.1.1.92")
	testutil.CheckPantherParser(t, log, NewProxyParser(), &event.PantherLog)
}
