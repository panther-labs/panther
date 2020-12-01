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
	"fmt"
	"testing"
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// nolint:lll
func TestDNSParser(t *testing.T) {
	type testCase struct {
		Log     string
		Event   DNS
		IPs     []string
		Domain  string
		Time    time.Time
		WantErr bool
	}
	for i, tc := range []testCase{
		{
			Log: `"2015-01-16 17:48:41","ActiveDirectoryUserName","ActiveDirectoryUserName,ADSite,Network","10.10.1.100","24.123.132.133","Allowed","1 (A)","NOERROR","domain-visited.com.","Chat,Photo Sharing,Social Networking,Allow List"`,
			Event: DNS{
				PolicyIdentity: "ActiveDirectoryUserName",
				Identities: []string{
					"ActiveDirectoryUserName",
					"ADSite",
					"Network",
				},
				InternalIP:   "10.10.1.100",
				ExternalIP:   "24.123.132.133",
				Action:       "Allowed",
				QueryType:    "1 (A)",
				ResponseCode: "NOERROR",
				Domain:       "domain-visited.com.",
				Categories: []string{
					"Chat",
					"Photo Sharing",
					"Social Networking",
					"Allow List",
				},
			},
			IPs: []string{
				"10.10.1.100",
				"24.123.132.133",
			},
			Domain:  "domain-visited.com",
			Time:    time.Date(2015, 1, 16, 17, 48, 41, 0, time.UTC),
			WantErr: false,
		},
		{
			Log: `"2020-05-21 04:16:07","340 Fremont","340 Fremont","75.21.22.23","75.21.22.23","Allowed","1 (A)","NOERROR","docs.google.com.","File Storage,SaaS and B2B,Application","Networks","Networks",""`,
			Event: DNS{
				PolicyIdentity: "340 Fremont",
				Identities: []string{
					"340 Fremont",
				},
				InternalIP:   "75.21.22.23",
				ExternalIP:   "75.21.22.23",
				Action:       "Allowed",
				QueryType:    "1 (A)",
				ResponseCode: "NOERROR",
				Domain:       "docs.google.com.",
				Categories: []string{
					"File Storage",
					"SaaS and B2B",
					"Application",
				},
				PolicyIdentityType: "Networks",
				IdentityTypes: []string{
					"Networks",
				},
			},
			IPs: []string{
				"75.21.22.23",
				"75.21.22.23",
			},
			Domain:  "docs.google.com",
			Time:    time.Date(2020, 05, 21, 4, 16, 7, 0, time.UTC),
			WantErr: false,
		},
		{
			Log: `"2020-05-21 04:19:09","340 Fremont","340 Fremont","75.21.22.23","75.21.22.23","Allowed","1 (A)","NOERROR","play.google.com.","Ecommerce/Shopping,Movies,Software/Technology","Networks","Networks",""`,
			Event: DNS{
				PolicyIdentity: "340 Fremont",
				Identities: []string{
					"340 Fremont",
				},
				InternalIP:   "75.21.22.23",
				ExternalIP:   "75.21.22.23",
				Action:       "Allowed",
				QueryType:    "1 (A)",
				ResponseCode: "NOERROR",
				Domain:       "play.google.com.",
				Categories: []string{
					"Ecommerce/Shopping",
					"Movies",
					"Software/Technology",
				},
				PolicyIdentityType: "Networks",
				IdentityTypes: []string{
					"Networks",
				},
			},
			IPs: []string{
				"75.21.22.23",
				"75.21.22.23",
			},
			Domain:  "play.google.com",
			Time:    time.Date(2020, 05, 21, 4, 19, 9, 0, time.UTC),
			WantErr: false,
		},
	} {
		tc := tc
		t.Run(fmt.Sprintf("DNS-test-%d", i), func(t *testing.T) {
			event := tc.Event
			event.Timestamp = timestamp.RFC3339(tc.Time)
			event.SetCoreFields(TypeDNS, &event.Timestamp, &event)
			for _, addr := range tc.IPs {
				event.AppendAnyIPAddress(addr)
			}
			event.AppendAnyDomainNames(tc.Domain)
			testutil.CheckPantherParser(t, tc.Log, NewDNSParser(), &event.PantherLog)
		})
	}
}
