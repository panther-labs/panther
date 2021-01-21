package crowdstrikelogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes/logtesting"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
)

func TestAppInfoParser(t *testing.T) {
	parser := TypeAppInfo
	timestamp := 1590364206.99
	ts := tcodec.UnixSeconds(timestamp)
	input := fmt.Sprintf(`{
            "cid": "0123456789ABCDEFGHIJKLMNOPQRSTUV",
            "_time": "%.2f",
            "CompanyName": "Test Company",
            "detectioncount": "1",
            "FileName": "googleupdate.exe",
            "SHA256HashData": "69061e33acb7587d773d05000390f9101f71dfd6eed7973b551594eaf3f04193",
            "FileDescription": "Google Installer",
            "FileVersion": "15.00.0847.030",
            "ProductName": "Microsoft Exchange",
            "ProductVersion": "15.0"
        }`,
		timestamp)

	expect := fmt.Sprintf(`{
                "cid": "0123456789ABCDEFGHIJKLMNOPQRSTUV",
                "_time": %.2f,
                "CompanyName": "Test Company",
                "detectioncount": 1,
                "FileName": "googleupdate.exe",
                "FileDescription": "Google Installer",
                "FileVersion": "15.00.0847.030",
                "ProductName": "Microsoft Exchange",
                "ProductVersion": "15.0",
                "SHA256HashData": "69061e33acb7587d773d05000390f9101f71dfd6eed7973b551594eaf3f04193",
                "p_log_type": "%s",
                "p_event_time": "%s",
                "p_any_sha256_hashes": ["69061e33acb7587d773d05000390f9101f71dfd6eed7973b551594eaf3f04193"]
            }`,
		timestamp,
		parser,
		ts.UTC().Format(time.RFC3339Nano))

	logtesting.TestRegisteredParser(t, LogTypes(), parser.String(), input, expect)
}

func TestUserInfoParser(t *testing.T) {
	parser := TypeUserInfo
	timestamp := 1590364206.99
	timestampPasswordLastSet := 1590214206.99
	timestampLogonTime := 1590212206.99
	ts := tcodec.UnixSeconds(timestamp)
	input := fmt.Sprintf(`{
            "_time": "%.2f",	      
            "cid": "0123456789ABCDEFGHIJKLMNOPQRSTUV",
            "AccountType": "Domain User",
            "DomainUser": "Yes",
            "UserName": "User-1",
            "UserSid_readable": "S-A-BBBB-CCCC-DDDD",
            "LastLoggedOnHost": "test-host",
            "LocalAdminAccess": "Yes",
            "LoggedOnHostCount": "1",
            "LogonInfo": "Local User Logon",
            "LogonTime": "%.2f",
            "LogonType": "INTERACTIVE",
            "monthsincereset": "1",
            "PasswordLastSet": "%.2f",
            "User": "domain/User-1",
            "UserIsAdmin": "0",
            "UserLogonFlags_decimal": "1"
        }`,
		timestamp,
		timestampLogonTime,
		timestampPasswordLastSet)

	expect := fmt.Sprintf(`{
            "_time": %.2f,	      
            "cid": "0123456789ABCDEFGHIJKLMNOPQRSTUV",
            "AccountType": "Domain User",
            "DomainUser": "Yes",
            "UserName": "User-1",
            "UserSid_readable": "S-A-BBBB-CCCC-DDDD",
            "LastLoggedOnHost": "test-host",
            "LocalAdminAccess": "Yes",
            "LoggedOnHostCount": 1,
            "LogonInfo": "Local User Logon",
            "LogonTime": %.2f,
            "LogonType": "INTERACTIVE",
            "monthsincereset": 1,
            "PasswordLastSet": %.2f,
            "User": "domain/User-1",
            "UserIsAdmin": 0,
            "UserLogonFlags_decimal": "1",
            "p_log_type": "%s",
            "p_event_time": "%s",
            "p_any_trace_ids": ["S-A-BBBB-CCCC-DDDD"]
        }`,
		timestamp,
		timestampLogonTime,
		timestampPasswordLastSet,
		parser,
		ts.UTC().Format(time.RFC3339Nano),
	)

	logtesting.TestRegisteredParser(t, LogTypes(), parser.String(), input, expect)
}
