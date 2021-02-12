package crowdstrikelogs_test

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/crowdstrikelogs"
)

func TestUnknownEventParser(t *testing.T) {
	ts := tcodec.UnixSeconds(1590364198.683)
	input := `{
		"LocalAddressIP4": "0.0.0.0",
		"event_simpleName": "SomeOtherEvent",
		"ContextTimeStamp": "1590364198.683",
		"ConfigStateHash": "3182062592",
		"ConnectionFlags": "0",
		"ContextProcessId": "287989071618327558",
		"RemotePort": "60012",
		"aip": "71.198.164.96",
		"ConfigBuild": "1007.4.0010306.1",
		"event_platform": "Mac",
		"LocalPort": "0",
		"Entitlements": "15",
		"name": "SomeOtherEventMacV5",
		"id": "45e7efdb-9e19-11ea-88ea-02960d476b37",
		"Protocol": "6",
		"aid": "0659cf9079964e887615b6e4da7b0545",
		"RemoteAddressIP4": "127.0.0.1",
		"ConnectionDirection": "0",
		"InContext": "0",
		"timestamp": "1590364197242",
		"cid": "0cfb1a68ef6b49fdb0d2b12725057057"
	}`
	expect := fmt.Sprintf(`{
		"unknown_payload": {
			"LocalAddressIP4": "0.0.0.0",
			"event_simpleName": "SomeOtherEvent",
			"ContextTimeStamp": "1590364198.683",
			"ConfigStateHash": "3182062592",
			"ConnectionFlags": "0",
			"ContextProcessId": "287989071618327558",
			"RemotePort": "60012",
			"aip": "71.198.164.96",
			"ConfigBuild": "1007.4.0010306.1",
			"event_platform": "Mac",
			"LocalPort": "0",
			"Entitlements": "15",
			"name": "SomeOtherEventMacV5",
			"id": "45e7efdb-9e19-11ea-88ea-02960d476b37",
			"Protocol": "6",
			"aid": "0659cf9079964e887615b6e4da7b0545",
			"RemoteAddressIP4": "127.0.0.1",
			"ConnectionDirection": "0",
			"InContext": "0",
			"timestamp": "1590364197242",
			"cid": "0cfb1a68ef6b49fdb0d2b12725057057"
		},
		"event_simpleName": "SomeOtherEvent",
		"ContextTimeStamp": 1590364198.683,
		"ConfigStateHash": "3182062592",
		"ContextProcessId": "287989071618327558",
		"timestamp": 1590364197242,
		"cid": "0cfb1a68ef6b49fdb0d2b12725057057",
		"aip": "71.198.164.96",
		"ConfigBuild": "1007.4.0010306.1",
		"event_platform": "Mac",
		"InContext": "0",
		"Entitlements": "15",
		"name": "SomeOtherEventMacV5",
		"id": "45e7efdb-9e19-11ea-88ea-02960d476b37",
		"aid": "0659cf9079964e887615b6e4da7b0545",
		"p_any_ip_addresses": ["71.198.164.96"],
		"p_log_type": "Crowdstrike.Unknown",
		"p_event_time": "%s"
		}`,
		ts.UTC().Format(time.RFC3339Nano),
	)

	logtesting.TestRegisteredParser(t, crowdstrikelogs.LogTypes(), "Crowdstrike.Unknown", input, expect)
}
