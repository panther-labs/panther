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

func TestNetworkListenParser(t *testing.T) {
	ts := tcodec.UnixSeconds(1590364238.772)

	input := `{
		"LocalAddressIP4": "0.0.0.0",
		"event_simpleName": "NetworkListenIP4",
		"ContextTimeStamp": "1590364238.772",
		"ConfigStateHash": "156025532",
		"ConnectionFlags": "0",
		"ContextProcessId": "290786010680680985",
		"RemotePort": "0",
		"aip": "37.228.245.186",
		"ConfigBuild": "1007.4.0010306.1",
		"event_platform": "Mac",
		"LocalPort": "50992",
		"Entitlements": "15",
		"name": "NetworkListenIP4MacV5",
		"id": "5eb49a6f-9e19-11ea-b387-06c8bf30f3b9",
		"Protocol": "6",
		"aid": "5be0664506294ed0427671ed0563f1f8",
		"RemoteAddressIP4": "0.0.0.0",
		"ConnectionDirection": "0",
		"InContext": "0",
		"timestamp": "1590364238848",
		"cid": "0cfb1a68ef6b49fdb0d2b12725057057"
	}`
	expect := fmt.Sprintf(`{
		"LocalAddressIP4": "0.0.0.0",
		"event_simpleName": "NetworkListenIP4",
		"ContextTimeStamp": 1590364238.772,
		"ConfigStateHash": "156025532",
		"ConnectionFlags": 0,
		"ContextProcessId": "290786010680680985",
		"RemotePort": 0,
		"aip": "37.228.245.186",
		"ConfigBuild": "1007.4.0010306.1",
		"event_platform": "Mac",
		"LocalPort": 50992,
		"Entitlements": "15",
		"name": "NetworkListenIP4MacV5",
		"id": "5eb49a6f-9e19-11ea-b387-06c8bf30f3b9",
		"Protocol": 6,
		"aid": "5be0664506294ed0427671ed0563f1f8",
		"RemoteAddressIP4": "0.0.0.0",
		"ConnectionDirection": 0,
		"InContext": "0",
		"timestamp": 1590364238848,
		"cid": "0cfb1a68ef6b49fdb0d2b12725057057",
		"p_any_ip_addresses": ["0.0.0.0","37.228.245.186"],
		"p_event_time": "%s",
		"p_log_type": "%s"
	}`,
		ts.UTC().Format(time.RFC3339Nano),
		TypeNetworkListen,
	)

	logtesting.TestRegisteredParser(t, LogTypes(), TypeNetworkListen.String(), input, expect)
}

func TestNetworkConnectParser(t *testing.T) {
	ts := tcodec.UnixSeconds(1590364198.683)
	input := `{
		"LocalAddressIP4": "0.0.0.0",
		"event_simpleName": "NetworkConnectIP4",
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
		"name": "NetworkConnectIP4MacV5",
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
		"LocalAddressIP4": "0.0.0.0",
		"event_simpleName": "NetworkConnectIP4",
		"ContextTimeStamp": 1590364198.683,
		"ConfigStateHash": "3182062592",
		"ConnectionFlags": 0,
		"ContextProcessId": "287989071618327558",
		"RemotePort": 60012,
		"aip": "71.198.164.96",
		"ConfigBuild": "1007.4.0010306.1",
		"event_platform": "Mac",
		"LocalPort": 0,
		"Entitlements": "15",
		"name": "NetworkConnectIP4MacV5",
		"id": "45e7efdb-9e19-11ea-88ea-02960d476b37",
		"Protocol": 6,
		"aid": "0659cf9079964e887615b6e4da7b0545",
		"RemoteAddressIP4": "127.0.0.1",
		"ConnectionDirection": 0,
		"InContext": "0",
		"timestamp": 1590364197242,
		"cid": "0cfb1a68ef6b49fdb0d2b12725057057",
		"p_any_ip_addresses": ["0.0.0.0","127.0.0.1","71.198.164.96"],
		"p_event_time": "%s",
		"p_log_type": "%s"
	}`,
		ts.UTC().Format(time.RFC3339Nano),
		TypeNetworkConnect,
	)

	logtesting.TestRegisteredParser(t, LogTypes(), TypeNetworkConnect.String(), input, expect)
}
