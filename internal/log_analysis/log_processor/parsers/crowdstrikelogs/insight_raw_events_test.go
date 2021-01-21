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

func TestAIDMasterParser(t *testing.T) {
	parser := TypeAIDMaster
	timestamp := 1590364206.99
	timestampLocal := 1590364206.0
	ts := tcodec.UnixSeconds(timestamp)
	input := fmt.Sprintf(`{
			"aid": "0cfb1a68ef6b49fdb0d2b12725057057",
			"aip": "10.0.0.1",
			"AgentLoadFlags": "1",
			"AgentLocalTime": "%.2f",
			"AgentTimeOffset": "-15967.470",
			"AgentVersion": "2.0.0002.2180",
			"BiosManufacturer": "Phoenix Technologies LTC",
			"BiosVersion": "6.00",
			"cid": "0123456789ABCDEFGHIJKLMNOPQRSTUV",
			"ChassisType": "Desktop",
			"City": "Sunnyvale",
			"Country": "United States",
			"ComputerName": "my-host-name",
			"ConfigIDBuild": "abc1",
			"Continent": "North America",
			"event_platform": "Win",
			"FirstSeen": "%.2f",
			"MachineDomain": "XYZ.CORP",
			"OU": "TEST-ORGANIZATIONAL-UNIT",
			"PointerSize": "8",
			"ProductType": "1",
			"ServicePackMajor": "1",
			"SiteName": "Test-Office",
			"SystemManufacturer": "Test-Manufacturer",
			"SystemProductName": "12345",
			"Time": "%.2f",
			"Timezone": "America/Los Angeles",
			"Version": "Windows 8.1"
	    }`,
		timestampLocal,
		timestampLocal,
		timestamp)

	expect := fmt.Sprintf(`{
			"aid": "0cfb1a68ef6b49fdb0d2b12725057057",
			"aip": "10.0.0.1",
			"AgentLoadFlags": 1,
			"AgentLocalTime": %.0f,
			"AgentTimeOffset": -15967.470,
			"AgentVersion": "2.0.0002.2180",
			"BiosManufacturer": "Phoenix Technologies LTC",
			"BiosVersion": "6.00",
			"cid": "0123456789ABCDEFGHIJKLMNOPQRSTUV",
			"ChassisType": "Desktop",
			"City": "Sunnyvale",
			"Country": "United States",
			"ComputerName": "my-host-name",
			"ConfigIDBuild": "abc1",
			"Continent": "North America",
			"event_platform": "Win",
			"FirstSeen": %.0f,
			"MachineDomain": "XYZ.CORP",
			"OU": "TEST-ORGANIZATIONAL-UNIT",
			"PointerSize": "8",
			"ProductType": "1",
			"ServicePackMajor": "1",
			"SiteName": "Test-Office",
			"SystemManufacturer": "Test-Manufacturer",
			"SystemProductName": "12345",
			"Time": %.2f,
			"Timezone": "America/Los Angeles",
			"Version": "Windows 8.1",	
			"p_any_ip_addresses": ["10.0.0.1"],
			"p_any_trace_ids": ["0cfb1a68ef6b49fdb0d2b12725057057"],
			"p_log_type": "%s",
			"p_event_time": "%s"
		}`,
		timestampLocal,
		timestampLocal,
		timestamp,
		parser,
		ts.UTC().Format(time.RFC3339Nano),
	)

	logtesting.TestRegisteredParser(t, LogTypes(), parser.String(), input, expect)
}

func TestManagedAssetsParser(t *testing.T) {
	parser := TypeManagedAssets
	timestamp := 1590364206.99
	ts := tcodec.UnixSeconds(timestamp)

	input := fmt.Sprintf(`{
        "_time": "%.2f",
        "aid": "0cfb1a68ef6b49fdb0d2b12725057057",
        "cid": "0123456789ABCDEFGHIJKLMNOPQRSTUV",
        "GatewayIP": "10.0.0.1",
        "GatewayMAC": "11-22-33-44-55-66",
        "MacPrefix": "11-22-33",
        "MAC": "11-22-33-99-88-77",
        "InterfaceAlias": "Ethernet",
        "InterfaceDescription": "Inter(R) PRO/1000 MT",
        "LocalAddressIP4": "10.0.0.190"
	}`, timestamp)

	expect := fmt.Sprintf(`{
            "_time": %.2f,
            "aid": "0cfb1a68ef6b49fdb0d2b12725057057",
            "cid": "0123456789ABCDEFGHIJKLMNOPQRSTUV",
            "GatewayIP": "10.0.0.1",
            "GatewayMAC": "11-22-33-44-55-66",
            "MacPrefix": "11-22-33",
            "MAC": "11-22-33-99-88-77",
            "InterfaceAlias": "Ethernet",
            "InterfaceDescription": "Inter(R) PRO/1000 MT",
            "LocalAddressIP4": "10.0.0.190",
            "p_event_time": "%s",
            "p_log_type": "%s",
            "p_any_ip_addresses": ["10.0.0.190"],
            "p_any_trace_ids": ["0cfb1a68ef6b49fdb0d2b12725057057"]
        }`,
		timestamp,
		ts.UTC().Format(time.RFC3339Nano),
		parser)

	logtesting.TestRegisteredParser(t, LogTypes(), parser.String(), input, expect)
}

func TestNotManagedAssetsParser(t *testing.T) {
	parser := TypeNotManagedAssets
	timestamp := 1590364206.99
	timestampFirstDiscovered := 1590364106.99
	timestampLastDiscovered := 1590364150.98
	ts := tcodec.UnixSeconds(timestamp)

	input := fmt.Sprintf(`{
            "_time": "%.2f",
            "cid": "0123456789ABCDEFGHIJKLMNOPQRSTUV",
            "aip": "10.0.0.1",
            "aipcount": "1",
            "CurrentLocalIP": "10.0.0.190",
            "MacPrefix": "11-22-33",
            "MAC": "11-22-33-99-88-77",
            "ComputerName": "mysecurecomputer",
            "discoverer_aid": ["0cfb1a68ef6b49fdb0d2b12725057057"],
            "discoverer_devicetype": "Server",
            "discovererCount": "1",
            "FirstDiscoveredDate": "%.2f",
            "LastDiscoveredBy": "%.2f",
            "LocalAddressIP4": "10.0.0.175",
            "localipCount": "1",
            "NeighborName": "myvulnerablecomputer",
            "subnet": "255.255.255.0"
        }`,
		timestamp,
		timestampFirstDiscovered,
		timestampLastDiscovered)

	expect := fmt.Sprintf(`{
            "_time": %.2f,
            "cid": "0123456789ABCDEFGHIJKLMNOPQRSTUV",
            "aip": "10.0.0.1",
            "aipcount": 1,
            "CurrentLocalIP": "10.0.0.190",
            "MacPrefix": "11-22-33",
            "MAC": "11-22-33-99-88-77",
            "ComputerName": "mysecurecomputer",
            "discoverer_aid": ["0cfb1a68ef6b49fdb0d2b12725057057"],
            "discoverer_devicetype": "Server",
            "discovererCount": 1,
            "FirstDiscoveredDate": %.2f,
            "LastDiscoveredBy": %.2f,
            "LocalAddressIP4": "10.0.0.175",
            "localipCount": 1,
            "NeighborName": "myvulnerablecomputer",
            "subnet": "255.255.255.0",
            "p_event_time": "%s",
            "p_log_type": "%s",
            "p_any_ip_addresses": ["10.0.0.1", "10.0.0.175", "10.0.0.190"],
            "p_any_trace_ids": ["0cfb1a68ef6b49fdb0d2b12725057057"]
        }`,
		timestamp,
		timestampFirstDiscovered,
		timestampLastDiscovered,
		ts.UTC().Format(time.RFC3339Nano),
		parser)

	logtesting.TestRegisteredParser(t, LogTypes(), parser.String(), input, expect)
}
