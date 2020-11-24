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

func TestProcessRollup2Parser(t *testing.T) {
	input := `{
		"MachOSubType": "1",
		"ParentProcessId": "290298541974789642",
		"SourceProcessId": "290298642638085984",
		"aip": "98.207.249.49",
		"SHA1HashData": "0000000000000000000000000000000000000000",
		"event_platform": "Mac",
		"ProcessEndTime": "",
		"SVUID": "0",
		"id": "48ddb60e-9e19-11ea-82c5-06d62dd15d4d",
		"Tags": "27",
		"timestamp": "1590364202208",
		"ProcessGroupId": "290298642638085984",
		"event_simpleName": "ProcessRollup2",
		"RawProcessId": "58385",
		"GID": "0",
		"ConfigStateHash": "156025532",
		"SVGID": "0",
		"MD5HashData": "6f4176c6e24b186038c27648aa56c305",
		"SHA256HashData": "143c6f74b215152b729425dbd18c864ef3ad674f89ed69bc006728a476e903b9",
		"ConfigBuild": "1007.4.0010306.1",
		"UID": "0",
		"CommandLine": "/usr/bin/defaults read /Library/Preferences/com.apple.QuickTime \"Pro Key\"",
		"TargetProcessId": "290298642638085984",
		"ImageFileName": "/usr/bin/defaults",
		"RGID": "0",
		"SourceThreadId": "0",
		"Entitlements": "15",
		"name": "ProcessRollup2MacV3",
		"RUID": "0",
		"ProcessStartTime": "1590364202.021",
		"aid": "496cd4d2319145834d69b9e2bf0fbef2",
		"cid": "0cfb1a68ef6b49fdb0d2b12725057057"
	}`
	ts := tcodec.UnixMilliseconds(1590364202208)
	expect := fmt.Sprintf(`{
		"MachOSubType": "1",
		"ParentProcessId": 290298541974789642,
		"SourceProcessId": 290298642638085984,
		"aip": "98.207.249.49",
		"SHA1HashData": "0000000000000000000000000000000000000000",
		"event_platform": "Mac",
		"SVUID": 0,
		"id": "48ddb60e-9e19-11ea-82c5-06d62dd15d4d",
		"Tags": "27",
		"timestamp": 1590364202208,
		"ProcessGroupId": 290298642638085984,
		"event_simpleName": "ProcessRollup2",
		"RawProcessId": 58385,
		"GID": 0,
		"ConfigStateHash": "156025532",
		"SVGID": 0,
		"MD5HashData": "6f4176c6e24b186038c27648aa56c305",
		"SHA256HashData": "143c6f74b215152b729425dbd18c864ef3ad674f89ed69bc006728a476e903b9",
		"ConfigBuild": "1007.4.0010306.1",
		"UID": 0,
		"CommandLine": "/usr/bin/defaults read /Library/Preferences/com.apple.QuickTime \"Pro Key\"",
		"TargetProcessId": 290298642638085984,
		"ImageFileName": "/usr/bin/defaults",
		"RGID": 0,
		"SourceThreadId": 0,
		"Entitlements": "15",
		"name": "ProcessRollup2MacV3",
		"RUID": 0,
		"ProcessStartTime": 1590364202.021,
		"aid": "496cd4d2319145834d69b9e2bf0fbef2",
		"cid": "0cfb1a68ef6b49fdb0d2b12725057057",
		"p_log_type": "%s",
		"p_event_time": "%s",
		"p_any_ip_addresses": ["98.207.249.49"],
		"p_any_sha1_hashes": ["0000000000000000000000000000000000000000"],
		"p_any_md5_hashes": ["6f4176c6e24b186038c27648aa56c305"],
		"p_any_sha256_hashes": ["143c6f74b215152b729425dbd18c864ef3ad674f89ed69bc006728a476e903b9"]
	}`,
		TypeProcessRollup2,
		ts.UTC().Format(time.RFC3339Nano),
	)

	logtesting.TestRegisteredParser(t, LogTypes(), TypeProcessRollup2.String(), input, expect)
}

func TestSyntheticProcessRollup2Parser(t *testing.T) {
	input := `{
		"ParentProcessId": "290623959313607520",
		"SourceProcessId": "290623959970016140",
		"aip": "8.18.220.189",
		"SessionProcessId": "290456608935425586",
		"SyntheticPR2Flags": "16",
		"SHA1HashData": "0000000000000000000000000000000000000000",
		"event_platform": "Mac",
		"SVUID": "502",
		"id": "65ab4ad7-9e19-11ea-b86c-02cc943bebd7",
		"timestamp": "1590364250531",
		"ProcessGroupId": "290623959313607520",
		"event_simpleName": "SyntheticProcessRollup2",
		"RawProcessId": "65726",
		"ContextTimeStamp": "1590364248.055",
		"GID": "20",
		"ConfigStateHash": "2706021056",
		"SVGID": "20",
		"MD5HashData": "972fc22071d3449bfab5f4b4cd87580f",
		"SHA256HashData": "2e06816fee18729501ca0b878782cc29cf5ddb042d980a94a5dee1473fdcbe93",
		"ConfigBuild": "1007.4.0010902.1",
		"UID": "502",
		"CommandLine": "/bin/sh /usr/local/opt/mysql/bin/mysqld_safe --datadir\u003d/usr/local/var/mysql",
		"TargetProcessId": "290623959970016140",
		"ImageFileName": "/bin/sh",
		"RGID": "20",
		"Entitlements": "15",
		"name": "SyntheticProcessRollup2MacV3",
		"ProcessStartTime": "1590364248.054",
		"RUID": "502",
		"aid": "8b1b0112aa274d344284ee4693150de4",
		"cid": "0cfb1a68ef6b49fdb0d2b12725057057"
	}`

	ts := tcodec.UnixSeconds(1590364248.055)
	expect := fmt.Sprintf(`{
		"ParentProcessId": 290623959313607520,
		"SourceProcessId": 290623959970016140,
		"aip": "8.18.220.189",
		"SessionProcessId": 290456608935425586,
		"SyntheticPR2Flags": 16,
		"SHA1HashData": "0000000000000000000000000000000000000000",
		"event_platform": "Mac",
		"SVUID": 502,
		"id": "65ab4ad7-9e19-11ea-b86c-02cc943bebd7",
		"timestamp": 1590364250531,
		"ProcessGroupId": 290623959313607520,
		"event_simpleName": "SyntheticProcessRollup2",
		"RawProcessId": 65726,
		"ContextTimeStamp": 1590364248.055,
		"GID": 20,
		"ConfigStateHash": "2706021056",
		"SVGID": 20,
		"MD5HashData": "972fc22071d3449bfab5f4b4cd87580f",
		"SHA256HashData": "2e06816fee18729501ca0b878782cc29cf5ddb042d980a94a5dee1473fdcbe93",
		"ConfigBuild": "1007.4.0010902.1",
		"UID": 502,
		"CommandLine": "/bin/sh /usr/local/opt/mysql/bin/mysqld_safe --datadir\u003d/usr/local/var/mysql",
		"TargetProcessId": 290623959970016140,
		"ImageFileName": "/bin/sh",
		"RGID": 20,
		"Entitlements": "15",
		"name": "SyntheticProcessRollup2MacV3",
		"ProcessStartTime": 1590364248.054,
		"RUID": 502,
		"aid": "8b1b0112aa274d344284ee4693150de4",
		"cid": "0cfb1a68ef6b49fdb0d2b12725057057",
		"p_log_type": "%s",
		"p_event_time": "%s",
		"p_any_ip_addresses": ["8.18.220.189"],
		"p_any_sha1_hashes": ["0000000000000000000000000000000000000000"],
		"p_any_md5_hashes": ["972fc22071d3449bfab5f4b4cd87580f"],
		"p_any_sha256_hashes": ["2e06816fee18729501ca0b878782cc29cf5ddb042d980a94a5dee1473fdcbe93"]
	}`,
		TypeSyntheticProcessRollup2,
		ts.UTC().Format(time.RFC3339Nano),
	)

	logtesting.TestRegisteredParser(t, LogTypes(), TypeSyntheticProcessRollup2.String(), input, expect)
}
