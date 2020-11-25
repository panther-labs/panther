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

func TestDNSRequestParser(t *testing.T) {
	ts := tcodec.UnixSeconds(1590364206.989)
	input := `{
		"event_simpleName": "DnsRequest",
		"ContextTimeStamp": "1590364206.989",
		"ConfigStateHash": "156025532",
		"ContextProcessId": "289977812183778042",
		"DomainName": "spclient.wg.spotify.com",
		"ContextThreadId": "0",
		"aip": "154.61.65.189",
		"ConfigBuild": "1007.4.0010306.1",
		"event_platform": "Mac",
		"Entitlements": "15",
		"name": "DnsRequestMacV1",
		"id": "4be06eb8-9e19-11ea-a7b0-026c15f3d8ed",
		"aid": "307dc41ce39744f060622095f2805249",
		"timestamp": "1590364207259",
		"cid": "0cfb1a68ef6b49fdb0d2b12725057057",
		"RequestType": "1"
	}`
	expect := fmt.Sprintf(`{
		"event_simpleName": "DnsRequest",
		"ContextTimeStamp": 1590364206.989,
		"ConfigStateHash": "156025532",
		"ContextProcessId": "289977812183778042",
		"DomainName": "spclient.wg.spotify.com",
		"ContextThreadId": "0",
		"aip": "154.61.65.189",
		"ConfigBuild": "1007.4.0010306.1",
		"event_platform": "Mac",
		"Entitlements": "15",
		"name": "DnsRequestMacV1",
		"id": "4be06eb8-9e19-11ea-a7b0-026c15f3d8ed",
		"aid": "307dc41ce39744f060622095f2805249",
		"timestamp": 1590364207259,
		"cid": "0cfb1a68ef6b49fdb0d2b12725057057",
		"RequestType": "1",
		"p_any_ip_addresses": ["154.61.65.189"],
		"p_any_domain_names": ["spclient.wg.spotify.com"],
		"p_log_type": "%s",
		"p_event_time": "%s"
}`,
		TypeDNSRequest,
		ts.UTC().Format(time.RFC3339Nano),
	)

	logtesting.TestRegisteredParser(t, LogTypes(), TypeDNSRequest.String(), input, expect)
}
