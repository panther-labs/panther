package cloudflarelogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
)

func TestFirewallParser(t *testing.T) {
	type testCase struct {
		input  string
		output []string
	}
	for _, tc := range []testCase{
		{
			`
{
    "Action": "firewall-action",
    "ClientASN": 123,
    "ClientASNDescription": "123",
    "ClientCountry": "Greece",
    "ClientIP": "128.127.128.127",
    "ClientIPClass": "clean",
    "ClientRefererHost": "example-referrer.com",
    "ClientRefererPath": "/ref-path",
    "ClientRefererQuery": "?query=param",
    "ClientRefererScheme": "https",
    "ClientRequestHost": "example.com",
    "ClientRequestMethod": "POST",
    "ClientRequestPath": "/",
    "ClientRequestProtocol": "HTTP 1.1",
    "ClientRequestQuery": "/",
    "ClientRequestScheme": "https",
    "ClientRequestUserAgent": "firefox",
    "Datetime": 1600365601,
    "EdgeColoCode": "IATA-123",
    "EdgeResponseStatus": 200,
    "Kind": "firewall",
    "MatchIndex": 1234,
    "Metadata": {
        "Metadata1": "metadata-1",
        "Metadata2": "metadata-2"
    },
    "OriginResponseStatus": 200,
    "OriginatorRayID": "originator-ray-id",
    "RayID": "ray-id",
    "RuleID": "rule-id",
    "Source": "cloudflare-security-product"
}
`, []string{`
{
    "Action": "firewall-action",
    "ClientASN": 123,
    "ClientASNDescription": "123",
    "ClientCountry": "Greece",
    "ClientIP": "128.127.128.127",
    "ClientIPClass": "clean",
    "ClientRefererHost": "example-referrer.com",
    "ClientRefererPath": "/ref-path",
    "ClientRefererQuery": "?query=param",
    "ClientRefererScheme": "https",
    "ClientRequestHost": "example.com",
    "ClientRequestMethod": "POST",
    "ClientRequestPath": "/",
    "ClientRequestProtocol": "HTTP 1.1",
    "ClientRequestQuery": "/",
    "ClientRequestScheme": "https",
    "ClientRequestUserAgent": "firefox",
    "Datetime": "2020-09-17T18:00:01Z",
    "EdgeColoCode": "IATA-123",
    "EdgeResponseStatus": 200,
    "Kind": "firewall",
    "MatchIndex": 1234,
    "Metadata": {
        "Metadata1": "metadata-1",
        "Metadata2": "metadata-2"
    },
    "OriginResponseStatus": 200,
    "OriginatorRayID": "originator-ray-id",
    "RayID": "ray-id",
    "RuleID": "rule-id",
    "Source": "cloudflare-security-product",

	"p_log_type": "Cloudflare.Firewall",
	"p_event_time":"2020-09-17T18:00:01Z",
	"p_any_domain_names": ["example-referrer.com", "example.com"],
	"p_any_ip_addresses": ["128.127.128.127"],
	"p_any_trace_ids": ["originator-ray-id", "ray-id"]
}
`},
		},
	} {
		tc := tc
		t.Run("testcase", func(t *testing.T) {
			testutil.CheckRegisteredParser(t, "Cloudflare.Firewall", tc.input, tc.output...)
		})
	}
}
