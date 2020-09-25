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

func TestHTTPRequestParser(t *testing.T) {
	type testCase struct {
		input  string
		output []string
	}
	for _, tc := range []testCase{
		{
			`
{
	"BotScore":10,
	"BotScoreSrc":"Heuristics",
	"CacheCacheStatus":"hit",
	"CacheResponseBytes": 1024,
	"CacheResponseStatus": 200,
	"CacheTieredFill":true,
	"ClientASN": 123,
	"ClientCountry":"Greece",
	"ClientDeviceType":"mobile",
	"ClientIP": "127.0.0.1",
	"ClientIPClass": "clean",
	"ClientRequestBytes": 2048,
	"ClientRequestHost": "example.com",
	"ClientRequestMethod": "POST",
	"ClientRequestPath": "/path",
	"ClientRequestProtocol": "HTTP 1.1",
	"ClientRequestReferer": "example.com",
	"ClientRequestURI": "/",
	"ClientRequestUserAgent": "firefox",
	"ClientSSLProtocol": "TLS 1.3",
	"ClientSrcPort": 12800,
	"ClientXRequestedWith": "XMLHttpRequest",
	"EdgeColoCode": "9F",
	"EdgeColoID": 123,
	"EdgeEndTimestamp": "2020-08-07T07:52:09Z",
	"EdgePathingOp": "unknown",
	"EdgePathingSrc": "unknown",
	"EdgePathingStatus": "unknown",
	"EdgeRateLimitAction":"",
	"EdgeRateLimitID": "rule-id",
	"EdgeRequestHost": "example-edge.com",
	"EdgeResponseBytes":1024,
	"EdgeResponseCompressionRatio": 0.3,
	"EdgeResponseContentType": "application/json",
	"EdgeResponseStatus":200,
	"EdgeServerIP": "127.127.127.127",
	"EdgeStartTimestamp": 1600365600, 
	"FirewallMatchesActions": ["jschallengeFailed", "jschallengeBypassed"],
	"FirewallMatchesRuleIDs": ["rule1", "rule2"],
	"FirewallMatchesSources": ["sanitycheck","protect"],
	"OriginIP": "128.128.128.128",
	"OriginResponseBytes":512,
	"OriginResponseHTTPExpires": "Fri, 21 Oct 2016 07:28:00 GMT",
	"OriginResponseHTTPLastModified": "Fri, 21 Oct 2016 07:28:00 GMT",
	"OriginResponseStatus": 200,
	"OriginResponseTime": 1000000,
	"OriginSSLProtocol": "TLS 1.3",
	"ParentRayID": "parent-ray-id",
	"RayID": "ray-id",
	"SecurityLevel": "high",
	"WAFAction": "none",
	"WAFFlags": "simulate (0x1) | null",
	"WAFMatchedVar": "some-variable",
	"WAFProfile": "low",
	"WAFRuleID": "waf-rule-id",
	"WAFRuleMessage": "waf-rule-message",
	"WorkerCPUTime": 1000000,
	"WorkerStatus": "OK",
	"WorkerSubrequest": true,
	"WorkerSubrequestCount": 10,
	"ZoneID": 123
}`, []string{`
{
	"BotScore":10,
	"BotScoreSrc":"Heuristics",
	"CacheCacheStatus":"hit",
	"CacheResponseBytes": 1024,
	"CacheResponseStatus": 200,
	"CacheTieredFill":true,
	"ClientASN": 123,
	"ClientCountry":"Greece",
	"ClientDeviceType":"mobile",
	"ClientIP": "127.0.0.1",
	"ClientIPClass": "clean",
	"ClientRequestBytes": 2048,
	"ClientRequestHost": "example.com",
	"ClientRequestMethod": "POST",
	"ClientRequestPath": "/path",
	"ClientRequestProtocol": "HTTP 1.1",
	"ClientRequestReferer": "example.com",
	"ClientRequestURI": "/",
	"ClientRequestUserAgent": "firefox",
	"ClientSSLProtocol": "TLS 1.3",
	"ClientSrcPort": 12800,
	"ClientXRequestedWith": "XMLHttpRequest",
	"EdgeColoCode": "9F",
	"EdgeColoID": 123,
	"EdgeEndTimestamp": "2020-08-07T07:52:09Z",
	"EdgePathingOp": "unknown",
	"EdgePathingSrc": "unknown",
	"EdgePathingStatus": "unknown",
	"EdgeRateLimitAction":"",
	"EdgeRateLimitID": "rule-id",
	"EdgeRequestHost": "example-edge.com",
	"EdgeResponseBytes":1024,
	"EdgeResponseCompressionRatio": 0.3,
	"EdgeResponseContentType": "application/json",
	"EdgeResponseStatus":200,
	"EdgeServerIP": "127.127.127.127",
	"EdgeStartTimestamp": "2020-09-17T18:00:00Z",  
	"FirewallMatchesActions": ["jschallengeFailed", "jschallengeBypassed"],
	"FirewallMatchesRuleIDs": ["rule1", "rule2"],
	"FirewallMatchesSources": ["sanitycheck","protect"],
	"OriginIP": "128.128.128.128",
	"OriginResponseBytes":512,
	"OriginResponseHTTPExpires": "Fri, 21 Oct 2016 07:28:00 GMT",
	"OriginResponseHTTPLastModified": "Fri, 21 Oct 2016 07:28:00 GMT",
	"OriginResponseStatus": 200,
	"OriginResponseTime": 1000000,
	"OriginSSLProtocol": "TLS 1.3",
	"ParentRayID": "parent-ray-id",
	"RayID": "ray-id",
	"SecurityLevel": "high",
	"WAFAction": "none",
	"WAFFlags": "simulate (0x1) | null",
	"WAFMatchedVar": "some-variable",
	"WAFProfile": "low",
	"WAFRuleID": "waf-rule-id",
	"WAFRuleMessage": "waf-rule-message",
	"WorkerCPUTime": 1000000,
	"WorkerStatus": "OK",
	"WorkerSubrequest": true,
	"WorkerSubrequestCount": 10,
	"ZoneID": 123,

	"p_log_type": "Cloudflare.HttpRequest",
	"p_event_time":"2020-09-17T18:00:00Z",
	"p_any_domain_names": ["example-edge.com", "example.com"],
	"p_any_ip_addresses": ["127.0.0.1", "127.127.127.127", "128.128.128.128"],
	"p_any_trace_ids": ["parent-ray-id", "ray-id"]
}
`},
		},
	} { //nolint,whitespace

		tc := tc
		t.Run("testcase", func(t *testing.T) {
			testutil.CheckRegisteredParser(t, "Cloudflare.HttpRequest", tc.input, tc.output...)
		})
	}
}
