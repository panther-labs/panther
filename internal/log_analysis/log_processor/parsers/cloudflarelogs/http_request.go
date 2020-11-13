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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// nolint:lll,maligned
type HTTPRequest struct {
	BotScore                       pantherlog.Int64   `json:"BotScore" description:"Cloudflare Bot Score (available for Bot Management customers; please contact your account team to enable)"`
	BotScoreSrc                    pantherlog.String  `json:"BotScoreSrc" description:"Underlying detection engine or source on where a Bot Score is calculated. Possible values are Not Computed | Heuristics | Machine Learning | Behavioral Analysis | Verified Bot"`
	CacheCacheStatus               pantherlog.String  `json:"CacheCacheStatus" description:"unknown | miss | expired | updating | stale | hit | ignored | bypass | revalidated"`
	CacheResponseBytes             pantherlog.Int64   `json:"CacheResponseBytes" description:"Number of bytes returned by the cache"`
	CacheResponseStatus            pantherlog.Int16   `json:"CacheResponseStatus" description:"HTTP status code returned by the cache to the edge; all requests (including non-cacheable ones) go through the cache; also see CacheStatus field"`
	CacheTieredFill                pantherlog.Bool    `json:"CacheTieredFill" description:"Tiered Cache was used to serve this request"`
	ClientASN                      pantherlog.Int64   `json:"ClientASN" description:"Client AS number"`
	ClientCountry                  pantherlog.String  `json:"ClientCountry" description:"Country of the client IP address"`
	ClientDeviceType               pantherlog.String  `json:"ClientDeviceType" description:"Client device type"`
	ClientIP                       pantherlog.String  `json:"ClientIP" panther:"ip" description:"IP address of the client"`
	ClientIPClass                  pantherlog.String  `json:"ClientIPClass" description:"unknown | clean | badHost | searchEngine | whitelist | greylist | monitoringService | securityScanner | noRecord | scan |backupService | mobilePlatform | tor"`
	ClientRequestBytes             pantherlog.Int64   `json:"ClientRequestBytes" description:"Number of bytes in the client request"`
	ClientRequestHost              pantherlog.String  `json:"ClientRequestHost" panther:"hostname" description:"Host requested by the client"`
	ClientRequestMethod            pantherlog.String  `json:"ClientRequestMethod" description:"HTTP method of client request"`
	ClientRequestPath              pantherlog.String  `json:"ClientRequestPath" description:"URI path requested by the client"`
	ClientRequestProtocol          pantherlog.String  `json:"ClientRequestProtocol" description:"HTTP protocol of client request"`
	ClientRequestReferer           pantherlog.String  `json:"ClientRequestReferer" panther:"hostname" description:"HTTP request referrer"`
	ClientRequestURI               pantherlog.String  `json:"ClientRequestURI" description:"URI requested by the client"`
	ClientRequestUserAgent         pantherlog.String  `json:"ClientRequestUserAgent" description:"User agent reported by the client"`
	ClientSSLProtocol              pantherlog.String  `json:"ClientSSLProtocol" description:"Client SSL (TLS) protocol"`
	ClientSrcPort                  pantherlog.Int32   `json:"ClientSrcPort" description:"Client source port"`
	ClientXRequestedWith           pantherlog.String  `json:"ClientXRequestedWith" description:"X-Requested-With HTTP header"`
	EdgeColoCode                   pantherlog.String  `json:"EdgeColoCode" description:"IATA airport code of data center that received the request"`
	EdgeColoID                     pantherlog.Int64   `json:"EdgeColoID" description:"Cloudflare edge colo id"`
	EdgeEndTimestamp               pantherlog.Time    `json:"EdgeEndTimestamp" tcodec:"cloudflare" description:"Timestamp at which the edge finished sending response to the client"`
	EdgePathingOp                  pantherlog.String  `json:"EdgePathingOp" description:"Indicates what type of response was issued for this request (unknown = no specific action)	"`
	EdgePathingSrc                 pantherlog.String  `json:"EdgePathingSrc" description:"Details how the request was classified based on security checks (unknown = no specific classification)"`
	EdgePathingStatus              pantherlog.String  `json:"EdgePathingStatus" description:"Indicates what data was used to determine the handling of this request (unknown = no data)"`
	EdgeRateLimitAction            pantherlog.String  `json:"EdgeRateLimitAction" description:"The action taken by the blocking rule; empty if no action taken"`
	EdgeRateLimitID                pantherlog.String  `json:"EdgeRateLimitID" description:"The internal rule ID of the rate-limiting rule that triggered a block (ban) or simulate action. 0 if no action taken"`
	EdgeRequestHost                pantherlog.String  `json:"EdgeRequestHost" panther:"hostname" description:"Host header on the request from the edge to the origin"`
	EdgeResponseBytes              pantherlog.Int64   `json:"EdgeResponseBytes" description:"Number of bytes returned by the edge to the client"`
	EdgeResponseCompressionRatio   pantherlog.Float32 `json:"EdgeResponseCompressionRatio" description:"Edge response compression ratio"`
	EdgeResponseContentType        pantherlog.String  `json:"EdgeResponseContentType" description:"Edge response Content-Type header value"`
	EdgeResponseStatus             pantherlog.Int16   `json:"EdgeResponseStatus" description:"HTTP status code returned by Cloudflare to the client"`
	EdgeServerIP                   pantherlog.String  `json:"EdgeServerIP" panther:"ip" description:"IP of the edge server making a request to the origin"`
	EdgeStartTimestamp             pantherlog.Time    `json:"EdgeStartTimestamp" validate:"required" event_time:"true" tcodec:"cloudflare" description:"Timestamp at which the edge received request from the client"`
	FirewallMatchesActions         []string           `json:"FirewallMatchesActions" description:"Array of actions the Cloudflare firewall products performed on this request. The individual firewall products associated with this action be found in FirewallMatchesSources and their respective RuleIds can be found in FirewallMatchesRuleIDs. The length of the array is the same as FirewallMatchesRuleIDs and FirewallMatchesSources. Possible actions are allow | log | simulate | drop | challenge | jschallenge | connectionClose | challengeSolved | challengeFailed | challengeBypassed | jschallengeSolved | jschallengeFailed | jschallengeBypassed | bypass"`
	FirewallMatchesRuleIDs         []string           `json:"FirewallMatchesRuleIDs" description:"Array of RuleIDs of the firewall product that has matched the request. The firewall product associated with the RuleID can be found in FirewallMatchesSources. The length of the array is the same as FirewallMatchesActions and FirewallMatchesSources."`
	FirewallMatchesSources         []string           `json:"FirewallMatchesSources" description:"The firewall products that matched the request. The same product can appear multiple times, which indicates different rules or actions that were activated. The RuleIDs can be found in FirewallMatchesRuleIDs, the actions can be found in FirewallMatchesActions. The length of the array is the same as FirewallMatchesRuleIDs and FirewallMatchesActions. Possible sources are asn | country | ip | ipRange | securityLevel | zoneLockdown | waf | firewallRules | uaBlock | rateLimit |bic | hot | l7ddos | sanitycheck | protect"`
	OriginIP                       pantherlog.String  `json:"OriginIP" panther:"ip" description:"IP of the origin server"`
	OriginResponseBytes            pantherlog.Int64   `json:"OriginResponseBytes" description:"Number of bytes returned by the origin server"`
	OriginResponseHTTPExpires      pantherlog.Time    `json:"OriginResponseHTTPExpires" tcodec:"layout=Mon, 02 Jan 2006 15:04:05 MST" description:"Value of the origin 'expires' header in RFC1123 format"`
	OriginResponseHTTPLastModified pantherlog.Time    `json:"OriginResponseHTTPLastModified" tcodec:"layout=Mon, 02 Jan 2006 15:04:05 MST" description:"Value of the origin 'last-modified' header in RFC1123 format"`
	OriginResponseStatus           pantherlog.Int16   `json:"OriginResponseStatus" description:"Status returned by the origin server"`
	OriginResponseTime             pantherlog.Int64   `json:"OriginResponseTime" description:"Number of nanoseconds it took the origin to return the response to edge"`
	OriginSSLProtocol              pantherlog.String  `json:"OriginSSLProtocol" description:"SSL (TLS) protocol used to connect to the origin"`
	ParentRayID                    pantherlog.String  `json:"ParentRayID" panther:"trace_id" description:"Ray ID of the parent request if this request was made using a Worker script"`
	RayID                          pantherlog.String  `json:"RayID" panther:"trace_id" description:"ID of the request"`
	SecurityLevel                  pantherlog.String  `json:"SecurityLevel" description:"The security level configured at the time of this request. This is used to determine the sensitivity of the IP Reputation system"`
	WAFAction                      pantherlog.String  `json:"WAFAction" description:"Action taken by the WAF, if triggered"`
	WAFFlags                       pantherlog.String  `json:"WAFFlags" description:"Additional configuration flags: simulate (0x1) | null"`
	WAFMatchedVar                  pantherlog.String  `json:"WAFMatchedVar" description:"The full name of the most-recently matched variable"`
	WAFProfile                     pantherlog.String  `json:"WAFProfile" description:"low | med | high"`
	WAFRuleID                      pantherlog.String  `json:"WAFRuleID" description:"ID of the applied WAF rule"`
	WAFRuleMessage                 pantherlog.String  `json:"WAFRuleMessage" description:"Rule message associated with the triggered rule"`
	WorkerCPUTime                  pantherlog.Int64   `json:"WorkerCPUTime" description:"Amount of time in microseconds spent executing a worker, if any"`
	WorkerStatus                   pantherlog.String  `json:"WorkerStatus" description:"Status returned from worker daemon"`
	WorkerSubrequest               pantherlog.Bool    `json:"WorkerSubrequest" description:"Whether or not this request was a worker subrequest"`
	WorkerSubrequestCount          pantherlog.Int64   `json:"WorkerSubrequestCount" description:"Number of subrequests issued by a worker when handling this request"`
	ZoneID                         pantherlog.Int64   `json:"ZoneID" description:"Internal zone ID"`
}
