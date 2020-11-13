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
type FirewallEvent struct {
	Action                 pantherlog.String                `json:"Action" description:"The code of the first-class action the Cloudflare Firewall took on this request"`
	ClientASN              pantherlog.Int64                 `json:"ClientASN" description:"The ASN number of the visitor"`
	ClientASNDescription   pantherlog.String                `json:"ClientASNDescription" description:"The ASN of the visitor as string"`
	ClientCountry          pantherlog.String                `json:"ClientCountry" description:"Country from which request originated"`
	ClientIP               pantherlog.String                `json:"ClientIP" panther:"ip" description:"The visitor's IP address (IPv4 or IPv6)"`
	ClientIPClass          pantherlog.String                `json:"ClientIPClass" description:"The classification of the visitor's IP address, possible values are: unknown | clean | badHost | searchEngine | whitelist | greylist | monitoringService |securityScanner | noRecord | scan | backupService | mobilePlatform | tor"`
	ClientRefererHost      pantherlog.String                `json:"ClientRefererHost" panther:"hostname" description:"The referer host"`
	ClientRefererPath      pantherlog.String                `json:"ClientRefererPath" description:"The referer path requested by visitor"`
	ClientRefererQuery     pantherlog.String                `json:"ClientRefererQuery" description:"The referer query-string was requested by the visitor"`
	ClientRefererScheme    pantherlog.String                `json:"ClientRefererScheme" description:"The referer url scheme requested by the visitor"`
	ClientRequestHost      pantherlog.String                `json:"ClientRequestHost" panther:"hostname" description:"The HTTP hostname requested by the visitor"`
	ClientRequestMethod    pantherlog.String                `json:"ClientRequestMethod" description:"The HTTP method used by the visitor"`
	ClientRequestPath      pantherlog.String                `json:"ClientRequestPath" description:"The path requested by visitor"`
	ClientRequestProtocol  pantherlog.String                `json:"ClientRequestProtocol" description:"The version of HTTP protocol requested by the visitor"`
	ClientRequestQuery     pantherlog.String                `json:"ClientRequestQuery" description:"The query-string was requested by the visitor"`
	ClientRequestScheme    pantherlog.String                `json:"ClientRequestScheme" description:"The url scheme requested by the visitor"`
	ClientRequestUserAgent pantherlog.String                `json:"ClientRequestUserAgent" description:"Visitor's user-agent string"`
	Datetime               pantherlog.Time                  `json:"Datetime" validate:"required" event_time:"true" tcodec:"cloudflare" description:"The date and time the event occurred at the edge"`
	EdgeColoCode           pantherlog.String                `json:"EdgeColoCode" description:"The airport code of the Cloudflare datacenter that served this request"`
	EdgeResponseStatus     pantherlog.Int16                 `json:"EdgeResponseStatus" description:"HTTP response status code returned to browser"`
	Kind                   pantherlog.String                `json:"Kind" description:"The kind of event, currently only possible values are: firewall"`
	MatchIndex             pantherlog.Int64                 `json:"MatchIndex" description:"Rules match index in the chain"`
	Metadata               map[string]pantherlog.RawMessage `json:"Metadata" description:"Additional product-specific information. Metadata is organized in key:value pairs. Key and Value formats can vary by Cloudflare security product and can change over time"`
	OriginResponseStatus   pantherlog.Int16                 `json:"OriginResponseStatus" description:"HTTP origin response status code returned to browser"`
	OriginatorRayID        pantherlog.String                `json:"OriginatorRayID" panther:"trace_id" description:"The RayID of the request that issued the challenge/jschallenge"`
	RayID                  pantherlog.String                `json:"RayID" panther:"trace_id" description:"The RayID of the request"`
	RuleID                 pantherlog.String                `json:"RuleID" description:"The Cloudflare security product-specific RuleID triggered by this request"`
	Source                 pantherlog.String                `json:"Source" description:"The Cloudflare security product triggered by this request"`
}
