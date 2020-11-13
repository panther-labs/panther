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
type SpectrumEvent struct {
	Application                    pantherlog.String `json:"Application" description:"The unique public ID of the application on which the event occurred"`
	ClientASN                      pantherlog.Int64  `json:"ClientASN" description:"Client AS number"`
	ClientBytes                    pantherlog.Int64  `json:"ClientBytes" description:"The number of bytes read from the client by the Spectrum service"`
	ClientCountry                  pantherlog.String `json:"ClientCountry" description:"Country of the client IP address"`
	ClientIP                       pantherlog.String `json:"ClientIP" panther:"ip" description:"IP address of the client"`
	ClientMatchedIPFirewall        pantherlog.String `json:"ClientMatchedIpFirewall" description:"Whether the connection matched any IP Firewall rules; UNKNOWN | ALLOW | BLOCK_ERROR | BLOCK_IP | BLOCK_COUNTRY | BLOCK_ASN | WHITELIST_IP |WHITELIST_COUNTRY | WHITELIST_ASN"`
	ClientPort                     pantherlog.Uint16 `json:"ClientPort" description:"Client port"`
	ClientProto                    pantherlog.String `json:"ClientProto" description:"Transport protocol used by client; tcp | udp | unix"`
	ClientTCPRtt                   pantherlog.Int64  `json:"ClientTcpRtt" description:"The TCP round-trip time in nanoseconds between the client and Spectrum"`
	ClientTLSCipher                pantherlog.String `json:"ClientTlsCipher" description:"The cipher negotiated between the client and Spectrum"`
	ClientTLSClientHelloServerName pantherlog.String `json:"ClientTlsClientHelloServerName" description:"The server name in the Client Hello message from client to Spectrum"`
	ClientTLSProtocol              pantherlog.String `json:"ClientTlsProtocol" description:"The TLS version negotiated between the client and Spectrum; unknown | none | SSLv3 | TLSv1 | TLSv1.1 | TLSv1.2 | TLSv1.3"`
	ClientTLSStatus                pantherlog.String `json:"ClientTlsStatus" description:"Indicates state of TLS session from the client to Spectrum; UNKNOWN | OK | INTERNAL_ERROR | INVALID_CONFIG | INVALID_SNI | HANDSHAKE_FAILED | KEYLESS_RPC"`
	ColoCode                       pantherlog.String `json:"ColoCode" description:"IATA airport code of data center that received the request"`
	ConnectTimestamp               pantherlog.Time   `json:"ConnectTimestamp" tcodec:"cloudflare" description:"Timestamp at which both legs of the connection (client/edge, edge/origin or nexthop) were established"`
	DisconnectTimestamp            pantherlog.Time   `json:"DisconnectTimestamp" tcodec:"cloudflare" description:"Timestamp at which the connection was closed"`
	Event                          pantherlog.String `json:"Event" description:"connect | disconnect | clientFiltered | tlsError | resolveOrigin | originError"`
	IPFirewall                     pantherlog.Bool   `json:"IpFirewall" description:"Whether IP Firewall was enabled at time of connection"`
	OriginBytes                    pantherlog.Int64  `json:"OriginBytes" description:"The number of bytes read from the origin by Spectrum"`
	OriginIP                       pantherlog.String `json:"OriginIP" panther:"ip" description:"Origin IP address"`
	OriginPort                     pantherlog.Uint16 `json:"OriginPort" description:"Origin port"`
	OriginProto                    pantherlog.String `json:"OriginProto" description:"Transport protocol used by origin; tcp | udp | unix"`
	OriginTCPRtt                   pantherlog.Int64  `json:"OriginTcpRtt" description:"The TCP round-trip time in nanoseconds between Spectrum and the origin"`
	OriginTLSCipher                pantherlog.String `json:"OriginTlsCipher" description:"The cipher negotiated between Spectrum and the origin"`
	OriginTLSFingerprint           pantherlog.String `json:"OriginTlsFingerprint" description:"SHA256 hash of origin certificate"`
	OriginTLSMode                  pantherlog.String `json:"OriginTlsMode" description:"If and how the upstream connection is encrypted; unknown | off | flexible | full | strict"`
	OriginTLSProtocol              pantherlog.String `json:"OriginTlsProtocol" description:"The TLS version negotiated between Spectrum and the origin; unknown | none | SSLv3 | TLSv1 | TLSv1.1 | TLSv1.2 | TLSv1.3"`
	OriginTLSStatus                pantherlog.String `json:"OriginTlsStatus" description:"The state of the TLS session from Spectrum to the origin; UNKNOWN | OK | INTERNAL_ERROR | INVALID_CONFIG | INVALID_SNI | HANDSHAKE_FAILED | KEYLESS_RPC"`
	ProxyProtocol                  pantherlog.String `json:"ProxyProtocol" description:"Which form of proxy protocol is applied to the given connection; off | v1 | v2 | simple"`
	Status                         pantherlog.Int64  `json:"Status" description:"A code indicating reason for connection closure"`
	Timestamp                      pantherlog.Time   `json:"Timestamp" validate:"required" event_time:"true" tcodec:"cloudflare" description:"Timestamp at which the event took place"`
}
