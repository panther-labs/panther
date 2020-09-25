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

func TestSpectrumEventParser(t *testing.T) {
	type testCase struct {
		input  string
		output []string
	}
	for _, tc := range []testCase{
		{
			`
{
    "Application": "app-123",
    "ClientASN": 123,
    "ClientBytes": 1024,
    "ClientCountry": "Greece",
    "ClientIP": "127.127.127.127",
    "ClientMatchedIpFirewall": "ALLOW",
    "ClientPort": 1040,
    "ClientProto": "tcp",
    "ClientTcpRtt": 200000,
    "ClientTlsCipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ClientTlsClientHelloServerName": "hello-server-name",
    "ClientTlsProtocol": "TLS 1.3",
    "ClientTlsStatus": "OK",
    "ColoCode": "IATA-123",
    "ConnectTimestamp": "2020-08-07T07:52:09Z",
    "DisconnectTimestamp": "2020-08-07T07:52:09Z",
    "Event": "connect",
    "IpFirewall": true,
    "OriginBytes": 512,
    "OriginIP": "128.128.128.128",
    "OriginPort": 443,
    "OriginProto": "tcp",
    "OriginTcpRtt": 100000,
    "OriginTlsCipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "OriginTlsFingerprint": "tls-fingerprint",
    "OriginTlsMode": "unknown",
    "OriginTlsProtocol": "SSLv3",
    "OriginTlsStatus": "KEYLESS_RPC",
    "ProxyProtocol": "simple",
    "Status": 123,
    "Timestamp": 1600368586194526741
}
`, []string{`
{
    "Application": "app-123",
    "ClientASN": 123,
    "ClientBytes": 1024,
    "ClientCountry": "Greece",
    "ClientIP": "127.127.127.127",
    "ClientMatchedIpFirewall": "ALLOW",
    "ClientPort": 1040,
    "ClientProto": "tcp",
    "ClientTcpRtt": 200000,
    "ClientTlsCipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ClientTlsClientHelloServerName": "hello-server-name",
    "ClientTlsProtocol": "TLS 1.3",
    "ClientTlsStatus": "OK",
    "ColoCode": "IATA-123",
    "ConnectTimestamp": "2020-08-07T07:52:09Z",
    "DisconnectTimestamp": "2020-08-07T07:52:09Z",
    "Event": "connect",
    "IpFirewall": true,
    "OriginBytes": 512,
    "OriginIP": "128.128.128.128",
    "OriginPort": 443,
    "OriginProto": "tcp",
    "OriginTcpRtt": 100000,
    "OriginTlsCipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "OriginTlsFingerprint": "tls-fingerprint",
    "OriginTlsMode": "unknown",
    "OriginTlsProtocol": "SSLv3",
    "OriginTlsStatus": "KEYLESS_RPC",
    "ProxyProtocol": "simple",
    "Status": 123,
    "Timestamp": "2020-09-17T18:49:46Z",

	"p_log_type": "Cloudflare.Spectrum",
	"p_event_time":"2020-09-17T18:49:46.194526741Z",
	"p_any_ip_addresses": ["127.127.127.127", "128.128.128.128"]
}
`},
		},
	} {
		tc := tc
		t.Run("testcase", func(t *testing.T) {
			testutil.CheckRegisteredParser(t, "Cloudflare.Spectrum", tc.input, tc.output...)
		})
	}
}
