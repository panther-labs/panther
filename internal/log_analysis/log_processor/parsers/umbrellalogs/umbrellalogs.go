// Package umbrellalogs provides parsers for Cisco Umbrella logs
package umbrellalogs

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
	"strings"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

const (
	layoutUmbrellaTimestamp = `2006-01-02 15:04:05`
	TypeDNS                 = `CiscoUmbrella.DNS`
	TypeCloudFirewall       = `CiscoUmbrella.CloudFirewall`
	TypeIP                  = `CiscoUmbrella.IP`
	TypeProxy               = `CiscoUmbrella.Proxy`
)

func parseList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func LogTypes() logtypes.Group {
	return logTypes
}

var logTypes = logtypes.Must("CiscoUmbrella",
	logtypes.Config{
		Name:         TypeDNS,
		Description:  `DNS logs show traffic that has reached our DNS resolvers.`,
		ReferenceURL: `https://docs.umbrella.com/deployment-umbrella/docs/log-formats-and-versioning#section-dns-logs`,
		Schema:       &DNS{},
		NewParser:    parsers.AdapterFactory(&DNSParser{}),
	},
	logtypes.Config{
		Name:         TypeCloudFirewall,
		Description:  `Cloud Firewall logs show traffic that has been handled by network tunnels.`,
		ReferenceURL: `https://docs.umbrella.com/deployment-umbrella/docs/log-formats-and-versioning#section-cloud-firewall-logs`,
		Schema:       &CloudFirewall{},
		NewParser:    parsers.AdapterFactory(&CloudFirewallParser{}),
	},
	logtypes.Config{
		Name:         TypeIP,
		Description:  `IP logs show traffic that has been handled by the IP Layer Enforcement feature.`,
		ReferenceURL: `https://docs.umbrella.com/deployment-umbrella/docs/log-formats-and-versioning#section-ip-logs`,
		Schema:       &IP{},
		NewParser:    parsers.AdapterFactory(&IPParser{}),
	},
	logtypes.Config{
		Name:         TypeProxy,
		Description:  `Proxy logs show traffic that has passed through the Umbrella Secure Web Gateway or the Selective Proxy.`,
		ReferenceURL: `https://docs.umbrella.com/deployment-umbrella/docs/log-formats-and-versioning#section-proxy-logs`,
		Schema:       &Proxy{},
		NewParser:    parsers.AdapterFactory(&IPParser{}),
	},
)
