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
	"time"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/csvstream"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

type DNSParser struct {
	*csvstream.StreamingCSVReader
}

var _ parsers.LogParser = (*DNSParser)(nil)

func NewDNSParser() *DNSParser {
	return &DNSParser{
		StreamingCSVReader: csvstream.NewStreamingCSVReader(),
	}
}

func (p *DNSParser) New() parsers.LogParser {
	return NewDNSParser()
}

func (p *DNSParser) LogType() string {
	return TypeDNS
}

func (p *DNSParser) Parse(log string) ([]*parsers.PantherLog, error) {
	row, err := p.StreamingCSVReader.Parse(log)
	if err != nil {
		return nil, err
	}
	event := DNS{}
	if err := event.setRow(row); err != nil {
		return nil, err
	}
	event.updatePantherFields(&event.PantherLog)
	return event.Logs(), nil
}

// nolint:lll
type DNS struct {
	Timestamp      timestamp.RFC3339 `json:"timestamp" validate:"required" description:"When this request was made in UTC. This is different than the Umbrella dashboard, which converts the time to your specified time zone."`
	PolicyIdentity string            `json:"policyIdentity,omitempty" description:"The first identity that matched the request."`
	Identities     []string          `json:"identities,omitempty" description:"All identities associated with this request."`
	InternalIP     string            `json:"internalIp,omitempty" description:"The internal IP address that made the request."`
	ExternalIP     string            `json:"externalIp,omitempty" description:"The external IP address that made the request."`
	Action         string            `json:"action,omitempty" description:"Whether the request was allowed or blocked."`
	QueryType      string            `json:"queryType,omitempty" description:"The type of DNS request that was made. For more information, see Common DNS Request Types."`
	ResponseCode   string            `json:"responseCode,omitempty" description:"The DNS return code for this request. For more information, see Common DNS return codes for any DNS service (and Umbrella)."`
	Domain         string            `json:"domain,omitempty" description:"The domain that was requested."`
	Categories     []string          `json:"categories,omitempty" description:"The security or content categories that the destination matches."`
	// V3
	PolicyIdentityType string   `json:"policyIdentityType,omitempty" description:"The first identity type matched with this request. Available in version 3 and above."`
	IdentityTypes      []string `json:"identityTypes,omitempty" description:"The type of identity that made the request. For example, Roaming Computer, Network, and so on. Available in version 3 and above."`
	// V4
	BlockedCategories []string `json:"blockedCategories,omitempty" description:"The categories that resulted in the destination being blocked. Available in version 4 and above."`

	parsers.PantherLog
}

func (event *DNS) setRow(row []string) error {
	const (
		numFieldsDNS   = 10
		numFieldsDNSV3 = 12
		numFieldsDNSV4 = 13
	)
	if len(row) < numFieldsDNS {
		return errors.New("invalid number of fields")
	}
	tm, err := time.ParseInLocation(layoutUmbrellaTimestamp, row[0], time.UTC)
	if err != nil {
		return err
	}
	*event = DNS{
		Timestamp:      timestamp.RFC3339(tm),
		PolicyIdentity: row[1],
		Identities:     parseList(row[2]),
		InternalIP:     row[3],
		ExternalIP:     row[4],
		Action:         row[5],
		QueryType:      row[6],
		ResponseCode:   row[7],
		Domain:         row[8],
		Categories:     parseList(row[9]),
	}
	if len(row) >= numFieldsDNSV3 {
		event.PolicyIdentityType, event.IdentityTypes = row[10], parseList(row[11])
		if len(row) >= numFieldsDNSV4 {
			event.BlockedCategories = parseList(row[12])
		}
	}
	return nil
}

func (event *DNS) updatePantherFields(p *parsers.PantherLog) {
	p.SetCoreFields(TypeDNS, &event.Timestamp, event)
	p.AppendAnyIPAddress(event.InternalIP)
	p.AppendAnyIPAddress(event.ExternalIP)
	p.AppendAnyDomainNames(strings.TrimRight(event.Domain, "."))
}
