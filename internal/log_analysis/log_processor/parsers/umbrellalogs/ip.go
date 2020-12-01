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
	"strconv"
	"time"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/csvstream"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

type IPParser struct {
	*csvstream.StreamingCSVReader
}

func NewIPParser() *IPParser {
	return &IPParser{
		StreamingCSVReader: csvstream.NewStreamingCSVReader(),
	}
}

var _ parsers.LogParser = (*IPParser)(nil)

func (p *IPParser) LogType() string {
	return TypeIP
}

func (p *IPParser) New() parsers.LogParser {
	return NewIPParser()
}

func (p *IPParser) Parse(log string) ([]*parsers.PantherLog, error) {
	row, err := p.StreamingCSVReader.Parse(log)
	if err != nil {
		return nil, err
	}
	event := IP{}
	if err := event.setRow(row); err != nil {
		return nil, err
	}
	event.updatePantherFields(&event.PantherLog)
	return event.Logs(), nil
}

//nolint:lll,maligned
type IP struct {
	Timestamp       timestamp.RFC3339 `json:"timestamp" validate:"required" description:"The timestamp of the request transaction in UTC (2015-01-16 17:48:41)."`
	Identity        string            `json:"identity,omitempty" description:"The first identity that matched the request."`
	SourceIP        string            `json:"sourceIp,omitempty" description:"The IP of the computer making the request."`
	SourcePort      uint16            `json:"sourcePort,omitempty" description:"The port the request was made on."`
	DestinationIP   string            `json:"destinationIp,omitempty" description:"The destination IP requested."`
	DestinationPort uint16            `json:"destinationPort,omitempty" description:"The destination port the request was made on."`
	Categories      []string          `json:"categories,omitempty" description:"Which security categories, if any, matched against the destination IP address/port requested."`
	// Undocumented field
	IdentityTypes []string `json:"identityTypes,omitempty" description:"The type of identity that made the request. For example, Roaming Computer, Network, and so on. Available in version 3 and above."`

	parsers.PantherLog
}

func (event *IP) setRow(row []string) error {
	const numFieldsIP = 8
	if len(row) != numFieldsIP {
		return errors.New("invalid number of fields")
	}
	fields := struct {
		Timestamp       string
		SourcePort      string
		DestinationPort string
	}{
		Timestamp:       row[0],
		SourcePort:      row[3],
		DestinationPort: row[5],
	}
	tm, err := time.ParseInLocation(layoutUmbrellaTimestamp, fields.Timestamp, time.UTC)
	if err != nil {
		return err
	}
	// Avoid overflows by using strconv.ParseUint bitSize argument and check valid port range
	sourcePort, err := strconv.ParseUint(fields.SourcePort, 10, 16)
	if err != nil {
		return err
	}
	destPort, err := strconv.ParseUint(fields.DestinationPort, 10, 16)
	if err != nil {
		return err
	}

	*event = IP{
		Timestamp:       timestamp.RFC3339(tm),
		Identity:        row[1],
		SourceIP:        row[2],
		SourcePort:      uint16(sourcePort),
		DestinationIP:   row[4],
		DestinationPort: uint16(destPort),
		Categories:      parseList(row[6]),
		IdentityTypes:   parseList(row[7]),
	}
	return nil
}

func (event *IP) updatePantherFields(p *parsers.PantherLog) {
	p.SetCoreFields(TypeIP, &event.Timestamp, event)
	p.AppendAnyIPAddress(event.SourceIP)
	p.AppendAnyIPAddress(event.DestinationIP)
}
