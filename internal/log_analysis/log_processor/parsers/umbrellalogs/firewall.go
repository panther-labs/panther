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
	"errors"
	"strconv"
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/csvstream"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

type CloudFirewallParser struct {
	*csvstream.StreamingCSVReader
}

var _ parsers.LogParser = (*CloudFirewallParser)(nil)

func NewCloudFirewallParser() *CloudFirewallParser {
	return &CloudFirewallParser{
		StreamingCSVReader: csvstream.NewStreamingCSVReader(),
	}
}

func (p *CloudFirewallParser) LogType() string {
	return TypeCloudFirewall
}

func (p *CloudFirewallParser) New() parsers.LogParser {
	return NewCloudFirewallParser()
}

func (p *CloudFirewallParser) Parse(log string) ([]*parsers.PantherLog, error) {
	row, err := p.StreamingCSVReader.Parse(log)
	if err != nil {
		return nil, err
	}
	event := CloudFirewall{}
	if err := event.setRow(row); err != nil {
		return nil, err
	}
	event.updatePantherFields(&event.PantherLog)
	return event.Logs(), nil
}

// nolint:lll,maligned
type CloudFirewall struct {
	Timestamp       timestamp.RFC3339 `json:"timestamp" validate:"required" description:"The timestamp of the request transaction in UTC (2015-01-16 17:48:41)."`
	OriginID        string            `json:"originId,omitempty" description:"The unique identity of the network tunnel."`
	Identity        string            `json:"identity,omitempty" description:"The name of the network tunnel."`
	IdentityType    string            `json:"identityType,omitempty" description:"The type of identity that made the request. Should always be 'CDFW Tunnel Device'."`
	Direction       string            `json:"direction,omitempty" description:"The direction of the packet. It is destined either towards the internet or to the customer's network."`
	IPProtocol      uint16            `json:"ipProtocol" description:"The actual IP protocol of the traffic. It could be TCP, UDP, ICMP."`
	PacketSize      uint16            `json:"packetSize,omitempty" description:"The size of the packet that Umbrella CDFW received."`
	SourceIP        string            `json:"sourceIp,omitempty" description:"The internal IP address of the user-generated traffic towards the CDFW. If the traffic goes through NAT before it comes to CDFW, it will be the NAT IP address."`
	SourcePort      uint16            `json:"sourcePort,omitempty" description:"The internal port number of the user-generated traffic towards the CDFW."`
	DestinationIP   string            `json:"destinationIp,omitempty" description:"The destination IP address of the user-generated traffic towards the CDFW."`
	DestinationPort uint16            `json:"destinationPort,omitempty" description:"The destination port number of the user-generated traffic towards the CDFW."`
	DataCenter      string            `json:"dataCenter,omitempty" description:"The name of the Umbrella Data Center that processed the user-generated traffic."`
	RuleID          string            `json:"ruleId,omitempty" description:"The ID of the rule that processed the user traffic."`
	Verdict         string            `json:"verdict,omitempty" description:"The final verdict whether to allow or block the traffic based on the rule."`

	parsers.PantherLog
}

func (event *CloudFirewall) setRow(row []string) error {
	const numFieldsCloudFirewall = 14
	if len(row) != numFieldsCloudFirewall {
		return errors.New("invalid number of fields")
	}
	fields := struct {
		Timestamp       string
		IPProtocol      string
		PacketSize      string
		SourcePort      string
		DestinationPort string
	}{
		Timestamp:       row[0],
		IPProtocol:      row[5],
		PacketSize:      row[6],
		SourcePort:      row[8],
		DestinationPort: row[10],
	}
	tm, err := time.ParseInLocation(layoutUmbrellaTimestamp, fields.Timestamp, time.UTC)
	if err != nil {
		return err
	}
	// IP protocol has an upper limit of 2^16 for packets
	packetSize, err := strconv.ParseUint(fields.PacketSize, 10, 16)
	if err != nil {
		return err
	}
	ipProtocol, err := strconv.ParseUint(fields.IPProtocol, 10, 16)
	if err != nil {
		return err
	}
	var (
		// Ports seem to be able to be missing in docs sample
		sourcePort, _      = strconv.ParseUint(fields.SourcePort, 10, 16)
		destinationPort, _ = strconv.ParseUint(fields.DestinationPort, 10, 16)
	)

	*event = CloudFirewall{
		Timestamp:       timestamp.RFC3339(tm),
		OriginID:        row[1],
		Identity:        row[2],
		IdentityType:    row[3],
		Direction:       row[4],
		IPProtocol:      uint16(ipProtocol),
		PacketSize:      uint16(packetSize),
		SourceIP:        row[7],
		SourcePort:      uint16(sourcePort),
		DestinationIP:   row[9],
		DestinationPort: uint16(destinationPort),

		DataCenter: row[11],
		RuleID:     row[12],
		Verdict:    row[13],
	}
	return nil
}

func (event *CloudFirewall) updatePantherFields(p *parsers.PantherLog) {
	p.SetCoreFields(TypeCloudFirewall, &event.Timestamp, event)
	p.AppendAnyIPAddress(event.SourceIP)
	p.AppendAnyIPAddress(event.DestinationIP)
}
