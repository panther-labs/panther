package juniperlogs

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
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeFirewall = `Juniper.Firewall`

type FirewallParser struct {
	timestampParser
}

var _ parsers.LogParser = (*FirewallParser)(nil)

func NewFirewallParser() *FirewallParser {
	return &FirewallParser{
		timestampParser: timestampParser{
			Now: time.Now(),
		},
	}
}

func (*FirewallParser) New() parsers.LogParser {
	return NewFirewallParser()
}
func (*FirewallParser) LogType() string {
	return TypeFirewall
}

func (p *FirewallParser) Parse(log string) ([]*parsers.PantherLog, error) {
	match := rxFirewall.FindStringSubmatch(log)
	if match == nil {
		return nil, errors.New("invalid log line")
	}
	fields := struct {
		Timestamp string
		Hostname  string
		Event     string
		IPTables  string
	}{
		Timestamp: match[1],
		Hostname:  match[2],
		Event:     match[3],
		IPTables:  match[4],
	}
	ts, err := p.ParseTimestamp(fields.Timestamp)
	if err != nil {
		return nil, err
	}

	event := Firewall{
		Timestamp: timestamp.RFC3339(ts),
		Hostname:  fields.Hostname,
		Event:     fields.Event,
	}
	if err := event.IPTables.unmarshalString(fields.IPTables); err != nil {
		return nil, err
	}
	event.updatePantherFields(&event.PantherLog)
	return event.Logs(), nil
}

type Firewall struct {
	Timestamp timestamp.RFC3339 `json:"timestamp" validate:"required" description:"Log timestamp"`
	Hostname  string            `json:"hostname" description:"Hostname"`
	Event     string            `json:"event" description:"Event name"`
	IPTables

	parsers.PantherLog
}

// nolint:maligned
type IPTables struct {
	DestinationIP   string `json:"DST,omitempty" description:"Destination IP address"`
	DestinationPort uint16 `json:"DPT,omitempty" description:"Destination port"`
	SourceIP        string `json:"SRC,omitempty" description:"Source IP address"`
	SourcePort      uint16 `json:"SPT,omitempty" description:"Source port"`
	PacketTTL       int64  `json:"TTL,omitempty" description:"IP TTL in milliseconds"`
	PacketID        int64  `json:"ID" description:"Packet id"`
	MACAddress      string `json:"MAC,omitempty" description:"MAC address"`
	PacketLength    uint16 `json:"LEN,omitempty" description:"Packet length"`
	TypeOfService   string `json:"TOS,omitempty" description:"Packet Type of Service field"`
	Precedence      string `json:"PREC,omitempty" description:"Packet precedence bits"`
	RST             bool   `json:"RST,omitempty" description:"Packet is RST"`
	SYN             bool   `json:"SYN,omitempty" description:"Packet is SYN"`
	DoNotFragment   bool   `json:"DF,omitempty" description:"Packet has do not fragment flag"`
	Input           string `json:"IN,omitempty" description:"Input interface"`
	Output          string `json:"OUT,omitempty" description:"Output interface"`
	Protocol        string `json:"PROTO,omitempty" description:"Protocol"`
	WindowSize      int32  `json:"WINDOW,omitempty" description:"Transmit window"`
}

var rxFirewall = regexp.MustCompile(fmt.Sprintf(
	`^(%s) (\S+) kernel: IPTABLES (\w+):\s*(.+)`,
	rxTimestamp,
))

func (f *Firewall) updatePantherFields(p *parsers.PantherLog) {
	p.SetCoreFields(TypeFirewall, &f.Timestamp, f)
	p.AppendAnyIPAddress(f.DestinationIP)
	p.AppendAnyIPAddress(f.SourceIP)
}

func (t *IPTables) unmarshalString(s string) error {
	s = strings.TrimSpace(s)
	for _, field := range strings.Split(s, " ") {
		switch k, v := parseField(field); k {
		case "ID":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return err
			}
			t.PacketID = n
		case "TTL":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return err
			}
			t.PacketTTL = n
		case "DST":
			t.DestinationIP = v
		case "SRC":
			t.SourceIP = v
		case "DPT":
			port, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return err
			}
			t.DestinationPort = uint16(port)
		case "SPT":
			port, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return err
			}
			t.SourcePort = uint16(port)
		case "IN":
			t.Input = v
		case "OUT":
			t.Output = v
		case "MAC":
			t.MACAddress = v
		case "LEN":
			n, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return err
			}
			t.PacketLength = uint16(n)
		case "TOS":
			t.TypeOfService = v
		case "PREC":
			t.Precedence = v
		case "PROTO":
			t.Protocol = v
		case "WINDOW":
			n, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return err
			}
			t.WindowSize = int32(n)
		case "SYN":
			t.SYN = true
		case "DF":
			t.DoNotFragment = true
		case "RST":
			t.RST = true
		}
	}
	return nil
}

func parseField(f string) (k, v string) {
	if pos := strings.IndexByte(f, '='); 0 <= pos && pos < len(f) {
		return f[:pos], f[pos+1:]
	}
	return f, ""
}
