package awslogs

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
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/csvstream"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var VPCFlowDesc = `VPCFlow is a VPC NetFlow log, which is a layer 3 representation of network traffic in EC2.
Log format & samples can be seen here: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html`

// nolint:lll
type VPCFlow struct { // NOTE: since fields are customizable by users, the only "required" fields are the Start/End times since those are critical and data is useless w/out those
	Version     *int               `json:"version,omitempty"  description:"The VPC Flow Logs version. If you use the default format, the version is 2. If you specify a custom format, the version is 3."`
	AccountID   *string            `json:"account,omitempty" validate:"omitempty,len=12,numeric" description:"The AWS account ID for the flow log."`
	InterfaceID *string            `json:"interfaceId,omitempty" description:"The ID of the network interface for which the traffic is recorded."`
	SrcAddr     *string            `json:"srcAddr,omitempty" description:"The source address for incoming traffic, or the IPv4 or IPv6 address of the network interface for outgoing traffic on the network interface. The IPv4 address of the network interface is always its private IPv4 address. "`
	DstAddr     *string            `json:"dstAddr,omitempty" description:"The destination address for outgoing traffic, or the IPv4 or IPv6 address of the network interface for incoming traffic on the network interface. The IPv4 address of the network interface is always its private IPv4 address."`
	SrcPort     *int               `json:"srcPort,omitempty" validate:"omitempty,min=0,max=65535" description:"The source port of the traffic."`
	DstPort     *int               `json:"dstPort,omitempty" validate:"omitempty,min=0,max=65535" description:"The destination port of the traffic."`
	Protocol    *int               `json:"protocol,omitempty" description:"The IANA protocol number of the traffic."`
	Packets     *int               `json:"packets,omitempty" description:"The number of packets transferred during the flow."`
	Bytes       *int               `json:"bytes,omitempty" description:"The number of bytes transferred during the flow."`
	Start       *timestamp.RFC3339 `json:"start,omitempty" validate:"required" description:"The time of the start of the flow (UTC)."`
	End         *timestamp.RFC3339 `json:"end,omitempty" validate:"required" description:"The time of the end of the flow (UTC)."`
	Action      *string            `json:"action,omitempty" validate:"omitempty,oneof=ACCEPT REJECT" description:"The action that is associated with the traffic. ACCEPT: The recorded traffic was permitted by the security groups or network ACLs. REJECT: The recorded traffic was not permitted by the security groups or network ACLs."`
	LogStatus   *string            `json:"status,omitempty" validate:"oneof=OK NODATA SKIPDATA" description:"The logging status of the flow log. OK: Data is logging normally to the chosen destinations. NODATA: There was no network traffic to or from the network interface during the capture window. SKIPDATA: Some flow log records were skipped during the capture window. This may be because of an internal capacity constraint, or an internal error."`

	// extended custom fields
	VpcID         *string `json:"vpcId,omitempty" description:"The ID of the VPC that contains the network interface for which the traffic is recorded."`
	SubNetID      *string `json:"subNetId,omitempty" description:"The ID of the subnet that contains the network interface for which the traffic is recorded."`
	InstanceID    *string `json:"instanceId,omitempty" description:"The ID of the instance that's associated with network interface for which the traffic is recorded, if the instance is owned by you. Returns a '-' symbol for a requester-managed network interface; for example, the network interface for a NAT gateway."`
	TCPFlags      *int    `json:"tcpFlags,omitempty" description:"The bitmask value for the following TCP flags: SYN: 2, SYN-ACK: 18, FIN: 1, RST: 4. ACK is reported only when it's accompanied with SYN. TCP flags can be OR-ed during the aggregation interval. For short connections, the flags might be set on the same line in the flow log record, for example, 19 for SYN-ACK and FIN, and 3 for SYN and FIN."`
	Type          *string `json:"trafficType,omitempty" description:"The type of traffic: IPv4, IPv6, or EFA."`
	PacketSrcAddr *string `json:"pktSrcAddr,omitempty" description:"The packet-level (original) source IP address of the traffic. Use this field with the srcaddr field to distinguish between the IP address of an intermediate layer through which traffic flows, and the original source IP address of the traffic. For example, when traffic flows through a network interface for a NAT gateway, or where the IP address of a pod in Amazon EKS is different from the IP address of the network interface of the instance node on which the pod is running."`
	PacketDstAddr *string `json:"pktDstAddr,omitempty" description:"The packet-level (original) destination IP address for the traffic. Use this field with the dstaddr field to distinguish between the IP address of an intermediate layer through which traffic flows, and the final destination IP address of the traffic. For example, when traffic flows through a network interface for a NAT gateway, or where the IP address of a pod in Amazon EKS is different from the IP address of the network interface of the instance node on which the pod is running."`

	// NOTE: added to end of struct to allow expansion later
	AWSPantherLog
}

// VPCFlowParser parses AWS VPC Flow Parser logs
type VPCFlowParser struct {
	CSVReader *csvstream.StreamingCSVReader
	columnMap map[int]string // column position to header name
}

var _ parsers.LogParser = (*VPCFlowParser)(nil)

func (p *VPCFlowParser) New() parsers.LogParser {
	reader := csvstream.NewStreamingCSVReader()
	// non-default settings
	reader.CVSReader.Comma = ' '
	return &VPCFlowParser{
		CSVReader: reader,
	}
}

const (
	vpcFlowHeaderThreshold = 5 // the number of headers that have to match to detect as VPCFlow
	vpcFlowVersion         = "version"
	vpcFlowAccountID       = "account-id"
	vpcFlowInterfaceID     = "interface-id"
	vpcFlowSrcAddr         = "srcaddr"
	vpcFlowDstAddr         = "dstaddr"
	vpcFlowSrcPort         = "srcport"
	vpcFlowDstPort         = "dstport"
	vpcFlowProtocol        = "protocol"
	vpcFlowPackets         = "packets"
	vpcFlowBytes           = "bytes"
	vpcFlowStart           = "start"
	vpcFlowEnd             = "end"
	vpcFlowAction          = "action"
	vpcFlowLogStatus       = "log-status"
	vpcFlowVpcID           = "vpc-id"
	vpcFlowSubNetID        = "subnet-id"
	vpcFlowInstanceID      = "instance-id"
	vpcFlowTCPFlags        = "tcp-flags"
	vpcFlowType            = "type"
	vpcFlowPktSrcAddr      = "pkt-srcaddr"
	vpcFlowPktDstAddr      = "pkt-dstaddr"
)

var (
	//  https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-log-records
	vpcFlowHeaders = map[string]struct{}{
		// default fields
		vpcFlowVersion:     {},
		vpcFlowAccountID:   {},
		vpcFlowInterfaceID: {},
		vpcFlowSrcAddr:     {},
		vpcFlowDstAddr:     {},
		vpcFlowSrcPort:     {},
		vpcFlowDstPort:     {},
		vpcFlowProtocol:    {},
		vpcFlowPackets:     {},
		vpcFlowBytes:       {},
		vpcFlowStart:       {},
		vpcFlowEnd:         {},
		vpcFlowAction:      {},
		vpcFlowLogStatus:   {},
		// extended custom fields
		vpcFlowVpcID:      {},
		vpcFlowSubNetID:   {},
		vpcFlowInstanceID: {},
		vpcFlowTCPFlags:   {},
		vpcFlowType:       {},
		vpcFlowPktSrcAddr: {},
		vpcFlowPktDstAddr: {},
	}
)

// Parse returns the parsed events or nil if parsing failed
func (p *VPCFlowParser) Parse(log string) ([]*parsers.PantherLog, error) {
	if p.columnMap == nil { // must be first log line in file
		if p.isVpcFlowHeader(log) { // if this is a header, return success but no events and setup p.columnMap
			return []*parsers.PantherLog{}, nil
		}
		return nil, errors.New("invalid header")
	}

	record, err := p.CSVReader.Parse(log)
	if err != nil {
		return nil, err
	}

	event := p.populateEvent(record) // parser should only receive 1 line at a time

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		return nil, err
	}

	return event.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *VPCFlowParser) LogType() string {
	return "AWS.VPCFlow"
}

func (p *VPCFlowParser) isVpcFlowHeader(log string) bool {
	// CloudTrail can be detected as VPCFlow due to lucky token matching, skip JSON looking things here!
	if len(log) > 0 && log[0] == '{' {
		return false
	}
	headers := strings.Split(log, " ")
	matchCount := 0
	for _, header := range headers {
		header = strings.TrimSpace(header) // just in case
		if _, exists := vpcFlowHeaders[header]; exists {
			matchCount++
		}
	}

	// require a minimal number of matching fields
	if matchCount < vpcFlowHeaderThreshold {
		return false
	}

	p.columnMap = make(map[int]string, len(headers))
	for i, header := range headers {
		header = strings.TrimSpace(header) // just in case there are extra spaces (I don't trust them to get this right)
		p.columnMap[i] = header
	}

	return true
}

func (p *VPCFlowParser) populateEvent(columns []string) (event *VPCFlow) {
	event = &VPCFlow{}

	for i := range columns {
		switch p.columnMap[i] {
		// default fields
		case vpcFlowVersion:
			event.Version = parsers.CsvStringToIntPointer(columns[i])
		case vpcFlowAccountID:
			if columns[i] != "-" && columns[i] != "unknown" {
				event.AccountID = &columns[i]
			}
		case vpcFlowInterfaceID:
			event.InterfaceID = parsers.CsvStringToPointer(columns[i])
		case vpcFlowSrcAddr:
			event.SrcAddr = parsers.CsvStringToPointer(columns[i])
		case vpcFlowDstAddr:
			event.DstAddr = parsers.CsvStringToPointer(columns[i])
		case vpcFlowSrcPort:
			event.SrcPort = parsers.CsvStringToIntPointer(columns[i])
		case vpcFlowDstPort:
			event.DstPort = parsers.CsvStringToIntPointer(columns[i])
		case vpcFlowProtocol:
			event.Protocol = parsers.CsvStringToIntPointer(columns[i])
		case vpcFlowPackets:
			event.Packets = parsers.CsvStringToIntPointer(columns[i])
		case vpcFlowBytes:
			event.Bytes = parsers.CsvStringToIntPointer(columns[i])
		case vpcFlowStart:
			startTimeUnix, err := strconv.Atoi(columns[i])
			if err != nil {
				return nil
			}
			ts := timestamp.Unix(int64(startTimeUnix), 0)
			event.Start = &ts
		case vpcFlowEnd:
			endTimeUnix, err := strconv.Atoi(columns[i])
			if err != nil {
				return nil
			}
			ts := timestamp.Unix(int64(endTimeUnix), 0)
			event.End = &ts
		case vpcFlowAction:
			event.Action = parsers.CsvStringToPointer(columns[i])
		case vpcFlowLogStatus:
			event.LogStatus = parsers.CsvStringToPointer(columns[i])

			// extended custom fields
		case vpcFlowVpcID:
			event.VpcID = parsers.CsvStringToPointer(columns[i])
		case vpcFlowSubNetID:
			event.SubNetID = parsers.CsvStringToPointer(columns[i])
		case vpcFlowInstanceID:
			event.InstanceID = parsers.CsvStringToPointer(columns[i])
		case vpcFlowTCPFlags:
			event.TCPFlags = parsers.CsvStringToIntPointer(columns[i])
		case vpcFlowType:
			event.Type = parsers.CsvStringToPointer(columns[i])
		case vpcFlowPktSrcAddr:
			event.PacketSrcAddr = parsers.CsvStringToPointer(columns[i])
		case vpcFlowPktDstAddr:
			event.PacketDstAddr = parsers.CsvStringToPointer(columns[i])
		default:
			zap.L().Warn(fmt.Sprintf("unknown %s header %s (could be a new header, check AWS documentation)", p.LogType(), p.columnMap[i]))
		}
	}

	return event
}

func (event *VPCFlow) updatePantherFields(p *VPCFlowParser) {
	event.SetCoreFields(p.LogType(), event.Start, event)
	event.AppendAnyAWSAccountIdPtrs(event.AccountID)
	event.AppendAnyAWSInstanceIdPtrs(event.InstanceID)
	event.AppendAnyIPAddressPtr(event.SrcAddr)
	event.AppendAnyIPAddressPtr(event.DstAddr)
	event.AppendAnyIPAddressPtr(event.PacketSrcAddr)
	event.AppendAnyIPAddressPtr(event.PacketDstAddr)
}
