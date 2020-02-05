package awslogs

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"encoding/csv"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const (
	vpcFlowMinNumberOfColumns = 14 // At _least_ this many, FIXME: we are currently not parsing all columns!
)

var VPCFlowDesc = `VPCFlow is a VPC NetFlow log, which is a layer 3 representation of network traffic in EC2.
Log format & samples can be seen here: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html`

// nolint:lll
type VPCFlow struct {
	Version     *int               `json:"version,omitempty" validate:"required" description:"The VPC Flow Logs version. If you use the default format, the version is 2. If you specify a custom format, the version is 3."`
	Account     *string            `json:"account,omitempty" validate:"omitempty,len=12,numeric" description:"The AWS account ID for the flow log."`
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

	// NOTE: added to end of struct to allow expansion later
	AWSPantherLog
}

// VPCFlowParser parses AWS VPC Flow Parser logs
type VPCFlowParser struct{}

var (
	vpcFlowHeaders = map[string]struct{} {
		"version": struct{}{},
		"account-id": struct{}{},
		"interface-id": struct{}{},
		"srcaddr": struct{}{},
		"dstaddr": struct{}{},
		"srcport": struct{}{},
		"dstport": struct{}{},
		"protocol": struct{}{},
		"packets": struct{}{},
		"bytes": struct{}{},
		"start": struct{}{},
		"end": struct{}{},
		"action": struct{}{},
		"log-status": struct{}{},
	}
)

func isVpcFlowHeader(log string) bool {
	headers := strings.Split(log, " ")
	matchCount := 0
	for _, header := range headers {
		header = strings.TrimSpace(header) // just in case
		if _, exists := vpcFlowHeaders[header]; exists {
			matchCount++
		}
	}
	return matchCount == len(headers) // should we allow a % match in case new fields are added by AWS?
}

func (p *VPCFlowParser) ParseHeader(log string) []interface{} {
	// If this is a header, return success but no events
	if isVpcFlowHeader(log) {
		return []interface{}{} // empty list
	}
	return nil
}

// Parse returns the parsed events or nil if parsing failed
func (p *VPCFlowParser) Parse(log string) []interface{} {
	reader := csv.NewReader(strings.NewReader(log))
	reader.Comma = ' '

	records, err := reader.ReadAll()
	if len(records) == 0 || err != nil {
		zap.L().Debug("failed to parse the log as csv")
		return nil
	}

	// parser should only receive 1 line at a time
	record := records[0]

	if len(record) < vpcFlowMinNumberOfColumns {
		zap.L().Debug("failed to parse the log as csv (wrong number of columns)")
		return nil
	}

	var account *string = nil
	if record[1] != "-" && record[1] != "unknown" {
		account = &record[1]
	}

	startTimeUnix, err := strconv.Atoi(record[10])
	if err != nil {
		return nil
	}
	endTimeUnix, err := strconv.Atoi(record[11])
	if err != nil {
		return nil
	}

	startTime := timestamp.Unix(int64(startTimeUnix), 0)
	endTime := timestamp.Unix(int64(endTimeUnix), 0)

	event := &VPCFlow{
		Version:     parsers.CsvStringToIntPointer(record[0]),
		Account:     account,
		InterfaceID: parsers.CsvStringToPointer(record[2]),
		SrcAddr:     parsers.CsvStringToPointer(record[3]),
		DstAddr:     parsers.CsvStringToPointer(record[4]),
		SrcPort:     parsers.CsvStringToIntPointer(record[5]),
		DstPort:     parsers.CsvStringToIntPointer(record[6]),
		Protocol:    parsers.CsvStringToIntPointer(record[7]),
		Packets:     parsers.CsvStringToIntPointer(record[8]),
		Bytes:       parsers.CsvStringToIntPointer(record[9]),
		Start:       &startTime,
		End:         &endTime,
		Action:      parsers.CsvStringToPointer(record[12]),
		LogStatus:   parsers.CsvStringToPointer(record[13]),
	}

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return []interface{}{event}
}

// LogType returns the log type supported by this parser
func (p *VPCFlowParser) LogType() string {
	return "AWS.VPCFlow"
}

func (event *VPCFlow) updatePantherFields(p *VPCFlowParser) {
	event.SetRequiredPtr(p.LogType(), event.Start)
	event.AppendAnyAWSAccountIdPtrs(event.Account)
	event.AppendAnyIPAddressPtrs(event.SrcAddr, event.DstAddr)
}
