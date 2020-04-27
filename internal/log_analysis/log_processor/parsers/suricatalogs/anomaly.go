package suricatalogs

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var AnomalyDesc = `Suricata parser for the Anomaly event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html#anomaly`

//nolint:lll
type Anomaly struct {
	Anomaly      *AnomalyDetails              `json:"anomaly" validate:"required,dive" description:"Suricata Anomaly Anomaly"`
	AppProto     *string                      `json:"app_proto,omitempty" description:"Suricata Anomaly AppProto"`
	CommunityID  *string                      `json:"community_id,omitempty" description:"Suricata Anomaly CommunityID"`
	DestIP       *string                      `json:"dest_ip,omitempty" description:"Suricata Anomaly DestIP"`
	DestPort     *uint16                      `json:"dest_port,omitempty" description:"Suricata Anomaly DestPort"`
	EventType    *string                      `json:"event_type" validate:"required,eq=anomaly" description:"Suricata Anomaly EventType"`
	FlowID       *int                         `json:"flow_id,omitempty" description:"Suricata Anomaly FlowID"`
	IcmpCode     *int                         `json:"icmp_code,omitempty" description:"Suricata Anomaly IcmpCode"`
	IcmpType     *int                         `json:"icmp_type,omitempty" description:"Suricata Anomaly IcmpType"`
	Metadata     *AnomalyMetadata             `json:"metadata,omitempty" validate:"omitempty,dive" description:"Suricata Anomaly Metadata"`
	Packet       *string                      `json:"packet,omitempty" description:"Suricata Anomaly Packet"`
	PacketInfo   *AnomalyPacketInfo           `json:"packet_info,omitempty" validate:"omitempty,dive" description:"Suricata Anomaly PacketInfo"`
	PcapCnt      *int                         `json:"pcap_cnt,omitempty" description:"Suricata Anomaly PcapCnt"`
	PcapFilename *string                      `json:"pcap_filename,omitempty" description:"Suricata Anomaly PcapFilename"`
	Proto        *numerics.Integer            `json:"proto,omitempty" description:"Suricata Anomaly Proto"`
	SrcIP        *string                      `json:"src_ip,omitempty" description:"Suricata Anomaly SrcIP"`
	SrcPort      *uint16                      `json:"src_port,omitempty" description:"Suricata Anomaly SrcPort"`
	Timestamp    *timestamp.SuricataTimestamp `json:"timestamp" validate:"required" description:"Suricata Anomaly Timestamp"`
	TxID         *int                         `json:"tx_id,omitempty" description:"Suricata Anomaly TxID"`
	Vlan         []int                        `json:"vlan,omitempty" description:"Suricata Anomaly Vlan"`
}

//nolint:lll
type AnomalyPacketInfo struct {
	Linktype *int `json:"linktype,omitempty" description:"Suricata AnomalyPacketInfo Linktype"`
}

//nolint:lll
type AnomalyDetails struct {
	Code  *int    `json:"code,omitempty" description:"Suricata AnomalyDetails Code"`
	Event *string `json:"event,omitempty" description:"Suricata AnomalyDetails Event"`
	Layer *string `json:"layer,omitempty" description:"Suricata AnomalyDetails Layer"`
	Type  *string `json:"type,omitempty" description:"Suricata AnomalyDetails Type"`
}

//nolint:lll
type AnomalyMetadata struct {
	Flowbits []string                 `json:"flowbits,omitempty" description:"Suricata AnomalyMetadata Flowbits"`
	Flowints *AnomalyMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive" description:"Suricata AnomalyMetadata Flowints"`
}

//nolint:lll
type AnomalyMetadataFlowints struct {
	ApplayerAnomalyCount   *int `json:"applayer.anomaly.count,omitempty" description:"Suricata AnomalyMetadataFlowints ApplayerAnomalyCount"`
	HTTPAnomalyCount       *int `json:"http.anomaly.count,omitempty" description:"Suricata AnomalyMetadataFlowints HTTPAnomalyCount"`
	TCPRetransmissionCount *int `json:"tcp.retransmission.count,omitempty" description:"Suricata AnomalyMetadataFlowints TCPRetransmissionCount"`
	TLSAnomalyCount        *int `json:"tls.anomaly.count,omitempty" description:"Suricata AnomalyMetadataFlowints TLSAnomalyCount"`
}

// AnomalyParser parses Suricata Anomaly alerts in the JSON format
type AnomalyParser struct{}

var _ parsers.LogParser = (*AnomalyParser)(nil)

func (p *AnomalyParser) New() parsers.LogParser {
	return &AnomalyParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *AnomalyParser) Parse(log string) ([]*parsers.PantherLogJSON, error) {
	event := &Anomaly{}
	return parsers.QuickParseJSON(event, log)
}

// LogType returns the log type supported by this parser
func (p *AnomalyParser) LogType() string {
	return TypeAnomaly
}

const TypeAnomaly = "Suricata.Anomaly"

func (event *Anomaly) PantherEvent() *parsers.PantherEvent {
	return parsers.NewEvent(TypeAnomaly, event.Timestamp.UTC(),
		parsers.IPAddress(aws.StringValue(event.SrcIP)),
		parsers.IPAddress(aws.StringValue(event.DestIP)),
	)
}
