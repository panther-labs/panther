package ossec

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
	"fmt"

	"go.uber.org/zap"

	jsoniter "github.com/json-iterator/go"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var EventInfoDesc = `OSSEC EventInfo alert parser. Currently only JSON output is supported.
Reference: https://www.ossec.net/docs/docs/formats/alerts.html`

// nolint:lll
type EventInfo struct {
	// Required
	ID        *string                    `json:"id" validate:"required" description:"Event ID (timestamp.streamposition)"`
	Rule      *Rule                      `json:"rule" validate:"required" description:"Rule object with information about what rule created the alert"`
	Timestamp *timestamp.UnixMillisecond `json:"TimeStamp" validate:"required" description:"Timestamp in Unix Epoch (Milliseconds)"`
	Location  *string                    `json:"location" validate:"required" description:"Source of the alert (filename or command)"`
	Hostname  *string                    `json:"hostname" validate:"required" description:"Hostname of the host that generated the alert"`
	FullLog   *string                    `json:"full_log" validate:"required" description:"The full captured log of the alert"`

	// Optional
	Action             *string   `json:"action,omitempty" description:"Action"`
	AgentIP            *string   `json:"agentip,omitempty" description:"AgentIP"`
	AgentName          *string   `json:"agent_name,omitempty" description:"AgentName"`
	Command            *string   `json:"command,omitempty" description:"Command"`
	Data               *string   `json:"data,omitempty" description:"Data"`
	Decoder            *string   `json:"decoder,omitempty" description:"Decoder"`
	DecoderDescription *Decoder  `json:"decoder_desc,omitempty" description:"DecoderDescription"`
	DecoderParent      *string   `json:"decoder_parent,omitempty" description:"DecoderParent"`
	DstGeoIP           *string   `json:"dstgeoip,omitempty" description:"DstGeoIP"`
	DstIP              *string   `json:"dstip,omitempty" description:"DstIP"`
	DstPort            *string   `json:"dstport,omitempty" description:"DstPort"`
	DstUser            *string   `json:"dstuser,omitempty" description:"DstUser"`
	Logfile            *string   `json:"logfile,omitempty" description:"Logfile"`
	PreviousOutput     *string   `json:"previous_output,omitempty" description:"PreviousOutput"`
	ProgramName        *string   `json:"program_name,omitempty" description:"ProgramName"`
	Protocol           *string   `json:"protocol,omitempty" description:"Protocol"`
	SrcGeoIP           *string   `json:"srcgeoip,omitempty" description:"SrcGeoIP"`
	SrcIP              *string   `json:"srcip,omitempty" description:"SrcIP"`
	SrcPort            *string   `json:"srcport,omitempty" description:"SrcPort"`
	SrcUser            *string   `json:"srcuser,omitempty" description:"SrcUser"`
	Status             *string   `json:"status,omitempty" description:"Status"`
	Syscheckfile       *FileDiff `json:"SyscheckFile,omitempty" description:"Syscheckfile"`
	Systemname         *string   `json:"systemname,omitempty" description:"Systemname"`
	URL                *string   `json:"url,omitempty" description:"URL"`

	// Deliberately ommited because duplicate case insensitive keys cause problems in Athena
	// TimestampString    *string                    `json:"timestamp,omitempty" description:"TimestampString"`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

type Rule struct {
	// Required
	Comment *string `json:"comment" validate:"required"`
	Group   *string `json:"group" validate:"required"`
	Level   *int    `json:"level" validate:"required"`
	SIDID   *int    `json:"sidid" validate:"required"`

	// Optional
	CIS        *[]string `json:"CIS,omitempty"`
	CVE        *string   `json:"cve,omitempty"`
	Firedtimes *int      `json:"firedtimes,omitempty"`
	Frequency  *int      `json:"frequency,omitempty"`
	Groups     *[]string `json:"groups,omitempty"`
	Info       *string   `json:"info,omitempty"`
	PCIDSS     *[]string `json:"PCI_DSS,omitempty"`
}

type FileDiff struct {
	GroupOwnerAfter  *string `json:"gowner_after,omitempty"`
	GroupOwnerBefore *string `json:"gowner_before,omitempty"`
	Md5After         *string `json:"md5_after,omitempty"`
	Md5Before        *string `json:"md5_before,omitempty"`
	OwnerAfter       *string `json:"owner_after,omitempty"`
	OwnerBefore      *string `json:"owner_before,omitempty"`
	Path             *string `json:"path,omitempty"`
	PermAfter        *int    `json:"perm_after,omitempty"`
	PermBefore       *int    `json:"perm_before,omitempty"`
	SHA1After        *string `json:"sha1_after,omitempty"`
	SHA1Before       *string `json:"sha1_before,omitempty"`
}

type Decoder struct {
	Accumulate *int    `json:"accumulate,omitempty"`
	Fts        *int    `json:"fts,omitempty"`
	Ftscomment *string `json:"ftscomment,omitempty"`
	Name       *string `json:"name,omitempty"`
	Parent     *string `json:"parent,omitempty"`
}

// EventInfoParser parses OSSEC EventInfo alerts in the JSON format
type EventInfoParser struct{}

func (p *EventInfoParser) New() parsers.LogParser {
	return &EventInfoParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *EventInfoParser) Parse(log string) []interface{} {
	eventInfo := &EventInfo{}

	err := jsoniter.UnmarshalFromString(log, eventInfo)
	if err != nil {
		fmt.Println(err)
		zap.L().Error("failed to parse log", zap.Error(err))
		return nil
	}

	eventInfo.updatePantherFields(p)

	if err := parsers.Validator.Struct(eventInfo); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return []interface{}{eventInfo}
}

// LogType returns the log type supported by this parser
func (p *EventInfoParser) LogType() string {
	return "OSSEC.EventInfo"
}

func (event *EventInfo) updatePantherFields(p *EventInfoParser) {
	event.SetCoreFieldsPtr(p.LogType(), (*timestamp.RFC3339)(event.Timestamp))
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DstIP)
}
