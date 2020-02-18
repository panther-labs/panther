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
	ID                 *string                    `json:"id" validate:"required"`
	Rule               *Rule                      `json:"rule" validate:"required"`
	Timestamp          *timestamp.UnixMillisecond `json:"TimeStamp" validate:"required"`
	Decoder            *string                    `json:"decoder,omitempty"`
	DecoderParent      *string                    `json:"decoder_parent,omitempty"`
	DecoderDescription *Decoder                   `json:"decoder_desc,omitempty"`
	Action             *string                    `json:"action,omitempty"`
	Protocol           *string                    `json:"protocol,omitempty"`
	SrcIP              *string                    `json:"srcip,omitempty"`
	SrcGeoIP           *string                    `json:"srcgeoip,omitempty"`
	SrcPort            *string                    `json:"srcport,omitempty"`
	SrcUser            *string                    `json:"srcuser,omitempty"`
	DstIP              *string                    `json:"dstip,omitempty"`
	DstGeoIP           *string                    `json:"dstgeoip,omitempty"`
	DstPort            *string                    `json:"dstport,omitempty"`
	DstUser            *string                    `json:"dstuser,omitempty"`
	Location           *string                    `json:"location,omitempty"`
	FullLog            *string                    `json:"full_log,omitempty"`
	PreviousOutput     *string                    `json:"previous_output,omitempty"`
	Hostname           *string                    `json:"hostname,omitempty"`
	ProgramName        *string                    `json:"program_name,omitempty"`
	Status             *string                    `json:"status,omitempty"`
	Command            *string                    `json:"command,omitempty"`
	URL                *string                    `json:"url,omitempty"`
	Data               *string                    `json:"data,omitempty"`
	Systemname         *string                    `json:"systemname,omitempty"`
	AgentName          *string                    `json:"agent_name,omitempty"`
	TimestampString    *string                    `json:"timestamp,omitempty"`
	AgentIP            *string                    `json:"agentip,omitempty"`
	Logfile            *string                    `json:"logfile,omitempty"`
	Syscheckfile       *FileDiff                  `json:"SyscheckFile,omitempty"`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

type Rule struct {
	Level      *int      `json:"level,omitempty"`
	Group      *string   `json:"group,omitempty"`
	Comment    *string   `json:"comment,omitempty"`
	SIDID      *int      `json:"sidid,omitempty"`
	CVE        *string   `json:"cve,omitempty"`
	Info       *string   `json:"info,omitempty"`
	Frequency  *int      `json:"frequency,omitempty"`
	Firedtimes *int      `json:"firedtimes,omitempty"`
	Groups     *[]string `json:"groups,omitempty"`
	PCIDSS     *[]string `json:"PCI_DSS,omitempty"`
	CIS        *[]string `json:"CIS,omitempty"`
}

type FileDiff struct {
	Path             *string `json:"path,omitempty"`
	Md5Before        *string `json:"md5_before,omitempty"`
	Md5After         *string `json:"md5_after,omitempty"`
	SHA1Before       *string `json:"sha1_before,omitempty"`
	SHA1After        *string `json:"sha1_after,omitempty"`
	OwnerBefore      *string `json:"owner_before,omitempty"`
	OwnerAfter       *string `json:"owner_after,omitempty"`
	GroupOwnerBefore *string `json:"gowner_before,omitempty"`
	GroupOwnerAfter  *string `json:"gowner_after,omitempty"`
	PermBefore       *int    `json:"perm_before,omitempty"`
	PermAfter        *int    `json:"perm_after,omitempty"`
}

type Decoder struct {
	Fts        *int    `json:"fts,omitempty"`
	Accumulate *int    `json:"accumulate,omitempty"`
	Parent     *string `json:"parent,omitempty"`
	Name       *string `json:"name,omitempty"`
	Ftscomment *string `json:"ftscomment,omitempty"`
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
