package osseclogs

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
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var EventInfoDesc = `OSSEC EventInfo alert parser. Currently only JSON output is supported.
Reference: https://www.ossec.net/docs/docs/formats/alerts.html`

// nolint:lll
type EventInfo struct {
	// Required
	ID        *string                    `json:"id" validate:"required" description:"Unique id of the event."`
	Rule      *Rule                      `json:"rule" validate:"required,dive" description:"Information about the rule that created the event."`
	Timestamp *timestamp.UnixMillisecond `json:"TimeStamp" validate:"required" description:"Timestamp in UTC."`
	Location  *string                    `json:"location" validate:"required" description:"Source of the event (filename, command, etc)."`
	Hostname  *string                    `json:"hostname" validate:"required" description:"Hostname of the host that created the event."`
	FullLog   *string                    `json:"full_log" validate:"required" description:"The full captured log of the event."`

	// Optional
	Action             *string   `json:"action,omitempty" description:"The event action (drop, deny, accept, etc)."`
	AgentIP            *string   `json:"agentip,omitempty" description:"The IP address of an agent extracted from the hostname."`
	AgentName          *string   `json:"agent_name,omitempty" description:"The name of an agent extracted from the hostname."`
	Command            *string   `json:"command,omitempty" description:"The command extracted by the decoder."`
	Data               *string   `json:"data,omitempty" description:"Additional data extracted by the decoder. For example a filename."`
	Decoder            *string   `json:"decoder,omitempty" description:"The name of the decoder used to parse the logs."`
	DecoderDescription *Decoder  `json:"decoder_desc,omitempty" validate:"omitempty,dive" description:"Information about the decoder used to parse the logs."`
	DecoderParent      *string   `json:"decoder_parent,omitempty" description:"In the case of a nested decoder, the name of it's parent."`
	DstGeoIP           *string   `json:"dstgeoip,omitempty" description:"GeoIP location information about the destination IP address."`
	DstIP              *string   `json:"dstip,omitempty" description:"The destination IP address."`
	DstPort            *string   `json:"dstport,omitempty" description:"The destination port."`
	DstUser            *string   `json:"dstuser,omitempty" description:"The destination (target) username."`
	Logfile            *string   `json:"logfile,omitempty" description:"The source log file that was decoded to generate the event."`
	PreviousOutput     *string   `json:"previous_output,omitempty" description:"The full captured log of the previous event."`
	ProgramName        *string   `json:"program_name,omitempty" description:"The executable name extracted from the log by the decoder used to match a rule."`
	Protocol           *string   `json:"protocol,omitempty" description:"The protocol (ip, tcp, udp, etc) extracted by the decoder."`
	SrcGeoIP           *string   `json:"srcgeoip,omitempty" description:"GeoIP location information about the source IP address."`
	SrcIP              *string   `json:"srcip,omitempty" description:"The source IP address."`
	SrcPort            *string   `json:"srcport,omitempty" description:"The source port."`
	SrcUser            *string   `json:"srcuser,omitempty" description:"The source username."`
	Status             *string   `json:"status,omitempty" description:"Event status (success, failure, etc)."`
	SyscheckFile       *FileDiff `json:"SyscheckFile,omitempty" validate:"omitempty,dive" description:"Information about a file integrity check."`
	Systemname         *string   `json:"systemname,omitempty" description:"The system name extracted by the decoder."`
	URL                *string   `json:"url,omitempty" description:"URL of the event."`

	// Deliberately omitted because duplicate case insensitive keys cause problems in Athena
	// TimestampString    *string                    `json:"timestamp,omitempty" description:"TimestampString"`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// nolint:lll
type Rule struct {
	// Required
	Comment *string `json:"comment" validate:"required" description:"The rule description."`
	Group   *string `json:"group" validate:"required" description:"Groups are optional tags added to alerts."`
	Level   *int    `json:"level" validate:"required" description:"The level of the rule (0 to 16). Alerts and responses use this value."`
	SIDID   *int    `json:"sidid" validate:"required" description:"The ID of the rule (100 to 99999)."`

	// Optional
	CIS        []string `json:"CIS,omitempty" description:"A list of Center for Internet Security (CIS) checks relevant to the rule."`
	CVE        *string  `json:"cve,omitempty" description:"A Common Vulnerabilities and Exposures (CVE) identifier relevant to the rule."`
	Firedtimes *int     `json:"firedtimes,omitempty" description:"The number of times the rule fired."`
	Frequency  *int     `json:"frequency,omitempty" description:"Specifies the number of times the rule must have matched before firing."`
	Groups     []string `json:"groups,omitempty" description:"Groups are optional tags added to alerts."`
	Info       *string  `json:"info,omitempty" description:"Additional information or reference about the rule."`
	PCIDSS     []string `json:"PCI_DSS,omitempty" description:"A list of Payment Card Industry Data Security Standard (PCI DSS) requirements relevant to the rule."`
}

// nolint:lll
type FileDiff struct {
	GroupOwnerAfter  *string `json:"gowner_after,omitempty" description:"The group owner after modification."`
	GroupOwnerBefore *string `json:"gowner_before,omitempty" description:"The group owner before modification."`
	MD5After         *string `json:"md5_after,omitempty" description:"MD5 hash of the file after modification."`
	MD5Before        *string `json:"md5_before,omitempty" description:"MD5 hash of the file before modification."`
	OwnerAfter       *string `json:"owner_after,omitempty" description:"The file owner after modification."`
	OwnerBefore      *string `json:"owner_before,omitempty" description:"The file owner before modification."`
	Path             *string `json:"path,omitempty" description:"The path to the file."`
	PermAfter        *int    `json:"perm_after,omitempty" description:"The permissions of the file after modification."`
	PermBefore       *int    `json:"perm_before,omitempty" description:"The permissions of the file before modification."`
	SHA1After        *string `json:"sha1_after,omitempty" description:"SHA1 hash of the file after modification."`
	SHA1Before       *string `json:"sha1_before,omitempty" description:"SHA1 hash of the file before modification."`
}

// nolint:lll
type Decoder struct {
	Accumulate *int    `json:"accumulate,omitempty" description:"True if OSSEC tracks events over multiple log messages based on decoded id."`
	Fts        *int    `json:"fts,omitempty" description:"The First Time Seen option inside of analysisd."`
	Ftscomment *string `json:"ftscomment,omitempty" description:"Unused at this time."`
	Name       *string `json:"name,omitempty" description:"The name of the decoder."`
	Parent     *string `json:"parent,omitempty" description:"In the case of a nested decoder, the name of it's parent."`
}

// EventInfoParser parses OSSEC EventInfo alerts in the JSON format
type EventInfoParser struct{}

func (p *EventInfoParser) New() parsers.LogParser {
	return &EventInfoParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *EventInfoParser) Parse(log string) []*parsers.PantherLog {
	eventInfo := &EventInfo{}

	err := jsoniter.UnmarshalFromString(log, eventInfo)
	if err != nil {
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
	}

	eventInfo.updatePantherFields(p)

	if err := parsers.Validator.Struct(eventInfo); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return eventInfo.Logs()
}

// LogType returns the log type supported by this parser
func (p *EventInfoParser) LogType() string {
	return "OSSEC.EventInfo"
}

func (event *EventInfo) updatePantherFields(p *EventInfoParser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.Timestamp), event)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DstIP)
	if event.SyscheckFile != nil {
		event.AppendAnyMD5HashPtrs(event.SyscheckFile.MD5Before, event.SyscheckFile.MD5After)
		event.AppendAnySHA1HashPtrs(event.SyscheckFile.SHA1Before, event.SyscheckFile.SHA1After)
	}
}
