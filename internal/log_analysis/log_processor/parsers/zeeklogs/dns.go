package zeeklogs

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
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// https://docs.zeek.org/en/current/scripts/base/protocols/dns/consts.zeek.html#id-DNS::query_types
const (
	aQueryType    = uint64(1)
	aaaaQueryType = uint64(28)
)

// nolint:lll
type ZeekDNS struct {
	TS         *timestamp.UnixFloat `json:"ts,omitempty" validate:"required" description:"The earliest time at which a DNS protocol message over the associated connection is observed."`
	UID        *string              `json:"uid,omitempty" validate:"required" description:"A unique identifier of the connection over which DNS messages are being transferred."`
	IDOrigH    *string              `json:"id.orig_h" validate:"required" description:"The originator’s IP address."`
	IDOrigP    *uint16              `json:"id.orig_p" validate:"required" description:"The originator’s port number."`
	IDRespH    *string              `json:"id.resp_h" validate:"required" description:"The responder’s IP address."`
	IDRespP    *uint16              `json:"id.resp_p" validate:"required" description:"The responder’s port number."`
	Proto      *string              `json:"proto" validate:"required" description:"The transport layer protocol of the connection."`
	TransID    *uint16              `json:"trans_id,omitempty" description:"A 16-bit identifier assigned by the program that generated the DNS query. Also used in responses to match up replies to outstanding queries."`
	Query      *string              `json:"query,omitempty" description:"The domain name that is the subject of the DNS query."`
	QClass     *uint64              `json:"qclass,omitempty" description:"The QCLASS value specifying the class of the query."`
	QClassName *string              `json:"qclass_name,omitempty" description:"A descriptive name for the class of the query."`
	QType      *uint64              `json:"qtype,omitempty" description:"A QTYPE value specifying the type of the query."`
	QTypeName  *string              `json:"qtype_name,omitempty" description:"A descriptive name for the type of the query."`
	Rcode      *uint64              `json:"rcode,omitempty" description:"The response code value in DNS response messages."`
	RcodeName  *string              `json:"rcode_name" description:"A descriptive name for the response code value."`
	AA         *bool                `json:"AA,omitempty" description:"The Authoritative Answer bit for response messages specifies that the responding name server is an authority for the domain name in the question section."`
	TC         *bool                `json:"TC,omitempty" description:"The Truncation bit specifies that the message was truncated."`
	RD         *bool                `json:"RD,omitempty" description:"The Recursion Desired bit in a request message indicates that the client wants recursive service for this query."`
	RA         *bool                `json:"RA,omitempty" description:"The Recursion Available bit in a response message indicates that the name server supports recursive queries."`
	Z          *int                 `json:"Z,omitempty" description:"A reserved field that is usually zero in queries and responses."`
	Answers    []string             `json:"answers,omitempty" description:"The set of resource descriptions in the query answer."`
	TTLs       []float64            `json:"TTLs,omitempty" description:"The caching intervals (measured in seconds) of the associated RRs described by the answers field."`
	Rejected   *bool                `json:"rejected,omitempty" description:"The DNS query was rejected by the server."`
	parsers.PantherLog
}

// ZeekDNSParser parses zeek dns logs
type ZeekDNSParser struct{}

var _ parsers.LogParser = (*ZeekDNSParser)(nil)

func (p *ZeekDNSParser) New() parsers.LogParser {
	return &ZeekDNSParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *ZeekDNSParser) Parse(log string) ([]*parsers.PantherLog, error) {
	zeekDNS := &ZeekDNS{}

	err := jsoniter.UnmarshalFromString(log, zeekDNS)
	if err != nil {
		return nil, err
	}

	zeekDNS.updatePantherFields(p)

	if err := parsers.Validator.Struct(zeekDNS); err != nil {
		return nil, err
	}

	return zeekDNS.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *ZeekDNSParser) LogType() string {
	return TypeZeekDNS
}

func (event *ZeekDNS) updatePantherFields(p *ZeekDNSParser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.TS), event)

	event.AppendAnyIPAddressPtr(event.IDOrigH)
	event.AppendAnyIPAddressPtr(event.IDRespH)

	if event.QType != nil && (*event.QType == aQueryType || *event.QType == aaaaQueryType) {
		if event.Query != nil {
			event.AppendAnyDomainNames(*event.Query)
		}
	}

	for _, answer := range event.Answers {
		// Answer might be IP or Domain name
		if !event.AppendAnyIPAddress(answer) {
			event.AppendAnyDomainNames(answer)
		}
	}
}
