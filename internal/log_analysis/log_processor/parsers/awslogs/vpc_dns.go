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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// nolint:lll
type VPCDns struct {
	Version        pantherlog.String `json:"version" validate:"required" description:"The version number of the query log format. If we add fields to the log or change the format of existing fields, we'll increment this value."`
	AccountID      pantherlog.String `json:"account_id" validate:"required" panther:"aws_account_id" description:"The ID of the AWS account that created the VPC."`
	Region         pantherlog.String `json:"region" validate:"required" description:"The AWS Region that you created the VPC in."`
	VPCID          pantherlog.String `json:"vpc_id" validate:"required" description:"The ID of the VPC that the query originated in."`
	QueryTimestamp pantherlog.Time   `json:"query_timestamp" validate:"required" event_time:"true" tcodec:"rfc3339" description:"The date and time that the query was submitted, in ISO 8601 format and Coordinated Universal Time (UTC)"`
	QueryName      pantherlog.String `json:"query_name" validate:"required" description:"The domain name (example.com) or subdomain name (www.example.com) that was specified in the query."`
	QueryType      pantherlog.String `json:"query_type" validate:"required" description:"Either the DNS record type that was specified in the request, or ANY. For information about the types that Route 53 supports."`
	QueryClass     pantherlog.String `json:"query_class" validate:"required" description:"The class of the query."`
	Rcode          pantherlog.String `json:"rcode" validate:"required" description:"The DNS response code that Resolver returned in response to the DNS query. The response code indicates whether the query was valid or not. The most common response code is NOERROR, meaning that the query was valid. If the response is not valid, Resolver returns a response code that explains why not. For a list of possible response codes, see DNS RCODEs on the IANA website."`
	Answers        []DNSAnswer       `json:"answers" validate:"required" description:"Answers to the query"`
	SrcAddr        pantherlog.String `json:"srcaddr" validate:"required" panther:"ip" description:"The IP address of the instance that the query originated from."`
	SrcPort        pantherlog.String `json:"srcport" validate:"required"  description:"The port on the instance that the query originated from."`
	Transport      pantherlog.String `json:"transport" validate:"required"  description:"The protocol used to submit the DNS query."`
	SrcIDs         DNSSrcID          `json:"srcids" validate:"required"  description:"The list of IDs of the sources the DNS query originated from or passed through."`
}

var _ pantherlog.ValueWriterTo = (*VPCDns)(nil)

func (vpcdns *VPCDns) WriteValuesTo(w pantherlog.ValueWriter) {
	if len(vpcdns.QueryName.Value) > 1 { // remove trailing '.'
		pantherlog.ScanDomainName(w, vpcdns.QueryName.Value[0:len(vpcdns.QueryName.Value)-1])
	}
}

// nolint:lll
type DNSAnswer struct {
	Rdata pantherlog.String `json:"Rdata" validate:"required" description:"The value that Resolver returned in response to the query. For example, for an A record, this is an IP address in IPv4 format. For a CNAME record, this is the domain name in the CNAME record."`
	Type  pantherlog.String `json:"Type" validate:"required" description:"The DNS record type (such as A, MX, or CNAME) of the value that Resolver is returning in response to the query."`
	Class pantherlog.String `json:"Class" validate:"required" description:"The class of the Resolver response to the query."`
}

var _ pantherlog.ValueWriterTo = (*DNSAnswer)(nil)

func (answer *DNSAnswer) WriteValuesTo(w pantherlog.ValueWriter) {
	switch answer.Type.Value {
	case "A", "AAAA":
		if answer.Rdata.Value != "" {
			pantherlog.ScanIPAddress(w, answer.Rdata.Value)
		}
	case "CNAME", "MX", "NS", "PTR":
		if len(answer.Rdata.Value) > 1 { // remove trailing '.'
			pantherlog.ScanDomainName(w, answer.Rdata.Value[0:len(answer.Rdata.Value)-1])
		}
	}
}

// nolint:lll
type DNSSrcID struct {
	InstanceID       pantherlog.String `json:"instance"  panther:"aws_instance_id" description:"The ID of the instance that the query originated from."`
	ResolverEndpoint pantherlog.String `json:"resolver-endpoint" description:"The ID of the resolver endpoint that passes the DNS query to on-premises DNS servers."`
}
