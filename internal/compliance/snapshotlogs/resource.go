package snapshotlogs

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
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

const TypeResource = "Resource.History"

var logTypeResourceHistory = logtypes.MustBuild(logtypes.ConfigJSON{
	Name:         TypeResource,
	Description:  `Contains Cloud Security resource snapshots`,
	ReferenceURL: `https://docs.runpanther.io/cloud-security/resources`,
	NewEvent: func() interface{} {
		return &Resource{}
	},
	ExtraIndicators: pantherlog.FieldSet{ // these are added by extractors but not used in struct directly
		pantherlog.FieldDomainName,
		pantherlog.FieldIPAddress,
		pantherlog.FieldAWSTag,
	},
	Validate: pantherlog.ValidateStruct,
})

// nolint:lll
type Resource struct {
	ChangeType       pantherlog.String      `json:"changeType" validate:"required" description:"The type of change that initiated this snapshot creation."`
	Changes          *pantherlog.RawMessage `json:"changes" description:"The changes, if any, from the prior snapshot to this one."`
	IntegrationID    pantherlog.String      `json:"integrationId" validate:"required" description:"The unique source ID of the account this resource lives in."`
	IntegrationLabel pantherlog.String      `json:"integrationLabel" validate:"required" description:"The friendly source name of the account this resource lives in."`
	LastUpdated      pantherlog.Time        `json:"lastUpdated" tcodec:"rfc3339" event_time:"true" validate:"required" description:"The time this snapshot occurred."`
	Resource         pantherlog.RawMessage  `json:"resource" validate:"required" description:"This object represents the state of the resource."`
	ID               pantherlog.String      `json:"id" description:"The AWS resource identifier of the resource."`
	ResourceID       pantherlog.String      `json:"resourceId" description:"A panther wide unique identifier of the resource."`
	ResourceType     pantherlog.String      `json:"resourceType" description:"A panther defined resource type for the resource."`
	TimeCreated      pantherlog.Time        `json:"timeCreated" tcodec:"rfc3339" description:"When this resource was created."`
	AccountID        pantherlog.String      `json:"accountId" panther:"aws_account_id" description:"The ID of the AWS Account the resource resides in."`
	Region           pantherlog.String      `json:"region" description:"The region the resource exists in."`
	ARN              pantherlog.String      `json:"arn" panther:"aws_arn" description:"The Amazon Resource Name (ARN) of the resource."`
	Name             pantherlog.String      `json:"name" description:"The AWS resource name of the resource."`
	Tags             map[string]string      `json:"tags" description:"A standardized format for key/value resource tags."`
}

// WriteValuesTo implements pantherlog.ValueWriterTo interface
func (r *Resource) WriteValuesTo(w pantherlog.ValueWriter) {
	pantherlog.ExtractRawMessageIndicators(w, extractIndicators, r.Resource)
	for key, value := range r.Tags {
		w.WriteValues(pantherlog.FieldAWSTag, key+":"+value)
	}
}

func extractIndicators(w pantherlog.ValueWriter, iter *jsoniter.Iterator, key string) {
	switch iter.WhatIsNext() {
	case jsoniter.ObjectValue:
		switch key {
		default:
			for key := iter.ReadObject(); key != ""; key = iter.ReadObject() {
				extractIndicators(w, iter, key)
			}
		}
	case jsoniter.ArrayValue:
		switch key {
		case "ManagedPolicyARNs":
			for iter.ReadArray() {
				pantherlog.ScanARN(w, iter.ReadString())
			}
		default:
			for iter.ReadArray() {
				extractIndicators(w, iter, key)
			}
		}
	case jsoniter.StringValue:
		value := iter.ReadString()
		switch key {
		case "ID":
			pantherlog.ScanAWSInstanceID(w, value)
		case "AccountId", "OwnerId":
			pantherlog.ScanAWSAccountID(w, value)
		case "Address", "AssignPublicIp", "PrivateIpAddress", "PrivateIPAddress", "PublicIpAddress", "PublicIPAddress":
			pantherlog.ScanIPAddress(w, value)
		case "Domain", "DomainName", "DNSName", "FQDN", "PrivateDnsName", "PublicDnsName":
			pantherlog.ScanHostname(w, value)
		default:
			switch {
			case strings.HasSuffix(key, "ARN") || strings.HasSuffix(key, "arn") || arn.IsARN(value):
				pantherlog.ScanARN(w, value)
			}
		}
	default:
		iter.Skip()
	}
}
