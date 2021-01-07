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
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// mustBuildEventSchema builds a log event schema with all AWS indicators to be compatible with the legacy tables
func mustBuildEventSchema(schema interface{}) interface{} {
	return pantherlog.MustBuildEventSchema(schema, append(pantherlog.DefaultIndicators(),
		pantherlog.FieldAWSARN,
		pantherlog.FieldAWSAccountID,
		pantherlog.FieldAWSInstanceID,
		pantherlog.FieldAWSTag,
	)...)
}

func extractIndicators(w pantherlog.ValueWriter, iter *jsoniter.Iterator, key string) {
	switch iter.WhatIsNext() {
	case jsoniter.ObjectValue:
		switch key {
		case "tags":
			tag := struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			}{}
			if iter.ReadVal(&tag); tag.Key != "" && tag.Value != "" {
				w.WriteValues(pantherlog.FieldAWSTag, tag.Key+":"+tag.Value)
			}
		default:
			for key := iter.ReadObject(); key != ""; key = iter.ReadObject() {
				extractIndicators(w, iter, key)
			}
		}
	case jsoniter.ArrayValue:
		for iter.ReadArray() {
			extractIndicators(w, iter, key)
		}
	case jsoniter.StringValue:
		value := iter.ReadString()
		switch key {
		case "arn", "ARN", "aws:SourceArn":
			pantherlog.ScanARN(w, value)
		case "instanceId", "instance-id":
			pantherlog.ScanAWSInstanceID(w, value)
		case "accountId", "account":
			pantherlog.ScanAWSAccountID(w, value)
		case "tags":
			pantherlog.ScanAWSTag(w, value)
		case "ipv6Addresses", "publicIp", "privateIpAddress", "ipAddressV4", "sourceIPAddress":
			pantherlog.ScanIPAddress(w, value)
		case "publicDnsName", "privateDnsName", "domain":
			if value != "" {
				w.WriteValues(pantherlog.FieldDomainName, value)
			}
		default:
			switch {
			case strings.HasSuffix(key, "AccountId"):
				pantherlog.ScanAWSAccountID(w, value)
			case strings.HasSuffix(key, "InstanceId"):
				pantherlog.ScanAWSInstanceID(w, value)
			case arn.IsARN(value):
				pantherlog.ScanARN(w, value)
			}
		}
	default:
		iter.Skip()
	}
}
