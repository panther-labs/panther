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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/logs"
)

// nolint(lll)
type Meta struct {
	logs.Meta

	PantherAnyAWSAccountIds  []string `json:"p_any_aws_account_ids,omitempty" description:"Panther added field with collection of aws account ids associated with the row"`
	PantherAnyAWSInstanceIds []string `json:"p_any_aws_instance_ids,omitempty" description:"Panther added field with collection of aws instance ids associated with the row"`
	PantherAnyAWSARNs        []string `json:"p_any_aws_arns,omitempty" description:"Panther added field with collection of aws arns associated with the row"`
	PantherAnyAWSTags        []string `json:"p_any_aws_tags,omitempty" description:"Panther added field with collection of aws tags associated with the row"`
}

const (
	_ logs.FieldKind = iota + 999
	KindAWSARN
	KindAWSAccountID
	KindAWSInstanceID
	KindAWSTag
)

func ArnP(arn *string) logs.Field {
	if arn != nil {
		return ARN(*arn)
	}
	return logs.Field{}
}
func InstanceIDP(id *string) logs.Field {
	if id != nil {
		return InstanceID(*id)
	}
	return logs.Field{}
}
func AccountIDP(id *string) logs.Field {
	if id != nil {
		return AccountID(*id)
	}
	return logs.Field{}
}
func TagP(tag *string) logs.Field {
	if tag != nil {
		return Tag(*tag)
	}
	return logs.Field{}
}
func ARN(arn string) logs.Field {
	if arn = strings.TrimSpace(arn); strings.HasPrefix(arn, "arn:") {
		return logs.Field{Kind: KindAWSARN, Value: arn}
	}
	return logs.Field{}
}
func InstanceID(id string) logs.Field {
	if id := strings.TrimSpace(id); id != "" {
		return logs.Field{Kind: KindAWSInstanceID, Value: id}
	}
	return logs.Field{}
}
func AccountID(id string) logs.Field {
	if id := strings.TrimSpace(id); id != "" {
		return logs.Field{Kind: KindAWSAccountID, Value: id}
	}
	return logs.Field{}
}
func Tag(tag string) logs.Field {
	if tag := strings.TrimSpace(tag); tag != "" {
		return logs.Field{Kind: KindAWSTag, Value: tag}
	}
	return logs.Field{}
}
