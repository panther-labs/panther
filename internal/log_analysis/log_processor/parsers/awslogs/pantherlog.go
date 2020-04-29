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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// nolint(lll)
type AWSPantherLog struct {
	parsers.PantherLog

	PantherAnyAWSAccountIds  parsers.SmallStringSet `json:"p_any_aws_account_ids,omitempty" description:"Panther added field with collection of aws account ids associated with the row"`
	PantherAnyAWSInstanceIds parsers.SmallStringSet `json:"p_any_aws_instance_ids,omitempty" description:"Panther added field with collection of aws instance ids associated with the row"`
	PantherAnyAWSARNs        parsers.SmallStringSet `json:"p_any_aws_arns,omitempty" description:"Panther added field with collection of aws arns associated with the row"`
	PantherAnyAWSTags        parsers.SmallStringSet `json:"p_any_aws_tags,omitempty" description:"Panther added field with collection of aws tags associated with the row"`
}

const (
	_ parsers.PantherFieldKind = iota + 999
	KindAWSARN
	KindAWSAccountID
	KindAWSInstanceID
	KindAWSTag
)

func ArnP(arn *string) parsers.PantherField {
	if arn != nil {
		return ARN(*arn)
	}
	return parsers.PantherFieldZero()
}
func InstanceIDP(id *string) parsers.PantherField {
	return parsers.NewPantherFieldP(KindAWSInstanceID, id)
}
func AccountIDP(id *string) parsers.PantherField {
	return parsers.NewPantherFieldP(KindAWSAccountID, id)
}
func TagP(tag *string) parsers.PantherField {
	return parsers.NewPantherFieldP(KindAWSTag, tag)
}
func ARN(arn string) parsers.PantherField {
	if arn = strings.TrimSpace(arn); strings.HasPrefix(arn, "arn:") {
		return parsers.NewPantherField(KindAWSARN, arn)
	}
	return parsers.PantherFieldZero()
}
func InstanceID(id string) parsers.PantherField {
	return parsers.NewPantherField(KindAWSInstanceID, id)
}
func AccountID(id string) parsers.PantherField {
	return parsers.NewPantherField(KindAWSAccountID, id)
}
func Tag(tag string) parsers.PantherField {
	return parsers.NewPantherField(KindAWSTag, tag)
}

func (pl *AWSPantherLog) ExtendPantherFields(fields ...parsers.PantherField) {
	for i := range fields {
		if field := &fields[i]; !field.IsEmpty() {
			pl.InsertPantherField(field.Kind, field.Value)
		}
	}
}

func (pl *AWSPantherLog) InsertPantherField(kind parsers.PantherFieldKind, value string) {
	switch kind {
	case KindAWSARN:
		pl.PantherAnyAWSARNs.Insert(value)
	case KindAWSAccountID:
		pl.PantherAnyAWSAccountIds.Insert(value)
	case KindAWSInstanceID:
		pl.PantherAnyAWSInstanceIds.Insert(value)
	case KindAWSTag:
		pl.PantherAnyAWSTags.Insert(value)
	default:
		// delegate to base PantherLog
		pl.PantherLog.InsertPantherField(kind, value)
	}
}
