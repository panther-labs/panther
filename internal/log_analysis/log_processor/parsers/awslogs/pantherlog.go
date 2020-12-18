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
	"regexp"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

var (
	awsAccountIDRegex = regexp.MustCompile(`^\d{12}$`)
)

// nolint(lll)
type AWSPantherLog struct {
	parsers.PantherLog

	PantherAnyAWSAccountIds  parsers.PantherAnyString `json:"p_any_aws_account_ids,omitempty" description:"Panther added field with collection of aws account ids associated with the row"`
	PantherAnyAWSInstanceIds parsers.PantherAnyString `json:"p_any_aws_instance_ids,omitempty" description:"Panther added field with collection of aws instance ids associated with the row"`
	PantherAnyAWSARNs        parsers.PantherAnyString `json:"p_any_aws_arns,omitempty" description:"Panther added field with collection of aws arns associated with the row"`
	PantherAnyAWSTags        parsers.PantherAnyString `json:"p_any_aws_tags,omitempty" description:"Panther added field with collection of aws tags associated with the row"`
}

func (pl *AWSPantherLog) AppendAnyAWSAccountIdPtrs(values ...*string) { // nolint
	for _, value := range values {
		if value != nil {
			pl.AppendAnyAWSAccountIds(*value)
		}
	}
}

func (pl *AWSPantherLog) AppendAnyAWSAccountIds(values ...string) {
	for _, value := range values {
		if !awsAccountIDRegex.MatchString(value) {
			continue
		}
		parsers.AppendAnyString(&pl.PantherAnyAWSAccountIds, value)
	}
}

func (pl *AWSPantherLog) AppendAnyAWSInstanceIdPtrs(values ...*string) { // nolint
	for _, value := range values {
		if value != nil {
			pl.AppendAnyAWSInstanceIds(*value)
		}
	}
}

func (pl *AWSPantherLog) AppendAnyAWSInstanceIds(values ...string) {
	parsers.AppendAnyString(&pl.PantherAnyAWSInstanceIds, values...)
}

func (pl *AWSPantherLog) AppendAnyAWSARNPtrs(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.AppendAnyAWSARNs(*value)
		}
	}
}

func (pl *AWSPantherLog) AppendAnyAWSARNs(values ...string) {
	parsers.AppendAnyString(&pl.PantherAnyAWSARNs, values...)
}

func (pl *AWSPantherLog) AppendAnyAWSTagPtrs(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.AppendAnyAWSTags(*value)
		}
	}
}

// NOTE: value should be of the form <key>:<value>
func (pl *AWSPantherLog) AppendAnyAWSTags(values ...string) {
	parsers.AppendAnyString(&pl.PantherAnyAWSTags, values...)
}
