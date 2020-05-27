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
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"regexp"
	"strings"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

var (
	awsAccountIDRegex = regexp.MustCompile(`^\d{12}$`)
)

// nolint(lll)
type AWSPantherLog struct {
	parsers.PantherLog

	PantherAnyAWSAccountIds  *parsers.PantherAnyString `json:"p_any_aws_account_ids,omitempty" description:"Panther added field with collection of aws account ids associated with the row"`
	PantherAnyAWSInstanceIds *parsers.PantherAnyString `json:"p_any_aws_instance_ids,omitempty" description:"Panther added field with collection of aws instance ids associated with the row"`
	PantherAnyAWSARNs        *parsers.PantherAnyString `json:"p_any_aws_arns,omitempty" description:"Panther added field with collection of aws arns associated with the row"`
	PantherAnyAWSTags        *parsers.PantherAnyString `json:"p_any_aws_tags,omitempty" description:"Panther added field with collection of aws tags associated with the row"`
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
		if pl.PantherAnyAWSAccountIds == nil { // lazy create
			pl.PantherAnyAWSAccountIds = parsers.NewPantherAnyString()
		}
		parsers.AppendAnyString(pl.PantherAnyAWSAccountIds, value)
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
	if pl.PantherAnyAWSInstanceIds == nil { // lazy create
		pl.PantherAnyAWSInstanceIds = parsers.NewPantherAnyString()
	}
	parsers.AppendAnyString(pl.PantherAnyAWSInstanceIds, values...)
}

func (pl *AWSPantherLog) AppendAnyAWSARNPtrs(values ...*string) {
	for _, value := range values {
		if value != nil {
			pl.AppendAnyAWSARNs(*value)
		}
	}
}

func (pl *AWSPantherLog) AppendAnyAWSARNs(values ...string) {
	if pl.PantherAnyAWSARNs == nil { // lazy create
		pl.PantherAnyAWSARNs = parsers.NewPantherAnyString()
	}
	parsers.AppendAnyString(pl.PantherAnyAWSARNs, values...)
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
	if pl.PantherAnyAWSTags == nil { // lazy create
		pl.PantherAnyAWSTags = parsers.NewPantherAnyString()
	}
	parsers.AppendAnyString(pl.PantherAnyAWSTags, values...)
}

const (
	// Use an offset for AWS values kinds
	_ pantherlog.ValueKind = iota + 999
	KindAccountID
	KindARN
	KindInstanceID
	KindTag
)

func ARN(s string) pantherlog.Value {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "arn:") {
		return pantherlog.Value{
			Kind: KindARN,
			Data: s,
		}
	}
	return pantherlog.Value{}
}
func AccountID(s string) pantherlog.Value {
	s = strings.TrimSpace(s)
	if s != "" && awsAccountIDRegex.MatchString(s) {
		return pantherlog.Value{
			Kind: KindAccountID,
			Data: s,
		}
	}
	return pantherlog.Value{}
}
func InstanceID(s string) pantherlog.Value {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "i-") {
		return pantherlog.Value{
			Kind: KindInstanceID,
			Data: s,
		}
	}
	return pantherlog.Value{}
}

func Tag(s string) pantherlog.Value {
	s = strings.TrimSpace(s)
	if s != "" {
		return pantherlog.Value{
			Kind: KindTag,
			Data: s,
		}
	}
	return pantherlog.Value{}
}

type scanARN struct{}

func ARNScanner() pantherlog.ValueScanner {
	return &scanARN{}
}

var _ pantherlog.ValueScanner = (*scanARN)(nil)

func (*scanARN) ScanValues(values []pantherlog.Value, input string) ([]pantherlog.Value, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return values, nil
	}
	arn, err := arn.Parse(input)
	if err != nil {
		return values, err
	}
	values = append(values, ARN(input), AccountID(arn.AccountID))
	if res := strings.TrimPrefix(arn.Resource, "instance/"); res != arn.Resource {
		values = append(values, InstanceID(res))
	}
	return values, nil
}

type Meta struct {
	pantherlog.Meta
	PantherAnyAWSAccountIds  []string `json:"p_any_aws_account_ids,omitempty" description:"Panther added field with collection of aws account ids associated with the row"`
	PantherAnyAWSInstanceIds []string `json:"p_any_aws_instance_ids,omitempty" description:"Panther added field with collection of aws instance ids associated with the row"`
	PantherAnyAWSARNs        []string `json:"p_any_aws_arns,omitempty" description:"Panther added field with collection of aws arns associated with the row"`
	PantherAnyAWSTags        []string `json:"p_any_aws_tags,omitempty" description:"Panther added field with collection of aws tags associated with the row"`
}

func metaFactory(event *pantherlog.Event) (interface{}, error) {
	return &Meta{
		Meta:                     pantherlog.NewMeta(event),
		PantherAnyAWSAccountIds:  event.Values(KindAccountID),
		PantherAnyAWSInstanceIds: event.Values(KindInstanceID),
		PantherAnyAWSARNs:        event.Values(KindARN),
		PantherAnyAWSTags:        event.Values(KindTag),
	}, nil
}
