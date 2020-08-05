package awssqs

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// Struct representing the policy of an SQS queue
type SqsPolicy struct {
	Version    string               `json:"Version"`
	Statements []SqsPolicyStatement `json:"Statement"`
}

// Struct representing the Policy Statement of an SQS queue
type SqsPolicyStatement struct {
	SID       string            `json:"Sid"`
	Effect    string            `json:"Effect"`
	Principal map[string]string `json:"Principal"`
	Action    string            `json:"Action"`
	Resource  string            `json:"Resource"`
	Condition interface{}       `json:"Condition,omitempty"`
}

const (
	PolicyAttributeName = "Policy"
)

func GetQueuePolicy(sqsClient sqsiface.SQSAPI, queueURL string) (*SqsPolicy, error) {
	getAttributesInput := &sqs.GetQueueAttributesInput{
		AttributeNames: aws.StringSlice([]string{PolicyAttributeName}),
		QueueUrl:       &queueURL,
	}
	attributes, err := sqsClient.GetQueueAttributes(getAttributesInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get queue attributes")
	}
	policyAttribute := attributes.Attributes[PolicyAttributeName]
	if len(aws.StringValue(policyAttribute)) == 0 {
		return &SqsPolicy{
			Version:    "2008-10-17",
			Statements: []SqsPolicyStatement{},
		}, nil
	}
	var policy SqsPolicy
	err = jsoniter.UnmarshalFromString(*policyAttribute, &policy)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall queue policy")
	}
	return &policy, nil
}

func SetQueuePolicy(sqsClient sqsiface.SQSAPI, queueURL string, policy *SqsPolicy) (err error) {
	var marshaledPolicy string
	if policy != nil && len(policy.Statements) > 0 {
		marshaledPolicy, err = jsoniter.MarshalToString(policy)
		if err != nil {
			return errors.Wrap(err, "failed to serialize policy")
		}
	}
	zap.L().Debug("setting SQS queue policy", zap.String("queueURL", queueURL), zap.String("policy", marshaledPolicy))

	setAttributesInput := &sqs.SetQueueAttributesInput{
		QueueUrl: &queueURL,
		Attributes: map[string]*string{
			PolicyAttributeName: &marshaledPolicy,
		},
	}

	_, err = sqsClient.SetQueueAttributes(setAttributesInput)
	if err != nil {
		return errors.Wrap(err, "failed to set queue attributes")
	}
	return nil
}
