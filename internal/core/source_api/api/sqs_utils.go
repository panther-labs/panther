package api

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
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

//
type SqsPolicy struct {
	Version    string               `json:"Version"`
	Statements []SqsPolicyStatement `json:"Statement"`
}

type SqsPolicyStatement struct {
	SID       string            `json:"Sid"`
	Effect    string            `json:"Effect"`
	Principal map[string]string `json:"Principal"`
	Action    string            `json:"Action"`
	Resource  string            `json:"Resource"`
	Condition interface{}       `json:"Condition"`
}

const (
	sidFormat           = "PantherSubscriptionSID-%s"
	policyAttributeName = "Policy"
)

// AddPermissionToLogProcessorQueue modifies the SQS Queue policy of the Log Processor
// to allow SNS topic from new account to subscribe to it
func AddPermissionToLogProcessorQueue(accountID string) (bool, error) {
	existingPolicy, err := getQueuePolicy()
	if err != nil {
		return false, err
	}
	if existingPolicy == nil {
		existingPolicy = &SqsPolicy{
			Version:    "2008-10-17",
			Statements: []SqsPolicyStatement{},
		}
	}

	// queue has already been configured
	if findStatementIndex(existingPolicy, accountID) >= 0 {
		// if it already exists, no need to do anything
		return false, nil
	}

	existingPolicy.Statements = append(existingPolicy.Statements, getStatementForAccount(accountID))
	err = setQueuePolicy(existingPolicy)
	if err != nil {
		zap.L().Error("failed to set policy", zap.Error(errors.Wrap(err, "failed to set policy")))
	}
	return true, setQueuePolicy(existingPolicy)
}

// RemovePermissionFromLogProcessorQueue modifies the SQS Queue policy of the Log Processor
// so that SNS topics from that account cannot subscribe to the queue
func RemovePermissionFromLogProcessorQueue(accountID string) error {
	existingPolicy, err := getQueuePolicy()
	if err != nil {
		return err
	}
	if existingPolicy == nil {
		zap.L().Warn("policy does not exist")
		return nil
	}

	statementToRemoveIndex := findStatementIndex(existingPolicy, accountID)
	if statementToRemoveIndex < 0 {
		zap.L().Warn("didn't find expected statement in queue policy",
			zap.String("accountId", accountID),
		)
		return nil
	}
	// Remove statement
	existingPolicy.Statements[statementToRemoveIndex] = existingPolicy.Statements[len(existingPolicy.Statements)-1]
	existingPolicy.Statements = existingPolicy.Statements[:len(existingPolicy.Statements)-1]

	return setQueuePolicy(existingPolicy)
}

func getQueuePolicy() (*SqsPolicy, error) {
	getAttributesInput := &sqs.GetQueueAttributesInput{
		AttributeNames: aws.StringSlice([]string{policyAttributeName}),
		QueueUrl:       aws.String(env.LogProcessorQueueURL),
	}
	attributes, err := sqsClient.GetQueueAttributes(getAttributesInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get queue attributes")
	}
	policyAttribute := attributes.Attributes[policyAttributeName]
	if len(aws.StringValue(policyAttribute)) == 0 {
		return nil, nil
	}
	var policy SqsPolicy
	err = jsoniter.UnmarshalFromString(*policyAttribute, &policy)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall queue policy")
	}
	return &policy, nil
}

func findStatementIndex(policy *SqsPolicy, accountID string) int {
	newStatementSid := fmt.Sprintf(sidFormat, accountID)
	for i, statement := range policy.Statements {
		if statement.SID == newStatementSid {
			return i
		}
	}
	return -1
}

func setQueuePolicy(policy *SqsPolicy) error {
	policyAttribute := aws.String("")
	if len(policy.Statements) > 0 {
		marshaledPolicy, err := jsoniter.MarshalToString(policy)
		if err != nil {
			zap.L().Error("failed to serialize policy", zap.Error(errors.WithStack(err)))
			return errors.WithStack(err)
		}
		policyAttribute = aws.String(marshaledPolicy)
	}

	setAttributesInput := &sqs.SetQueueAttributesInput{
		QueueUrl: aws.String(env.LogProcessorQueueURL),
		Attributes: map[string]*string{
			policyAttributeName: policyAttribute,
		},
	}

	_, err := sqsClient.SetQueueAttributes(setAttributesInput)
	if err != nil {
		return errors.Wrap(err, "failed to set queue attributes")
	}
	return nil
}

func getStatementForAccount(accountID string) SqsPolicyStatement {
	newStatementSid := fmt.Sprintf(sidFormat, accountID)
	return SqsPolicyStatement{
		SID:       newStatementSid,
		Effect:    "Allow",
		Principal: map[string]string{"AWS": "*"},
		Action:    "sqs:SendMessage",
		Resource:  env.LogProcessorQueueArn,
		Condition: map[string]interface{}{
			"ArnLike": map[string]string{
				"aws:SourceArn": fmt.Sprintf("arn:aws:sns:*:%s:*", accountID),
			},
		},
	}
}
