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

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/awssqs"
)

const (
	externalSnsTopicSubscriptionSIDFormat = "PantherSubscriptionSID-%s"
)

// AllowExternalSnsTopicSubscription modifies the SQS Queue policy of the Log Processor
// to allow SNS topic from new account to subscribe to it
func AllowExternalSnsTopicSubscription(accountID string) (bool, error) {
	existingPolicy, err := awssqs.GetQueuePolicy(sqsClient, env.LogProcessorQueueURL)
	if err != nil {
		return false, err
	}

	// queue has already been configured
	if findStatementIndex(existingPolicy, accountID) >= 0 {
		// if it already exists, no need to do anything
		return false, nil
	}

	existingPolicy.Statements = append(existingPolicy.Statements, getStatementForAccount(accountID))
	err = awssqs.SetQueuePolicy(sqsClient, env.LogProcessorQueueURL, existingPolicy)
	if err != nil {
		zap.L().Error("failed to set policy", zap.Error(errors.Wrap(err, "failed to set policy")))
		return false, err
	}
	return true, nil
}

// DisableExternalSnsTopicSubscription modifies the SQS Queue policy of the Log Processor
// so that SNS topics from that account cannot subscribe to the queue
func DisableExternalSnsTopicSubscription(accountID string) error {
	existingPolicy, err := awssqs.GetQueuePolicy(sqsClient, env.LogProcessorQueueURL)
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

	return awssqs.SetQueuePolicy(sqsClient, env.LogProcessorQueueURL, existingPolicy)
}

func findStatementIndex(policy *awssqs.SqsPolicy, accountID string) int {
	newStatementSid := fmt.Sprintf(externalSnsTopicSubscriptionSIDFormat, accountID)
	for i, statement := range policy.Statements {
		if statement.SID == newStatementSid {
			return i
		}
	}
	return -1
}

func getStatementForAccount(accountID string) awssqs.SqsPolicyStatement {
	newStatementSid := fmt.Sprintf(externalSnsTopicSubscriptionSIDFormat, accountID)
	return awssqs.SqsPolicyStatement{
		SID:       newStatementSid,
		Effect:    "Allow",
		Principal: map[string]string{"AWS": "*"},
		Action:    "sqs:SendMessage",
		Resource:  "*",
		Condition: map[string]interface{}{
			"ArnLike": map[string]string{
				"aws:SourceArn": fmt.Sprintf("arn:aws:sns:*:%s:*", accountID),
			},
		},
	}
}
