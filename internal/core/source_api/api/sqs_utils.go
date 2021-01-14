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

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/awssqs"
)

const (
	externalSnsTopicSubscriptionSIDFormat = "PantherSubscriptionSID-%s"
	inputDataBucketSID                    = "PantherInputDataBucket"

	// Format of the SQS queues that will be used as input to Panther
	inputSqsQueueNameFormat = "panther-source-%s"

	// Example https://sqs.eu-west-2.amazonaws.com/123456789012/QueueName
	sqsQueueURLFormat = "https://sqs.%s.amazonaws.com/%s/%s"

	// Example arn:aws:sqs:eu-west-2:123456789012:QueueName
	sqsQueueArnFormat = "arn:aws:sqs:%s:%s:%s"
)

// Returns the URL of an SQS queue source
func (api *API) SourceSqsQueueURL(integrationID string) string {
	return fmt.Sprintf(sqsQueueURLFormat, api.Config.Region, api.Config.AccountID, getSourceSqsName(integrationID))
}

// Returns the URL of an SQS queue source
func (api *API) SourceSqsQueueArn(integrationID string) string {
	return fmt.Sprintf(sqsQueueArnFormat, api.Config.Region, api.Config.AccountID, getSourceSqsName(integrationID))
}

// Creates a source SQS queue
// The new queue will allow the provided AWS principals and Source ARNs to send data to it
func (api *API) CreateSourceSqsQueue(integrationID string, allowedPrincipalArns []string, allowedSourceArns []string) error {
	queueName := getSourceSqsName(integrationID)
	policy := createSourceSqsQueuePolicy(allowedPrincipalArns, allowedSourceArns)

	createQueueInput := &sqs.CreateQueueInput{
		QueueName: &queueName,
	}

	if policy != nil {
		marshaledPolicy, err := jsoniter.MarshalToString(policy)
		if err != nil {
			return errors.Wrap(err, "failed to marshal policy")
		}
		createQueueInput.Attributes = map[string]*string{
			awssqs.PolicyAttributeName: &marshaledPolicy,
		}
	}

	zap.L().Debug("creating SQS queue", zap.String("name", queueName), zap.Any("policy", policy))

	_, err := api.SqsClient.CreateQueue(createQueueInput)
	if err != nil {
		return errors.Wrap(err, "failed to create SQS queue")
	}
	return nil
}

// Updates Source SQS queue with new permissions
func (api *API) UpdateSourceSqsQueue(integrationID string, allowedPrincipalArns []string, allowedSourceArns []string) error {
	queueName := api.SourceSqsQueueURL(integrationID)
	policy := createSourceSqsQueuePolicy(allowedPrincipalArns, allowedSourceArns)
	if err := awssqs.SetQueuePolicy(api.SqsClient, queueName, policy); err != nil {
		return errors.Wrap(err, "failed to update queue policy")
	}
	return nil
}

// Deletes a source SQS queue
func (api *API) DeleteSourceSqsQueue(integrationID string) error {
	queueURL := api.SourceSqsQueueURL(integrationID)
	input := &sqs.DeleteQueueInput{
		QueueUrl: &queueURL,
	}
	if _, err := api.SqsClient.DeleteQueue(input); err != nil {
		awsErr, ok := err.(awserr.Error)
		if ok && awsErr.Code() == sqs.ErrCodeQueueDoesNotExist {
			zap.L().Debug("tried to delete queue but queue doesn't exist",
				zap.String("integrationId", integrationID),
				zap.String("queueURL", queueURL))
			return nil
		}
		return errors.Wrap(err, "failed to delete queue")
	}
	return nil
}

// AllowExternalSnsTopicSubscription modifies the SQS Queue policy of the Log Processor
// to allow SNS topic from new account to subscribe to it
func (api *API) AllowExternalSnsTopicSubscription(accountID string) error {
	existingPolicy, err := awssqs.GetQueuePolicy(api.SqsClient, api.Config.LogProcessorQueueURL)
	if err != nil {
		return err
	}

	// queue has already been configured
	if findStatementIndex(existingPolicy, accountID) >= 0 {
		// if it already exists, no need to do anything
		return nil
	}

	existingPolicy.Statements = append(existingPolicy.Statements, getStatementForAccount(accountID))
	err = awssqs.SetQueuePolicy(api.SqsClient, api.Config.LogProcessorQueueURL, existingPolicy)
	if err != nil {
		zap.L().Error("failed to set policy", zap.Error(errors.Wrap(err, "failed to set policy")))
		return err
	}
	return nil
}

// DisableExternalSnsTopicSubscription modifies the SQS Queue policy of the Log Processor
// so that SNS topics from that account cannot subscribe to the queue
func (api *API) DisableExternalSnsTopicSubscription(accountID string) error {
	existingPolicy, err := awssqs.GetQueuePolicy(api.SqsClient, api.Config.LogProcessorQueueURL)
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

	return awssqs.SetQueuePolicy(api.SqsClient, api.Config.LogProcessorQueueURL, existingPolicy)
}

// Some of the integrations send data to an S3 bucket managed by Panther.
// This bucket is a staging bucket where data are stored temporarily until Log Processor
// picks them up. This function updates the log processor SQS queue permissions to allow it to
// receive event notifications from that bucket.
func (api *API) AllowInputDataBucketSubscription() error {
	existingPolicy, err := awssqs.GetQueuePolicy(api.SqsClient, api.Config.LogProcessorQueueURL)
	if err != nil {
		return err
	}

	for _, statement := range existingPolicy.Statements {
		if statement.SID == inputDataBucketSID {
			// statement already present
			// no need to do anything else
			return nil
		}
	}

	statement := awssqs.SqsPolicyStatement{
		SID:       inputDataBucketSID,
		Effect:    "Allow",
		Principal: map[string]string{"AWS": "*"},
		Action:    "sqs:SendMessage",
		Resource:  "*",
		Condition: map[string]interface{}{
			"ArnLike": map[string]string{
				"aws:SourceArn": api.Config.InputDataTopicArn,
			},
		},
	}

	existingPolicy.Statements = append(existingPolicy.Statements, statement)
	return awssqs.SetQueuePolicy(api.SqsClient, api.Config.LogProcessorQueueURL, existingPolicy)
}

// Generates the Policy for the Source SQS queue that allows the following list of AWS AccountIDs and sourceARNS to send
// data to the queue
func createSourceSqsQueuePolicy(allowedPrincipalArns []string, allowedSourceArns []string) *awssqs.SqsPolicy {
	if len(allowedPrincipalArns) == 0 && len(allowedSourceArns) == 0 {
		return nil
	}
	var statements []awssqs.SqsPolicyStatement
	for _, allowedArn := range allowedPrincipalArns {
		statement := awssqs.SqsPolicyStatement{
			SID:       allowedArn,
			Effect:    "Allow",
			Principal: map[string]string{"AWS": allowedArn},
			Action:    "sqs:SendMessage",
			Resource:  "*",
		}
		statements = append(statements, statement)
	}

	for _, allowedArn := range allowedSourceArns {
		statement := awssqs.SqsPolicyStatement{
			SID:       allowedArn,
			Effect:    "Allow",
			Principal: map[string]string{"AWS": "*"},
			Action:    "sqs:SendMessage",
			Resource:  "*",
			Condition: map[string]interface{}{
				"ArnLike": map[string]string{
					"aws:SourceArn": allowedArn,
				},
			},
		}
		statements = append(statements, statement)
	}

	return &awssqs.SqsPolicy{
		Version:    "2008-10-17",
		Statements: statements,
	}
}

func getSourceSqsName(integrationID string) string {
	return fmt.Sprintf(inputSqsQueueNameFormat, integrationID)
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
