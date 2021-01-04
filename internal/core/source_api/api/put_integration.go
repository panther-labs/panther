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
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	awspoller "github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws"
	"github.com/panther-labs/panther/internal/log_analysis/datacatalog_updater/datacatalog"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/stringset"
)

var (
	putIntegrationInternalError = &genericapi.InternalError{Message: "Failed to add source. Please try again later"}
)

// PutIntegration adds a set of new integrations in a batch.
func (api API) PutIntegration(input *models.PutIntegrationInput) (newIntegration *models.SourceIntegration, err error) {
	if err := api.validateIntegration(input); err != nil {
		zap.L().Error("failed to put integration", zap.Error(err))
		return nil, err
	}

	// Filter out existing integrations
	if err := api.integrationAlreadyExists(input); err != nil {
		zap.L().Error("failed to put integration", zap.Error(err))
		return nil, err
	}

	// Generate the new integration from the input
	newIntegration = generateNewIntegration(input)

	// First creating table - this action is idempotent. In case we succeed here and
	// fail at a later stage, in case of retry this will succeed again.
	if err = createTables(newIntegration); err != nil {
		zap.L().Error("failed to create Glue tables", zap.Error(err))
		return nil, putIntegrationInternalError
	}

	// Try to setupExternalResources
	if err := setupExternalResources(newIntegration); err != nil {
		zap.L().Error("failed to setup external integration", zap.Error(err))
		return nil, putIntegrationInternalError
	}

	// Write to DynamoDB
	item := integrationToItem(newIntegration)
	if err = dynamoClient.PutItem(item); err != nil {
		zap.L().Error("failed to store source integration in DDB", zap.Error(err))
		return nil, putIntegrationInternalError
	}

	if input.IntegrationType == models.IntegrationTypeAWSScan {
		err = api.FullScan(&models.FullScanInput{Integrations: []*models.SourceIntegrationMetadata{&newIntegration.SourceIntegrationMetadata}})
		if err != nil {
			zap.L().Error("failed to trigger scanning of resources", zap.Error(err))
			return nil, putIntegrationInternalError
		}
	}

	return newIntegration, nil
}

func setupExternalResources(integration *models.SourceIntegration) error {
	switch integration.IntegrationType {
	case models.IntegrationTypeAWS3:
		if err := AllowExternalSnsTopicSubscription(integration.AWSAccountID); err != nil {
			return errors.Wrap(err, "failed to add permissions to log processor queue")
		}
	case models.IntegrationTypeSqs:
		if err := AllowInputDataBucketSubscription(); err != nil {
			return errors.Wrap(err, "failed to enable subscription for input bucket")
		}
		if err := CreateSourceSqsQueue(integration.IntegrationID,
			integration.SqsConfig.AllowedPrincipalArns, integration.SqsConfig.AllowedSourceArns); err != nil {
			return errors.Wrap(err, "failed to create input SQS queue")
		}
		if err := AddSourceAsLambdaTrigger(integration.IntegrationID); err != nil {
			return errors.Wrap(err, "failed to configure queue as lambda source")
		}
	}
	return nil
}

func (api API) validateIntegration(input *models.PutIntegrationInput) error {
	// Prefixes in the same S3 source should should be unique (although we allow overlapping for now)
	if input.IntegrationType == models.IntegrationTypeAWS3 {
		prefixes := input.S3PrefixLogTypes.S3Prefixes()
		if len(prefixes) != len(stringset.Dedup(prefixes)) {
			return &genericapi.InvalidInputError{
				Message: "Cannot have duplicate prefixes in an s3 source.",
			}
		}
	}

	// Validate the new integration
	reason, passing, err := evaluateIntegrationFunc(api, &models.CheckIntegrationInput{
		AWSAccountID:      input.AWSAccountID,
		IntegrationType:   input.IntegrationType,
		IntegrationLabel:  input.IntegrationLabel,
		EnableCWESetup:    input.CWEEnabled,
		EnableRemediation: input.RemediationEnabled,
		S3Bucket:          input.S3Bucket,
		S3PrefixLogTypes:  input.S3PrefixLogTypes,
		KmsKey:            input.KmsKey,
		SqsConfig:         input.SqsConfig,
	})
	if err != nil {
		return putIntegrationInternalError
	}
	if !passing {
		zap.L().Warn("PutIntegration: resource has a misconfiguration",
			zap.Error(err),
			zap.String("reason", reason),
			zap.Any("input", input))
		return &genericapi.InvalidInputError{
			Message: fmt.Sprintf("Source %s did not pass configuration check. %s",
				input.IntegrationLabel, reason),
		}
	}
	return nil
}

func (api API) integrationAlreadyExists(input *models.PutIntegrationInput) error {
	// avoid inserting if already done
	existingIntegrations, err := api.ListIntegrations(&models.ListIntegrationsInput{})
	if err != nil {
		zap.L().Error("failed to fetch integrations", zap.Error(errors.WithStack(err)))
		return putIntegrationInternalError
	}

	for _, existingIntegration := range existingIntegrations {
		if existingIntegration.IntegrationType == input.IntegrationType {
			switch existingIntegration.IntegrationType {
			case models.IntegrationTypeAWSScan:
				if existingIntegration.AWSAccountID == input.AWSAccountID {
					// We can only have one cloudsec integration for each account
					return &genericapi.InvalidInputError{
						Message: fmt.Sprintf("Source account %s already onboarded", input.AWSAccountID),
					}
				}
				return nil
			case models.IntegrationTypeAWS3:
				if existingIntegration.AWSAccountID == input.AWSAccountID &&
					existingIntegration.IntegrationLabel == input.IntegrationLabel {
					// Log sources for same account need to have different labels
					return &genericapi.InvalidInputError{
						Message: fmt.Sprintf("Log source for account %s with label %s already onboarded",
							input.AWSAccountID,
							input.IntegrationLabel),
					}
				}

				// A bucket/prefix combination should be unique among s3 sources.
				if existingIntegration.S3Bucket == input.S3Bucket {
					for _, existingPrefix := range existingIntegration.S3PrefixLogTypes.S3Prefixes() {
						for _, prefix := range input.S3PrefixLogTypes.S3Prefixes() {
							if strings.TrimSpace(existingPrefix) == strings.TrimSpace(prefix) {
								return &genericapi.InvalidInputError{
									Message: "An S3 source with the same S3 bucket and prefix already exists.",
								}
							}
						}
					}
				}
			case models.IntegrationTypeSqs:
				if existingIntegration.IntegrationLabel == input.IntegrationLabel {
					// Sqs sources need to have different labels
					return &genericapi.InvalidInputError{
						Message: fmt.Sprintf("Integration with label %s already exists", input.IntegrationLabel),
					}
				}
			}
		}
	}

	return nil
}

// FullScan schedules scans for each Resource type for each integration.
//
// Each Resource type is sent within its own SQS message.
func (api API) FullScan(input *models.FullScanInput) error {
	var sqsEntries []*sqs.SendMessageBatchRequestEntry

	// For each integration, add a ScanMsg to the queue per service
	for _, integration := range input.Integrations {
		for resourceType := range awspoller.ServicePollers {
			scanMsg := &pollermodels.ScanMsg{
				Entries: []*pollermodels.ScanEntry{
					{
						AWSAccountID:  &integration.AWSAccountID,
						IntegrationID: &integration.IntegrationID,
						ResourceType:  aws.String(resourceType),
					},
				},
			}

			messageBodyBytes, err := jsoniter.MarshalToString(scanMsg)
			if err != nil {
				return &genericapi.InternalError{Message: err.Error()}
			}

			sqsEntries = append(sqsEntries, &sqs.SendMessageBatchRequestEntry{
				// Generates an ID of: IntegrationID-AWSResourceType
				Id: aws.String(
					integration.IntegrationID + "-" + strings.Replace(resourceType, ".", "", -1),
				),
				MessageBody: aws.String(messageBodyBytes),
			})
		}
	}

	zap.L().Info(
		"scheduling new scans",
		zap.String("queueUrl", env.SnapshotPollersQueueURL),
		zap.Int("count", len(sqsEntries)),
	)

	// Batch send all the messages to SQS
	_, err := sqsbatch.SendMessageBatch(sqsClient, maxElapsedTime, &sqs.SendMessageBatchInput{
		Entries:  sqsEntries,
		QueueUrl: &env.SnapshotPollersQueueURL,
	})
	return err
}

func generateNewIntegration(input *models.PutIntegrationInput) *models.SourceIntegration {
	metadata := models.SourceIntegrationMetadata{
		CreatedAtTime:    time.Now(),
		CreatedBy:        input.UserID,
		IntegrationID:    uuid.New().String(),
		IntegrationLabel: input.IntegrationLabel,
		IntegrationType:  input.IntegrationType,
	}

	switch input.IntegrationType {
	case models.IntegrationTypeAWSScan:
		metadata.AWSAccountID = input.AWSAccountID
		metadata.CWEEnabled = input.CWEEnabled
		metadata.LogProcessingRole = env.InputDataRoleArn
		metadata.RemediationEnabled = input.RemediationEnabled
		metadata.ScanIntervalMins = input.ScanIntervalMins
		metadata.StackName = getStackName(input.IntegrationType, input.IntegrationLabel)
		metadata.S3Bucket = env.InputDataBucketName
	case models.IntegrationTypeAWS3:
		metadata.AWSAccountID = input.AWSAccountID
		metadata.S3Bucket = input.S3Bucket
		metadata.S3PrefixLogTypes = input.S3PrefixLogTypes
		metadata.KmsKey = input.KmsKey
		metadata.S3PrefixLogTypes = input.S3PrefixLogTypes
		metadata.StackName = getStackName(input.IntegrationType, input.IntegrationLabel)
		metadata.LogProcessingRole = generateLogProcessingRoleArn(input.AWSAccountID, input.IntegrationLabel)
	case models.IntegrationTypeSqs:
		metadata.SqsConfig = &models.SqsConfig{
			S3Bucket:             env.InputDataBucketName,
			LogProcessingRole:    env.InputDataRoleArn,
			AllowedPrincipalArns: input.SqsConfig.AllowedPrincipalArns,
			AllowedSourceArns:    input.SqsConfig.AllowedSourceArns,
			LogTypes:             input.SqsConfig.LogTypes,
			QueueURL:             SourceSqsQueueURL(metadata.IntegrationID),
		}
	}
	return &models.SourceIntegration{
		SourceIntegrationMetadata: metadata,
	}
}

func createTables(integration *models.SourceIntegration) error {
	client := datacatalog.Client{
		SQSAPI:   sqsClient,
		QueueURL: env.DataCatalogUpdaterQueueURL,
	}
	logTypes := integration.RequiredLogTypes()
	err := client.SendCreateTablesForLogTypes(context.TODO(), logTypes...)
	if err != nil {
		return errors.Wrap(err, "failed to create Glue tables")
	}
	return nil
}
