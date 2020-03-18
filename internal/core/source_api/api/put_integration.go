package api

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	awspoller "github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// PutIntegration adds a set of new integrations in a batch.
func (api API) PutIntegration(input *models.PutIntegrationInput) ([]*models.SourceIntegrationMetadata, error) {
	// Validate the new integrations
	for _, integration := range input.Integrations {
		passing, err := evaluateIntegrationFunc(api, &models.CheckIntegrationInput{
			AWSAccountID:      integration.AWSAccountID,
			IntegrationType:   integration.IntegrationType,
			EnableCWESetup:    integration.CWEEnabled,
			EnableRemediation: integration.RemediationEnabled,
			S3Buckets:         integration.S3Buckets,
			KmsKeys:           integration.KmsKeys,
		})
		if err != nil {
			return nil, err
		}
		if !passing {
			return nil, &genericapi.InvalidInputError{
				Message: fmt.Sprintf("integration %s did not pass health check", *integration.AWSAccountID),
			}
		}
	}

	// Filter out existing integrations
	integrations, err := api.filterOutExistingIntegrations(input.Integrations)
	if err != nil {
		return nil, err
	}

	// Generate the new integrations
	newIntegrations := make([]*models.SourceIntegrationMetadata, len(integrations))
	for i, integration := range integrations {
		newIntegrations[i] = generateNewIntegration(integration)
	}

	// Get ready to add appropriate permissions to the SQS queue
	permissionsAddedForIntegrations := []*models.SourceIntegrationMetadata{}
	defer func() {
		if err != nil {
			// In case there has been any error, try to undo granting of permissions to SQS queue.
			for _, integration := range permissionsAddedForIntegrations {
				if undoErr := RemovePermissionFromLogProcessorQueue(*integration.AWSAccountID); undoErr != nil {
					zap.L().Error("failed to remove SQS permission for integration. SQS queue has additional permissions that have to be removed manually",
						zap.String("sqsPermissionLabel", *integration.IntegrationID),
						zap.Error(undoErr),
						zap.Error(err))
				}
			}
		}
	}()

	// Add appropriate permissions to the SQS queue
	for _, integration := range newIntegrations {
		if *integration.IntegrationType != models.IntegrationTypeAWS3 {
			continue
		}
		err = AddPermissionToLogProcessorQueue(*integration.AWSAccountID)
		if err != nil { // logging handled in called function
			return nil, err
		}
		permissionsAddedForIntegrations = append(permissionsAddedForIntegrations, integration)
	}

	// Batch write to DynamoDB
	if err = db.BatchPutSourceIntegrations(newIntegrations); err != nil {
		return nil, err
	}

	// Return early to skip sending to the snapshot queue
	if aws.BoolValue(input.SkipScanQueue) {
		return newIntegrations, nil
	}

	var integrationsToScan []*models.SourceIntegrationMetadata
	for _, integration := range newIntegrations {
		//We don't want to trigger scanning for aws-s3 type integrations
		if aws.StringValue(integration.IntegrationType) == models.IntegrationTypeAWS3 {
			continue
		}
		integrationsToScan = append(integrationsToScan, integration)
	}

	// Add to the Snapshot queue
	err = ScanAllResources(integrationsToScan)
	return newIntegrations, err
}

func (api API) filterOutExistingIntegrations(inputIntegrations []*models.PutIntegrationSettings) (
	existingIntegrations []*models.PutIntegrationSettings, err error) {

	// avoid inserting if already done
	currentIntegrations, err := api.ListIntegrations(&models.ListIntegrationsInput{})
	if err != nil {
		return nil, &genericapi.InternalError{Message: err.Error()}
	}
	currentIntegrationsMap := make(map[string]struct{})
	for _, integration := range currentIntegrations {
		currentIntegrationsMap[*integration.AWSAccountID+*integration.IntegrationType] = struct{}{}
	}
	for _, integration := range inputIntegrations {
		if _, found := currentIntegrationsMap[*integration.AWSAccountID+*integration.IntegrationType]; found {
			zap.L().Warn(fmt.Sprintf("integration exists for: %s:%s skipping PutIntegration()",
				*integration.AWSAccountID, *integration.IntegrationType))
		} else {
			existingIntegrations = append(existingIntegrations, integration)
		}
	}
	return existingIntegrations, nil
}

// ScanAllResources schedules scans for each Resource type for each integration.
//
// Each Resource type is sent within its own SQS message.
func ScanAllResources(integrations []*models.SourceIntegrationMetadata) error {
	var sqsEntries []*sqs.SendMessageBatchRequestEntry

	// For each integration, add a ScanMsg to the queue per service
	for _, integration := range integrations {
		for resourceType := range awspoller.ServicePollers {
			scanMsg := &pollermodels.ScanMsg{
				Entries: []*pollermodels.ScanEntry{
					{
						AWSAccountID:  integration.AWSAccountID,
						IntegrationID: integration.IntegrationID,
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
					*integration.IntegrationID + "-" + strings.Replace(resourceType, ".", "", -1),
				),
				MessageBody: aws.String(messageBodyBytes),
			})
		}
	}

	zap.L().Info(
		"scheduling new scans",
		zap.String("queueUrl", snapshotPollersQueueURL),
		zap.Int("count", len(sqsEntries)),
	)

	// Batch send all the messages to SQS
	return sqsbatch.SendMessageBatch(SQSClient, maxElapsedTime, &sqs.SendMessageBatchInput{
		Entries:  sqsEntries,
		QueueUrl: &snapshotPollersQueueURL,
	})
}

func generateNewIntegration(input *models.PutIntegrationSettings) *models.SourceIntegrationMetadata {
	return &models.SourceIntegrationMetadata{
		AWSAccountID:       input.AWSAccountID,
		CreatedAtTime:      aws.Time(time.Now()),
		CreatedBy:          input.UserID,
		IntegrationID:      aws.String(uuid.New().String()),
		IntegrationLabel:   input.IntegrationLabel,
		IntegrationType:    input.IntegrationType,
		CWEEnabled:         input.CWEEnabled,
		RemediationEnabled: input.RemediationEnabled,
		ScanIntervalMins:   input.ScanIntervalMins,
		// For log analysis integrations
		S3Buckets: input.S3Buckets,
		KmsKeys:   input.KmsKeys,
	}
}
