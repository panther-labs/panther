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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/snapshot/models"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	awspoller "github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// PutIntegration adds a set of new integrations in a batch.
func (API) PutIntegration(input *models.PutIntegrationInput) ([]*models.SourceIntegrationMetadata, error) {
	permissionsAddedForIntegrations := []*models.SourceIntegrationMetadata{}
	var err error
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
	newIntegrations := make([]*models.SourceIntegrationMetadata, len(input.Integrations))

	// Generate the new integrations
	for i, integration := range input.Integrations {
		newIntegrations[i] = generateNewIntegration(integration)
	}

	for _, integration := range newIntegrations {
		if *integration.IntegrationType != models.IntegrationTypeAWS3 {
			continue
		}
		err = AddPermissionToLogProcessorQueue(*integration.AWSAccountID)
		if err != nil { // logging handled in function
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

// ScanAllResources schedules scans for each Resource type for each integration.
//
// Each Resource type is sent within its own SQS message.
func ScanAllResources(integrations []*models.SourceIntegrationMetadata) error {
	var sqsEntries []*sqs.SendMessageBatchRequestEntry

	// For each integration, add a ScanMsg to the queue per service
	for _, integration := range integrations {
		if !*integration.ScanEnabled {
			continue
		}

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
		AWSAccountID:     input.AWSAccountID,
		CreatedAtTime:    aws.Time(time.Now()),
		CreatedBy:        input.UserID,
		IntegrationID:    aws.String(uuid.New().String()),
		IntegrationLabel: input.IntegrationLabel,
		IntegrationType:  input.IntegrationType,
		ScanEnabled:      input.ScanEnabled,
		ScanIntervalMins: input.ScanIntervalMins,
		// For log analysis integrations
		S3Buckets: input.S3Buckets,
		KmsKeys:   input.KmsKeys,
	}
}
