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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

var (
	deleteIntegrationInternalError = &genericapi.InternalError{Message: "Failed to delete source. Please try again later"}
)

// DeleteIntegration deletes a specific integration.
func (api *API) DeleteIntegration(input *models.DeleteIntegrationInput) error {
	integrationItem, err := api.DdbClient.GetItem(input.IntegrationID)
	if err != nil {
		errMsg := "failed to get integrationItem"
		err = errors.Wrap(err, errMsg)

		zap.L().Error(errMsg,
			zap.String("integrationId", input.IntegrationID),
			zap.Error(err))
		return deleteIntegrationInternalError
	}

	if integrationItem == nil {
		return &genericapi.DoesNotExistError{Message: "Integration does not exist"}
	}

	switch integrationItem.IntegrationType {
	case models.IntegrationTypeAWS3:
		existingIntegrations, err := api.DdbClient.ScanIntegrations(aws.String(models.IntegrationTypeAWS3))
		if err != nil {
			zap.L().Error("failed to scan integration", zap.Error(err))
			return deleteIntegrationInternalError
		}

		shouldRemovePermissions := true
		for _, existingIntegration := range existingIntegrations {
			if existingIntegration.AWSAccountID == integrationItem.AWSAccountID &&
				existingIntegration.IntegrationID != integrationItem.IntegrationID {
				// if another integrationItem exists for the same account
				// don't remove queue permissions. Allow the account to keep sending
				// us SQS notifications
				shouldRemovePermissions = false
				break
			}
		}

		if integrationItem.ManagedBucketNotifications {
			source := itemToIntegration(integrationItem)
			err = RemoveBucketNotifications(api.AwsSession, source)
			if err != nil {
				zap.L().Error("failed to remove bucket notifications",
					zap.Error(err), zap.String("integrationId", input.IntegrationID))
				return deleteIntegrationInternalError
			}
		}

		if shouldRemovePermissions {
			if err = api.DisableExternalSnsTopicSubscription(integrationItem.AWSAccountID); err != nil {
				zap.L().Error("failed to remove permission from SQS queue for integrationItem",
					zap.String("integrationId", input.IntegrationID),
					zap.Error(err))
				return deleteIntegrationInternalError
			}
		}
	case models.IntegrationTypeSqs:
		if err := api.RemoveSourceFromLambdaTrigger(input.IntegrationID); err != nil {
			zap.L().Error("failed to remove sqs queue from source",
				zap.String("integrationId", input.IntegrationID),
				zap.Error(err))
			return deleteIntegrationInternalError
		}
		if err := api.DeleteSourceSqsQueue(input.IntegrationID); err != nil {
			zap.L().Error("failed to delete source queue",
				zap.String("integrationId", input.IntegrationID),
				zap.Error(err))
			return deleteIntegrationInternalError
		}
	}

	err = api.DdbClient.DeleteItem(input.IntegrationID)
	if err != nil {
		zap.L().Error("failed to delete item", zap.Error(err))
		return deleteIntegrationInternalError
	}
	return nil
}
