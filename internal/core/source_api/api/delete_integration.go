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
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/pkg/genericapi"
)

var (
	deleteIntegrationInternalError = &genericapi.InternalError{Message: "Failed to delete source. Please try again later"}
)

// DeleteIntegration deletes a specific integration.
func (API) DeleteIntegration(input *models.DeleteIntegrationInput) (err error) {
	var integrationForDeletePermissions *models.SourceIntegration
	defer func() {
		if err != nil && integrationForDeletePermissions != nil {
			// In case we have already removed the Permissions from SQS but some other operation failed
			// re-add the permissions
			if _, undoErr := AllowExternalSnsTopicSubscription(*integrationForDeletePermissions.AWSAccountID); undoErr != nil {
				zap.L().Error("failed to re-add SQS permission for integrationItem. SQS is missing permissions that have to be added manually",
					zap.String("integrationId", *integrationForDeletePermissions.IntegrationID),
					zap.Error(undoErr),
					zap.Error(err))
			}
		}
	}()

	var integrationItem *ddb.Integration
	integrationItem, err = dynamoClient.GetItem(input.IntegrationID)
	if err != nil {
		errMsg := "failed to get integrationItem"
		err = errors.Wrap(err, errMsg)

		zap.L().Error(errMsg,
			zap.String("integrationId", *input.IntegrationID),
			zap.Error(err))
		return deleteIntegrationInternalError
	}

	if integrationItem == nil {
		return &genericapi.DoesNotExistError{Message: "Integration does not exist"}
	}

	switch *integrationItem.IntegrationType {
	case models.IntegrationTypeAWS3:
		existingIntegrations, err := dynamoClient.ScanIntegrations(aws.String(models.IntegrationTypeAWS3))
		if err != nil {
			return deleteIntegrationInternalError
		}

		shouldRemovePermissions := true
		for _, existingIntegration := range existingIntegrations {
			if *existingIntegration.AWSAccountID == *integrationItem.AWSAccountID &&
				*existingIntegration.IntegrationID != *integrationItem.IntegrationID {
				// if another integrationItem exists for the same account
				// don't remove queue permissions. Allow the account to keep sending
				// us SQS notifications
				shouldRemovePermissions = false
				break
			}
		}

		if shouldRemovePermissions {
			if err = DisableExternalSnsTopicSubscription(*integrationItem.AWSAccountID); err != nil {
				zap.L().Error("failed to remove permission from SQS queue for integrationItem",
					zap.String("integrationId", *input.IntegrationID),
					zap.Error(errors.Wrap(err, "failed to remove permission from SQS queue for integrationItem")))
				return deleteIntegrationInternalError
			}
			integrationForDeletePermissions = itemToIntegration(integrationItem)
		}
	}

	err = dynamoClient.DeleteItem(input.IntegrationID)
	if err != nil {
		return deleteIntegrationInternalError
	}
	return nil
}
