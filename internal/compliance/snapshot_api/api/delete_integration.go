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
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/snapshot/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// DeleteIntegration deletes a specific integration.
func (API) DeleteIntegration(input *models.DeleteIntegrationInput) (err error) {
	var integrationForDeletePermissions *models.SourceIntegrationMetadata
	defer func() {
		if err != nil && integrationForDeletePermissions != nil {
			// In case we have already removed the Permissions from SQS but some other operation failed
			// re-add the permissions
			if undoErr := AddPermissionToLogProcessorQueue(*integrationForDeletePermissions.AWSAccountID); undoErr != nil {
				zap.L().Error("failed to re-add SQS permission for integration. SQS is missing permissions that have to be added manually",
					zap.String("integrationId", *integrationForDeletePermissions.IntegrationID),
					zap.Error(undoErr),
					zap.Error(err))
			}
		}
	}()

	var integration *models.SourceIntegrationMetadata
	integration, err = db.GetIntegration(input.IntegrationID)
	if err != nil {
		errMsg := "failed to get integration"
		zap.L().Error(errMsg,
			zap.String("integrationId", *input.IntegrationID),
			zap.Error(errors.Wrap(err, errMsg)))
		return &genericapi.InternalError{Message: errMsg}
	}

	if integration == nil {
		return &genericapi.DoesNotExistError{Message: "Integration does not exist"}
	}

	if *integration.IntegrationType == models.IntegrationTypeAWS3 {
		if err = RemovePermissionFromLogProcessorQueue(*integration.AWSAccountID); err != nil {
			zap.L().Error("failed to remove permission from SQS queue for integration",
				zap.String("integrationId", *input.IntegrationID),
				zap.Error(errors.Wrap(err, "failed to remove permission from SQS queue for integration")))
			return &genericapi.InternalError{Message: "failed to update integration"}
		}
		integrationForDeletePermissions = integration
	}
	err = db.DeleteIntegrationItem(input)
	return err
}
