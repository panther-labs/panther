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
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/pkg/genericapi"
)

var (
	updateStatusInternalError = &genericapi.InternalError{Message: "Failed to update source status, please try again later"}
)

func (api API) UpdateStatus(input *models.UpdateStatusInput) error {
	status := ddb.IntegrationStatus{
		LastEventReceived: input.LastEventReceived,
	}
	err := dynamoClient.UpdateStatus(input.IntegrationID, status)
	if err != nil {
		zap.L().Error("failed to update integration status", zap.Error(err), zap.String("integrationId", input.IntegrationID))
		return updateStatusInternalError
	}
	return nil
}
