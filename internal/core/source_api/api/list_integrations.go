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

var genericListError = &genericapi.InternalError{Message: "Failed to list integrations"}

// ListIntegrations returns all enabled integrations.
func (api *API) ListIntegrations(
	input *models.ListIntegrationsInput) ([]*models.SourceIntegration, error) {

	integrationItems, err := api.DdbClient.ScanIntegrations(input.IntegrationType)
	if err != nil {
		zap.L().Error("failed to list integrations", zap.Error(err))
		return nil, genericListError
	}

	result := make([]*models.SourceIntegration, 0, len(integrationItems))
	for _, item := range integrationItems {
		if item.IntegrationType == "" {
			// Due to a previous bug, a deleted integration could be re-created in the DB without
			// the IntegrationType field. This would break Panther in many places in addition to
			// breaking Panther upgrades. Skip these sources.
			continue
		}
		integ := ddb.ItemToIntegration(item)
		// This is required for backwards compatibility
		// Before https://github.com/panther-labs/panther/issues/2031 , the Compliance sources
		// didn't have the InputDataBucket and InputDataRoleArn populated
		if integ.IntegrationType == models.IntegrationTypeAWSScan {
			if integ.S3Bucket == "" {
				integ.S3Bucket = api.Config.InputDataBucketName
				integ.LogProcessingRole = api.Config.InputDataRoleArn
			}
		}
		result = append(result, integ)
	}
	return result, nil
}
