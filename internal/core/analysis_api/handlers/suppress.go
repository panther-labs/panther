package handlers

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
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

// Suppress adds suppressions for one or more policies in the same organization.
func (API) Suppress(input *models.SuppressInput) *events.APIGatewayProxyResponse {
	updates, err := addSuppressions(input.PolicyIDs, input.ResourcePatterns)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	// Update compliance status with new suppressions
	for _, policy := range updates {
		if err := updateComplianceMetadata(policy); err != nil {
			// Log an error, but don't mark the API call as a failure
			zap.L().Error("failed to update compliance entries with new suppression", zap.Error(err))
		}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}
