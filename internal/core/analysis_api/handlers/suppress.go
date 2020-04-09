package handlers

/**
 * A Cloud-Native SIEM for the Modern Security Team
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
	"errors"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
)

// Suppress adds suppressions for one or more policies in the same organization.
func Suppress(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	input, err := parseSuppress(request)
	if err != nil {
		return badRequest(err)
	}

	updates, err := addSuppressions(input.PolicyIds, input.ResourcePatterns)
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

func parseSuppress(request *events.APIGatewayProxyRequest) (*models.Suppress, error) {
	var result models.Suppress
	if err := jsoniter.UnmarshalFromString(request.Body, &result); err != nil {
		return nil, err
	}

	if err := result.Validate(nil); err != nil {
		return nil, err
	}

	if len(result.ResourcePatterns) == 0 {
		return nil, errors.New("invalid resourcePatterns: at least one is required")
	}

	return &result, nil
}
