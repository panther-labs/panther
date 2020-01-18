package handlers

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
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
)

// DeletePolicies marks one or more policies as deleted.
func DeletePolicies(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	input, err := parseDeletePolicies(request)
	if err != nil {
		return badRequest(err)
	}

	if err = dynamoBatchDelete(input); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	if err = s3BatchDelete(input); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	if err = complianceBatchDelete(input.Policies, []string{}); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

func parseDeletePolicies(request *events.APIGatewayProxyRequest) (*models.DeletePolicies, error) {
	var result models.DeletePolicies
	if err := jsoniter.UnmarshalFromString(request.Body, &result); err != nil {
		return nil, err
	}

	if err := result.Validate(nil); err != nil {
		return nil, err
	}

	return &result, nil
}
