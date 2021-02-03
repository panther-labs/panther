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

	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

func (API) DeletePolicies(input *models.DeletePoliciesInput) *events.APIGatewayProxyResponse {
	if err := dynamoBatchDelete(input); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	if err := s3BatchDelete(input); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	if err := complianceBatchDelete(input.Entries, []string{}); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

func (API) DeleteRules(input *models.DeleteRulesInput) *events.APIGatewayProxyResponse {
	if err := dynamoBatchDelete(input); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	if err := s3BatchDelete(input); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

func (API) DeleteDetections(input *models.DeletePoliciesInput) *events.APIGatewayProxyResponse {
	if err := s3BatchDelete(input); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	if err := complianceBatchDelete(input.Entries, []string{}); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	if err := dynamoBatchDelete(input); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

func (api API) DeleteDataModels(input *models.DeleteDataModelsInput) *events.APIGatewayProxyResponse {
	return api.DeleteRules(input)
}

func (API) DeleteGlobals(input *models.DeleteGlobalsInput) *events.APIGatewayProxyResponse {
	/*
		There are three separate actions here, and each one could fail in turn leading to different scenarios:

		1. Dynamo delete fails. The whole process is cancelled and nothing changes, no inconsistent state. The user sees
		an error and needs to try and delete the global again.
		2. Layer update fails. At this point, the global has already been deleted from dynamo, but the history is still
		present and the layer is not updated, so there is an inconsistency between what is in dynamo and what is actually
		running. The next time any change happens to globals successfully (create, update, or delete), the layer manager
		will re-create the whole thing and the inconsistent state will be resolved.
		3. S3 delete fails. At this point, there is no memory of the global anywhere except in s3. Currently we're not
		using the s3 history for anything, but if we ever do then this could become problematic then.
	*/
	if err := dynamoBatchDelete(input); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	if err := updateLayer(); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	if err := s3BatchDelete(input); err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}
