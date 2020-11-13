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
	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// ModifyDataModel updates an existing data model.
func ModifyDataModel(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	input, err := parseUpdateDataModel(request)
	if err != nil {
		return badRequest(err)
	}

	item := &tableItem{
		Body:          input.Body,
		Description:   input.Description,
		DisplayName:   input.DisplayName,
		Enabled:       input.Enabled,
		ID:            input.ID,
		Mappings:      input.Mappings,
		ResourceTypes: input.LogTypes,
		Type:          typeDataModel,
	}

	// check for conflicting enabled DataModels and return an error
	// so the user doesn't expect this value to be updated
	enabledCheck, err := isSingleDataModelEnabled(input)
	if err != nil {
		return failedRequest(err.Error(), http.StatusInternalServerError)
	}
	if !enabledCheck {
		return badRequest(errMultipleDataModelsEnabled)
	}

	if _, err := writeItem(item, input.UserID, aws.Bool(true)); err != nil {
		if err == errNotExists || err == errWrongType {
			// errWrongType means we tried to modify a data model that is actually a global/policy/rule.
			// In this case return 404 - the data model you tried to modify does not exist.
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}
		}
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(item.DataModel(), http.StatusOK)
}
