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
	"errors"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/api/gateway/resources/models"
)

// ModifyResource will update some of the resource properties.
func ModifyResource(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	input, err := parseModifyResource(request)
	if err != nil {
		return badRequest(err)
	}

	// Replace subsets of the resource attributes, not the whole thing.
	// For example, {"VersioningEnabled": true, "EncryptionConfig.KeyID": "abc"}
	update := expression.Set(expression.Name("lastModified"), expression.Value(time.Now()))
	for key, val := range input.ReplaceAttributes.(map[string]interface{}) {
		update = update.Set(expression.Name("attributes."+key), expression.Value(val))
	}

	return doUpdate(update, input.ID)
}

// Parse the request body into a ModifyResource model.
func parseModifyResource(request *events.APIGatewayProxyRequest) (*models.ModifyResource, error) {
	var result models.ModifyResource
	if err := jsoniter.UnmarshalFromString(request.Body, &result); err != nil {
		return nil, err
	}

	// swagger doesn't validate an arbitrary object
	if len(result.ReplaceAttributes.(map[string]interface{})) == 0 {
		return &result, errors.New("at least one attribute is required")
	}

	return &result, result.Validate(nil)
}
