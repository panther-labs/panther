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
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/genericapi"
)

var (
	errDataModelTooManyLogTypes  = errors.New("only one ResourceType may be specified per DataModel")
	errPathOrMethodMissing       = errors.New("exactly one path or one method must be specified per mapping entry")
	errMappingTooManyOptions     = errors.New("a path or a method, but not both, must be specified per mapping entry")
	errMultipleDataModelsEnabled = errors.New("only one DataModel can be enabled per ResourceType")
)

// CreateDataModel adds a new DataModel to the Dynamo table.
func CreateDataModel(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	input, err := parseUpdateDataModel(request)
	if err != nil {
		return badRequest(err)
	}

	// we only need to check for conflicting enabled DataModels if the new one is
	// going to be enabled
	isEnabled, err := isSingleDataModelEnabled(input)
	if err != nil {
		return failedRequest(err.Error(), http.StatusInternalServerError)
	}
	if !isEnabled {
		return badRequest(errMultipleDataModelsEnabled)
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

	if _, err := writeItem(item, input.UserID, aws.Bool(false)); err != nil {
		if err == errExists {
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusConflict}
		}
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(item.DataModel(), http.StatusCreated)
}

// body parsing shared by CreateDataModel and ModifyDataModel
func parseUpdateDataModel(request *events.APIGatewayProxyRequest) (*models.UpdateDataModel, error) {
	var result models.UpdateDataModel
	if err := jsoniter.UnmarshalFromString(request.Body, &result); err != nil {
		return nil, err
	}

	if err := result.Validate(nil); err != nil {
		return nil, err
	}

	// Display names are embedded in emails, alert outputs, etc. Prevent a possible injection attack
	if genericapi.ContainsHTML(string(result.DisplayName)) {
		return nil, fmt.Errorf("display name: %v", genericapi.ErrContainsHTML)
	}

	// we also need to verify that field and method are mutually exclusive in the input
	for _, mapping := range result.Mappings {
		if mapping.Path != "" && mapping.Method != "" {
			return nil, errMappingTooManyOptions
		}
		if mapping.Path == "" && mapping.Method == "" {
			return nil, errPathOrMethodMissing
		}
	}

	// For now, we only allow setting one LogType per DataModel
	if len(result.LogTypes) > 1 {
		return nil, errDataModelTooManyLogTypes
	}

	return &result, nil
}

// check that only one DataModel is enabled per ResourceType/LogType
func isSingleDataModelEnabled(updateDataModel *models.UpdateDataModel) (bool, error) {
	// no need to check for conflicts if we aren't enabling the new DataModel
	if !bool(updateDataModel.Enabled) {
		return true, nil
	}
	// setup var for new LogTypes this data model will apply to
	newLogTypes := updateDataModel.LogTypes
	// check if this is an update or a new item
	oldItem, err := dynamoGet(updateDataModel.ID, true)
	if err != nil {
		return false, err
	}
	// this is updating an existing item
	if oldItem != nil {
		if updateDataModel.Enabled == oldItem.Enabled {
			// if not updating enabled status nor the LogTypes, no need to continue check
			if setEquality(oldItem.ResourceTypes, updateDataModel.LogTypes) {
				return true, nil
			}
			// This can be uncommented when we enabled multiple LogTypes per DataModel
			// if not updating the enabled status, only need to check new LogTypes
			//newLogTypes = setDifference(updateDataModel.LogTypes, oldItem.ResourceTypes)
		}
	}

	// Scan dynamo
	// Build the dynamodb scan expression
	projection := expression.NamesList(
		expression.Name("id"),
		expression.Name("enabled"),
		expression.Name("resourceTypes"),
	)
	// Build filter to search for enabled DataModels with the new LogTypes
	typeFilter := expression.Equal(expression.Name("type"), expression.Value(typeDataModel))
	enabledFilter := expression.Equal(expression.Name("enabled"), expression.Value(true))
	logTypeFilter := expression.AttributeNotExists(expression.Name("resourceTypes"))
	for _, typeName := range newLogTypes {
		logTypeFilter = logTypeFilter.Or(expression.Contains(expression.Name("resourceTypes"), typeName))
	}
	filter := expression.And(typeFilter, enabledFilter, logTypeFilter)

	expr, err := expression.NewBuilder().
		WithFilter(filter).
		WithProjection(projection).
		Build()

	if err != nil {
		return false, err
	}
	scanInput := &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &env.Table,
	}
	var dataModels []*models.DataModel
	err = scanPages(scanInput, func(item *tableItem) error {
		dataModels = append(dataModels, &models.DataModel{
			ID:       item.ID,
			Enabled:  item.Enabled,
			LogTypes: item.ResourceTypes,
		})
		return nil
	})

	if err != nil {
		return false, err
	}
	if len(dataModels) != 0 {
		return false, nil
	}
	return true, nil
}
