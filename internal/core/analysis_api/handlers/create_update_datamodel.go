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
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var (
	errPathOrMethodMissing       = errors.New("exactly one path or one method must be specified per mapping entry")
	errMappingTooManyOptions     = errors.New("a path or a method, but not both, must be specified per mapping entry")
	errMultipleDataModelsEnabled = errors.New("only one DataModel can be enabled per LogType")
)

// CreateDataModel adds a new DataModel to the Dynamo table.
func (API) CreateDataModel(input *models.CreateDataModelInput) *events.APIGatewayProxyResponse {
	return writeDataModel(input, true)
}

func (API) UpdateDataModel(input *models.UpdateDataModelInput) *events.APIGatewayProxyResponse {
	return writeDataModel(input, false)
}

func writeDataModel(input *models.UpdateDataModelInput, create bool) *events.APIGatewayProxyResponse {
	if err := validateUpdateDataModel(input); err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       err.Error(),
			StatusCode: http.StatusBadRequest,
		}
	}

	// we only need to check for conflicting enabled DataModels if the new one is
	// going to be enabled
	isEnabled, err := isSingleDataModelEnabled(input.ID, input.Enabled, input.LogTypes)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       err.Error(),
			StatusCode: http.StatusInternalServerError,
		}
	}
	if !isEnabled {
		return &events.APIGatewayProxyResponse{
			Body:       errMultipleDataModelsEnabled.Error(),
			StatusCode: http.StatusBadRequest,
		}
	}

	item := &tableItem{
		Body:          input.Body,
		Description:   input.Description,
		DisplayName:   input.DisplayName,
		Enabled:       input.Enabled,
		ID:            input.ID,
		Mappings:      input.Mappings,
		ResourceTypes: input.LogTypes,
		Type:          models.TypeDataModel,
	}

	var statusCode int
	if create {
		if _, err := writeItem(item, input.UserID, aws.Bool(false)); err != nil {
			if err == errExists {
				return &events.APIGatewayProxyResponse{
					Body:       err.Error(),
					StatusCode: http.StatusConflict,
				}
			}
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		statusCode = http.StatusCreated
	} else {
		if _, err := writeItem(item, input.UserID, aws.Bool(true)); err != nil {
			if err == errNotExists || err == errWrongType {
				// errWrongType means we tried to modify a data model that is actually a global/policy/rule.
				// In this case return 404 - the data model you tried to modify does not exist.
				return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}
			}
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
		statusCode = http.StatusOK
	}

	return gatewayapi.MarshalResponse(item.DataModel(), statusCode)
}

// Some extra validation which is not implemented in the input struct tags
func validateUpdateDataModel(input *models.UpdateDataModelInput) error {
	// verify that field and method are mutually exclusive in the input
	for _, mapping := range input.Mappings {
		if mapping.Path != "" && mapping.Method != "" {
			return errMappingTooManyOptions
		}
	}

	if err := validateLogtypeSet(input.LogTypes); err != nil {
		return errors.Errorf("dataModel contains invalid log type: %s", err.Error())
	}

	return nil
}

// check that only one DataModel is enabled per ResourceType/LogType
func isSingleDataModelEnabled(dataModelID string, enabled bool, logTypes []string) (bool, error) {
	// no need to check for conflicts if we aren't enabling the new DataModel
	if !enabled {
		return true, nil
	}

	enabledFilter := expression.Equal(expression.Name("enabled"), expression.Value(true))
	idFilter := expression.NotEqual(expression.Name("id"), expression.Value(dataModelID))
	logTypeFilter := expression.AttributeNotExists(expression.Name("resourceTypes"))
	for _, typeName := range logTypes {
		logTypeFilter = logTypeFilter.Or(expression.Contains(expression.Name("resourceTypes"), typeName))
	}

	scanInput, err := buildScanInput(
		[]models.DetectionType{models.TypeDataModel}, []string{"id"}, expression.And(enabledFilter, idFilter, logTypeFilter))

	if err != nil {
		return false, err
	}

	conflict := false
	err = scanPages(scanInput, func(item tableItem) error {
		conflict = true
		return nil
	})

	return !conflict, err
}
