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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// AddOutput encrypts the output configuration and stores it to Dynamo.
func (API) AddOutput(input *models.AddOutputInput) (*models.AddOutputOutput, error) {
	item, err := outputsTable.GetOutputByName(input.DisplayName)
	if err != nil {
		return nil, err
	}

	if item != nil {
		return nil, &genericapi.AlreadyExistsError{
			Message: "A destination with the name" + *input.DisplayName + " already exists, please choose another display name"}
	}

	outputType, err := getOutputType(input.OutputConfig)
	if err != nil {
		return nil, &genericapi.InvalidInputError{Message: err.Error()}
	}

	err = validateConfigByType(input.OutputConfig, outputType)
	if err != nil {
		return nil, &genericapi.InvalidInputError{Message: err.Error()}
	}

	alertOutput := &models.AlertOutput{
		OutputID:           aws.String(uuid.New().String()),
		DisplayName:        input.DisplayName,
		CreatedBy:          input.UserID,
		CreationTime:       aws.String(time.Now().Format(time.RFC3339)),
		LastModifiedBy:     input.UserID,
		LastModifiedTime:   aws.String(time.Now().Format(time.RFC3339)),
		OutputType:         outputType,
		OutputConfig:       input.OutputConfig,
		DefaultForSeverity: input.DefaultForSeverity,
		AlertTypes:         input.AlertTypes,
	}

	alertOutputItem, err := AlertOutputToItem(alertOutput)
	if err != nil {
		return nil, err
	}

	if err = outputsTable.PutOutput(alertOutputItem); err != nil {
		return nil, err
	}

	zap.L().Debug("stored new alert output",
		zap.String("outputId", *alertOutput.OutputID))

	redactOutput(alertOutput.OutputConfig)
	return alertOutput, nil
}
