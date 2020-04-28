package table

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Update updates account details and returns the updated item
func (table *OrganizationsTable) Update(settings *models.GeneralSettings) (*models.GeneralSettings, error) {
	expr, err := buildUpdateExpression(settings)
	if err != nil {
		return nil, err
	}

	input := &dynamodb.UpdateItemInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Key:                       settingsKey,
		ReturnValues:              aws.String("ALL_NEW"),
		TableName:                 table.Name,
		UpdateExpression:          expr.Update(),
	}

	zap.L().Debug("updating general settings in dynamo")
	response, err := table.client.UpdateItem(input)

	if err != nil {
		return nil, &genericapi.AWSError{Method: "dynamodb.UpdateItem", Err: err}
	}

	var newSettings models.GeneralSettings
	if err = dynamodbattribute.UnmarshalMap(response.Attributes, &newSettings); err != nil {
		return nil, &genericapi.InternalError{
			Message: "failed to unmarshal dynamo item to GeneralSettings: " + err.Error()}
	}

	return &newSettings, nil
}

// Update only the fields listed in the request.
func buildUpdateExpression(settings *models.GeneralSettings) (expression.Expression, error) {
	var update expression.UpdateBuilder
	updateInitialized := false

	if settings.DisplayName != nil {
		update = expression.Set(expression.Name("displayName"), expression.Value(settings.DisplayName))
		updateInitialized = true
	}

	if settings.Email != nil {
		if updateInitialized {
			update = update.Set(expression.Name("email"), expression.Value(settings.Email))
		} else {
			update = expression.Set(expression.Name("email"), expression.Value(settings.Email))
			updateInitialized = true
		}
	}

	if settings.ErrorReportingConsent != nil {
		if updateInitialized {
			update = update.Set(expression.Name("errorReportingConsent"), expression.Value(settings.ErrorReportingConsent))
		} else {
			update = expression.Set(expression.Name("errorReportingConsent"), expression.Value(settings.ErrorReportingConsent))
			updateInitialized = true
		}
	}

	var expr expression.Expression
	if !updateInitialized {
		return expr, &genericapi.InvalidInputError{
			Message: "at least one setting is required to update",
		}
	}

	expr, err := expression.NewBuilder().WithUpdate(update).Build()
	if err != nil {
		return expr, &genericapi.InternalError{
			Message: "failed to build update expression: " + err.Error()}
	}
	return expr, nil
}
