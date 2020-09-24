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

	"github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Update updates account details and returns the updated item
func (table *OrganizationsTable) UpdateGeneralSettings(settings *models.GeneralSettings) (*models.GeneralSettings, error) {
	expr, err := buildGeneralSettingsExpression(settings)
	if err != nil {
		return nil, err
	}

	var newSettings models.GeneralSettings
	if err = table.update(settingsKey, expr, &newSettings); err != nil {
		return nil, err
	}

	return &newSettings, nil
}

// Update only the fields listed in the request.
func buildGeneralSettingsExpression(settings *models.GeneralSettings) (expression.Expression, error) {
	// Initialize update with a no-op (raw expression.UpdateBuilder does not work)
	update := expression.Remove(expression.Name("noSuchName"))

	if settings.DisplayName != nil {
		update = update.Set(expression.Name("displayName"), expression.Value(*settings.DisplayName))
	}
	if settings.Email != nil {
		update = update.Set(expression.Name("email"), expression.Value(*settings.Email))
	}
	if settings.ErrorReportingConsent != nil {
		update = update.Set(expression.Name("errorReportingConsent"), expression.Value(*settings.ErrorReportingConsent))
	}
	if settings.AnalyticsConsent != nil {
		update = update.Set(expression.Name("analyticsConsent"), expression.Value(*settings.AnalyticsConsent))
	}

	expr, err := expression.NewBuilder().WithUpdate(update).Build()
	if err != nil {
		return expr, &genericapi.InternalError{
			Message: "failed to build update expression: " + err.Error()}
	}
	return expr, nil
}

func (table *OrganizationsTable) update(key DynamoItem, expr expression.Expression, newItem interface{}) error {
	response, err := table.client.UpdateItem(&dynamodb.UpdateItemInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Key:                       key,
		ReturnValues:              aws.String("ALL_NEW"),
		TableName:                 table.Name,
		UpdateExpression:          expr.Update(),
	})

	if err != nil {
		return &genericapi.AWSError{Method: "dynamodb.UpdateItem", Err: err}
	}

	if err = dynamodbattribute.UnmarshalMap(response.Attributes, newItem); err != nil {
		return &genericapi.InternalError{Message: "failed to unmarshal dynamo item: " + err.Error()}
	}
	return nil
}
