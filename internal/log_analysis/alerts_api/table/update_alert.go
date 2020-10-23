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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// UpdateAlertStatus - updates a list of alerts to a specified status and returns the updated list
func (table *AlertsTable) UpdateAlertStatus(input *models.UpdateAlertStatusInput) ([]*AlertItem, error) {
	updateItems := []*dynamodb.UpdateItemInput{}
	for _, alertID := range input.AlertIDs {
		// Create the dynamo key we want to update
		alertKey := DynamoItem{AlertIDKey: {S: aws.String(alertID)}}

		// Create the update builder
		updateBuilder := createUpdateBuilder(input)

		// Create the condition builder
		conditionBuilder := createConditionBuilder(alertID)

		// Build an expression from our builders
		expression, err := buildExpression(updateBuilder, conditionBuilder)
		if err != nil {
			return nil, err
		}

		// Create our dynamo update item
		updateItem := &dynamodb.UpdateItemInput{
			ConditionExpression:       expression.Condition(),
			ExpressionAttributeNames:  expression.Names(),
			ExpressionAttributeValues: expression.Values(),
			Key:                       alertKey,
			ReturnValues:              aws.String("ALL_NEW"),
			TableName:                 &table.AlertsTableName,
			UpdateExpression:          expression.Update(),
		}

		updateItems = append(updateItems, updateItem)
	}

	// Create a list of items that will hold our results
	updatedAlerts := make([]*AlertItem, len(updateItems))
	if err := table.updateAll(updateItems, updatedAlerts); err != nil {
		return nil, err
	}

	return updatedAlerts, nil
}

// UpdateAlertDelivery - updates the alert details and returns the updated item
func (table *AlertsTable) UpdateAlertDelivery(input *models.UpdateAlertDeliveryInput) (*AlertItem, error) {
	// Create the dynamo key we want to update
	alertKey := DynamoItem{AlertIDKey: {S: aws.String(input.AlertID)}}

	// Hack to work around dynamo's expression syntax which cannot simply store an empty slice
	// https://github.com/aws/aws-sdk-go/issues/682
	emptyList := dynamodb.AttributeValue{L: []*dynamodb.AttributeValue{}}

	// Create the update builder. If the column was null, we set to an empty list.
	// Dynamo cannot append to NULL so we must create the empty list
	updateBuilder := expression.Set(expression.Name(DeliveryResponsesKey),
		expression.ListAppend(
			expression.IfNotExists(expression.Name(DeliveryResponsesKey), expression.Value(emptyList)),
			expression.Value(input.DeliveryResponses),
		))

	// Create the condition builder
	conditionBuilder := expression.Equal(expression.Name(AlertIDKey), expression.Value(input.AlertID))

	// Build an expression from our builders
	expression, err := buildExpression(updateBuilder, conditionBuilder)
	if err != nil {
		return nil, err
	}

	// Create our dynamo update item
	updateItem := &dynamodb.UpdateItemInput{
		ExpressionAttributeNames:  expression.Names(),
		ExpressionAttributeValues: expression.Values(),
		Key:                       alertKey,
		ReturnValues:              aws.String("ALL_NEW"),
		TableName:                 &table.AlertsTableName,
		UpdateExpression:          expression.Update(),
		ConditionExpression:       expression.Condition(),
	}

	// Run the update query and marshal
	updatedAlert := &AlertItem{}
	if err = table.update(updateItem, &updatedAlert); err != nil {
		return nil, err
	}

	return updatedAlert, nil
}

// createUpdateBuilder - creates an update builder
func createUpdateBuilder(input *models.UpdateAlertStatusInput) expression.UpdateBuilder {
	// When settig an "open" status we actually remove the attribute
	// for uniformity against previous items in the database
	// which also do not have a status attribute.
	if input.Status == models.OpenStatus {
		return expression.
			Remove(expression.Name(StatusKey)).
			Set(expression.Name(LastUpdatedByKey), expression.Value(input.UserID)).
			Set(expression.Name(LastUpdatedByTimeKey), expression.Value(aws.Time(time.Now().UTC())))
	}

	return expression.
		Set(expression.Name(StatusKey), expression.Value(input.Status)).
		Set(expression.Name(LastUpdatedByKey), expression.Value(input.UserID)).
		Set(expression.Name(LastUpdatedByTimeKey), expression.Value(aws.Time(time.Now().UTC())))
}

// createConditionBuilder - creates a condition builder
func createConditionBuilder(alertID string) expression.ConditionBuilder {
	return expression.Equal(expression.Name(AlertIDKey), expression.Value(alertID))
}

// buildExpression - builds an expression
func buildExpression(
	updateBuilder expression.UpdateBuilder,
	conditionBuilder expression.ConditionBuilder,
) (expression.Expression, error) {

	expr, err := expression.
		NewBuilder().
		WithUpdate(updateBuilder).
		WithCondition(conditionBuilder).
		Build()
	if err != nil {
		return expr, &genericapi.InternalError{
			Message: "failed to build update expression: " + err.Error()}
	}
	return expr, nil
}

// table.updateAll - updates a list of items sequentially
func (table *AlertsTable) updateAll(
	updateInputs []*dynamodb.UpdateItemInput,
	updatedItems []*AlertItem,
) error {

	for i, updateInput := range updateInputs {
		if err := table.update(updateInput, &updatedItems[i]); err != nil {
			return err
		}
	}
	return nil
}

// table.update - runs a single update query
func (table *AlertsTable) update(
	updateInput *dynamodb.UpdateItemInput,
	updatedItem interface{},
) error {

	response, err := table.Client.UpdateItem(updateInput)
	if err != nil {
		return &genericapi.AWSError{Method: "dynamodb.UpdateItem", Err: err}
	}

	if err = dynamodbattribute.UnmarshalMap(response.Attributes, updatedItem); err != nil {
		return &genericapi.InternalError{Message: "failed to unmarshal dynamo item: " + err.Error()}
	}
	return nil
}
