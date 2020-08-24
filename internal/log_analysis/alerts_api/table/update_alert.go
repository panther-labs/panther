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
	"encoding/json"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// UpdateAlertStatus - updates the alert details and returns the updated item
func (table *AlertsTable) UpdateAlertStatus(input *models.UpdateAlertStatusInput) (*AlertItem, error) {
	// Create the dynamo key we want to update
	var alertKey = DynamoItem{AlertIDKey: {S: aws.String(*input.AlertID)}}

	// Create the update builder
	updateBuilder := createUpdateBuilder(input)

	// Create the condition builder
	conditionBuilder := createConditionBuilder(input)

	// Build an expression from our builders
	expression, err := buildExpression(updateBuilder, conditionBuilder)
	if err != nil {
		return nil, err
	}

	// Create our dynamo update item
	updateItem := dynamodb.UpdateItemInput{
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

// UpdateAlertDelivery - updates the alert details and returns the updated item
func (table *AlertsTable) UpdateAlertDelivery(input *models.UpdateAlertDeliveryInput) (*AlertItem, error) {
	// Create the dynamo key we want to update
	var alertKey = DynamoItem{AlertIDKey: {S: aws.String(input.AlertID)}}

	// convert out list of response structs to a list of maps to be stored in dynamo.
	// This is purely so we can clearly see JSON in DDB for readability
	deliveryResponsesMaps, err := toListOfMaps(input.DeliveryResponses)
	if err != nil {
		zap.L().Error(
			"failed to convert delivery responses struct to map",
			zap.Any("deliveryResponses", input.DeliveryResponses),
		)
		return nil, err
	}

	// Create the update builder. If the column was null, we set to an empty list.
	// Dynamo cannot append to NULL so we must create the empty list
	updateBuilder := expression.Set(expression.Name(DeliveryResponsesKey),
		expression.ListAppend(
			expression.IfNotExists(expression.Name(DeliveryResponsesKey), expression.Value([]interface{}{})),
			expression.Value(deliveryResponsesMaps),
		))

	// Create the condition builder
	conditionBuilder := expression.Equal(expression.Name(AlertIDKey), expression.Value(input.AlertID))

	// Build an expression from our builders
	expression, err := buildExpression(updateBuilder, conditionBuilder)
	if err != nil {
		return nil, err
	}

	// Create our dynamo update item
	updateItem := dynamodb.UpdateItemInput{
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
	if *input.Status == models.OpenStatus {
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
func createConditionBuilder(input *models.UpdateAlertStatusInput) expression.ConditionBuilder {
	return expression.Equal(expression.Name(AlertIDKey), expression.Value(input.AlertID))
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

// table.update - runs an update query
func (table *AlertsTable) update(
	item dynamodb.UpdateItemInput,
	newItem interface{},
) error {

	response, err := table.Client.UpdateItem(&item)

	if err != nil {
		return &genericapi.AWSError{Method: "dynamodb.UpdateItem", Err: err}
	}

	if err = dynamodbattribute.UnmarshalMap(response.Attributes, newItem); err != nil {
		return &genericapi.InternalError{Message: "failed to unmarshal dynamo item: " + err.Error()}
	}
	return nil
}

// toListOfMaps - convert our list of structs to a list of maps by marshaling
func toListOfMaps(responses []*models.DeliveryResponse) ([]map[string]interface{}, error) {
	result := make([]map[string]interface{}, 0)
	for _, response := range responses {
		responseBytes, err := json.Marshal(response)
		if err != nil {
			return nil, err
		}
		mappedResponse := make(map[string]interface{})
		err = json.Unmarshal(responseBytes, &mappedResponse)
		if err != nil {
			return nil, err
		}
		result = append(result, mappedResponse)
	}
	return result, nil
}
