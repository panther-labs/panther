package table

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Update updates account details and returns the updated item
func (table *OrganizationsTable) Update(org *models.Organization) (*models.Organization, error) {
	update := expression.
		Set(expression.Name("alertReportFrequency"), expression.Value(org.AlertReportFrequency)).
		Set(expression.Name("awsConfig"), expression.Value(org.AwsConfig)).
		Set(expression.Name("displayName"), expression.Value(org.DisplayName)).
		Set(expression.Name("email"), expression.Value(org.Email)).
		Set(expression.Name("errorReportingConsent"), expression.Value(org.ErrorReportingConsent)).
		Set(expression.Name("phone"), expression.Value(org.Phone))
	return table.doUpdate(update)
}

type flagSet []*models.Action

// Marshal string slice as a Dynamo StringSet instead of a List
func (s flagSet) MarshalDynamoDBAttributeValue(av *dynamodb.AttributeValue) error {
	av.SS = make([]*string, 0, len(s))
	for _, flag := range s {
		av.SS = append(av.SS, flag)
	}
	return nil
}

// AddActions append additional actions to completed actions and returns the updated organization
func (table *OrganizationsTable) AddActions(actions []*models.Action) (*models.Organization, error) {
	update := expression.Add(
		expression.Name("completedActions"), expression.Value(flagSet(actions)))
	return table.doUpdate(update)
}

func (table *OrganizationsTable) doUpdate(update expression.UpdateBuilder) (*models.Organization, error) {
	condition := expression.AttributeExists(expression.Name("id"))

	expr, err := expression.NewBuilder().WithCondition(condition).WithUpdate(update).Build()
	if err != nil {
		return nil, &genericapi.InternalError{
			Message: "failed to build update expression: " + err.Error()}
	}

	input := &dynamodb.UpdateItemInput{
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Key:                       DynamoItem{"id": {S: aws.String(orgID)}},
		ReturnValues:              aws.String("ALL_NEW"),
		TableName:                 table.Name,
		UpdateExpression:          expr.Update(),
	}

	zap.L().Info("updating org in dynamo")
	response, err := table.client.UpdateItem(input)

	if err != nil {
		aerr, ok := err.(awserr.Error)
		if ok && aerr.Code() == dynamodb.ErrCodeConditionalCheckFailedException {
			return nil, &genericapi.DoesNotExistError{}
		}
		return nil, &genericapi.AWSError{Method: "dynamodb.UpdateItem", Err: err}
	}

	var newOrg models.Organization
	if err = dynamodbattribute.UnmarshalMap(response.Attributes, &newOrg); err != nil {
		return nil, &genericapi.InternalError{
			Message: "failed to unmarshal dynamo item to an Organization: " + err.Error()}
	}

	return &newOrg, nil
}
