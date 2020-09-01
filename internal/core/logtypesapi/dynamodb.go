package logtypesapi

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
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/lambdalogger"
)

type ExternalAPIDynamoDB struct {
	DB        dynamodbiface.DynamoDBAPI
	TableName string
}

var _ ExternalAPI = (*ExternalAPIDynamoDB)(nil)

var L = lambdalogger.FromContext

func (s *ExternalAPIDynamoDB) ListLogTypes(ctx context.Context) ([]string, error) {
	ddbInput := dynamodb.GetItemInput{
		TableName:            aws.String(s.TableName),
		ProjectionExpression: aws.String(attrAvailableLogTypes),
		Key: mustMarshalMap(&recordKey{
			RecordID:   "Status",
			RecordKind: recordKindStatus,
		}),
	}

	ddbOutput, err := s.DB.GetItemWithContext(ctx, &ddbInput)
	if err != nil {
		L(ctx).Error(`failed to get DynamoDB item`, zap.Error(err))
		return nil, err
	}

	item := struct {
		AvailableLogTypes []string
	}{}
	if err := dynamodbattribute.UnmarshalMap(ddbOutput.Item, &item); err != nil {
		L(ctx).Error(`failed to unmarshal DynamoDB item`, zap.Error(err))
		return nil, err
	}

	return item.AvailableLogTypes, nil
}

const (
	recordKindStatus      = "status"
	attrAvailableLogTypes = "AvailableLogTypes"
)

func mustMarshalMap(val interface{}) map[string]*dynamodb.AttributeValue {
	attr, err := dynamodbattribute.MarshalMap(val)
	if err != nil {
		panic(err)
	}
	return attr
}

type recordKey struct {
	RecordID   string
	RecordKind string
}
