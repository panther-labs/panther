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
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/core/logtypesapi/transact"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

var L = lambdalogger.FromContext

const (
	// We will use this kind of record to store custom log types
	// For backwards compatibility the value is 'custom'
	recordKindSchema = "custom"

	attrRecordKind = "RecordKind"
	attrRevision   = "revision"
)

var _ SchemaDatabase = (*DynamoDBSchemas)(nil)

// DynamoDBSchemas provides logtypes api actions for DDB
type DynamoDBSchemas struct {
	DB        dynamodbiface.DynamoDBAPI
	TableName string
}

func (d *DynamoDBSchemas) ScanSchemas(ctx context.Context, scan ScanSchemaFunc) error {
	filter, err := expression.NewBuilder().WithFilter(
		expression.Name(attrRecordKind).Equal(expression.Value(recordKindSchema)),
	).Build()
	if err != nil {
		return err
	}
	var itemErr error
	scanErr := d.DB.ScanPagesWithContext(ctx, &dynamodb.ScanInput{
		FilterExpression:          filter.Filter(),
		ExpressionAttributeNames:  filter.Names(),
		ExpressionAttributeValues: filter.Values(),
		TableName:                 aws.String(d.TableName),
	}, func(page *dynamodb.ScanOutput, isLast bool) bool {
		for _, item := range page.Items {
			record := ddbSchemaRecord{}
			if itemErr = dynamodbattribute.UnmarshalMap(item, &record); itemErr != nil {
				return false
			}
			// Skip revision history records
			if record.RecordID != schemaRecordID(record.Name) {
				continue
			}
			if !scan(&record.SchemaRecord) {
				return false
			}
		}
		return true
	})
	if scanErr != nil {
		return scanErr
	}
	if itemErr != nil {
		return itemErr
	}
	return nil
}

func (d *DynamoDBSchemas) GetSchema(ctx context.Context, id string) (*SchemaRecord, error) {
	input := dynamodb.GetItemInput{
		TableName: aws.String(d.TableName),
		Key:       mustMarshalMap(schemaRecordKey(id)),
	}
	output, err := d.DB.GetItemWithContext(ctx, &input)
	if err != nil {
		return nil, err
	}
	L(ctx).Debug("retrieved schema record",
		zap.String("logType", id),
		zap.Any("item", output.Item))

	record := ddbSchemaRecord{}
	if err := dynamodbattribute.UnmarshalMap(output.Item, &record); err != nil {
		return nil, err
	}
	if record.Name == "" {
		return nil, nil
	}
	return &record.SchemaRecord, nil
}

// nolint:lll
func (d *DynamoDBSchemas) PutSchema(ctx context.Context, id string, record *SchemaRecord) (*SchemaRecord, error) {
	upd, err := buildPutSchemaExpression(record)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to build update schema expression")
	}
	reply, err := d.DB.UpdateItemWithContext(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(d.TableName),
		Key:                       mustMarshalMap(schemaRecordKey(id)),
		ConditionExpression:       upd.Condition(),
		UpdateExpression:          upd.Update(),
		ExpressionAttributeNames:  upd.Names(),
		ExpressionAttributeValues: upd.Values(),
		ReturnValues:              aws.String(dynamodb.ReturnValueAllNew),
	})
	if err != nil {
		if errors.As(err, &dynamodb.ConditionalCheckFailedException{}) {
			return nil, NewAPIError(ErrRevisionConflict, fmt.Sprintf("schema record %q is not at revision %d", id, record.Revision))
		}
		return nil, err
	}
	result := SchemaRecord{}
	if err := dynamodbattribute.UnmarshalMap(reply.Attributes, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func buildPutSchemaExpression(record *SchemaRecord) (expression.Expression, error) {
	return transact.BuildExpression(&transact.Update{
		Set: map[string]interface{}{
			// Set if the record is being put for the first time
			transact.SetIfNotExists: struct {
				CreatedAt time.Time `dynamodbav:"createdAt"`
				Name      string    `dynamodbav:"logType"`
				Managed   bool      `dynamodbav:"managed"`
			}{
				CreatedAt: record.CreatedAt,
				Name:      record.Name,
				Managed:   record.Managed,
			},
			// Update fields of the schema record
			transact.SetAll: struct {
				UpdatedAt    time.Time `dynamodbav:"updatedAt"`
				Release      string    `dynamodbav:"release"`
				Revision     int64     `dynamodbav:"revision"`
				Description  string    `dynamodbav:"description"`
				ReferenceURL string    `dynamodbav:"referenceURL"`
				Spec         string    `dynamodbav:"logSpec"`
				Disabled     bool      `dynamodbav:"IsDeleted"`
			}{
				UpdatedAt:    record.UpdatedAt,
				Revision:     record.Revision + 1,
				Release:      record.Release,
				Description:  record.Description,
				ReferenceURL: record.ReferenceURL,
				Spec:         record.Spec,
				Disabled:     record.Disabled,
			},
		},
		// Managed/Custom check is done at API level *BEFORE* the Put
		Condition: expression.Or(
			// Check that the record does not exist
			expression.Name(attrRecordKind).AttributeNotExists(),
			// OR
			// Check that the record has not incremented its revision
			expression.Name(attrRevision).Equal(expression.Value(record.Revision)),
		),
	})
}

type recordKey struct {
	RecordID   string `json:"RecordID" validate:"required"`
	RecordKind string `json:"RecordKind" validate:"required,oneof=native status custom"`
}

func mustMarshalMap(val interface{}) map[string]*dynamodb.AttributeValue {
	attr, err := dynamodbattribute.MarshalMap(val)
	if err != nil {
		panic(err)
	}
	return attr
}
func schemaRecordKey(id string) recordKey {
	return recordKey{
		RecordID:   schemaRecordID(id),
		RecordKind: recordKindSchema,
	}
}

func schemaRecordID(id string) string {
	return strings.ToUpper(id)
}

type ddbSchemaRecord struct {
	recordKey
	SchemaRecord
}
