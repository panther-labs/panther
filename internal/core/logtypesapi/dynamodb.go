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
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/customlogs"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

// DynamoDBLogTypes provides logtypes api actions for DDB
type DynamoDBLogTypes struct {
	DB        dynamodbiface.DynamoDBAPI
	TableName string
}

var _ LogTypesDatabase = (*DynamoDBLogTypes)(nil)

var L = lambdalogger.FromContext

const (
	// We will use this kind of record to store custom log types
	recordKindCustom = "custom"

	attrRecordKind = "RecordKind"
	attrDeleted    = "IsDeleted"
	attrRevision   = "revision"

	recordKindStatus      = "status"
	attrAvailableLogTypes = "AvailableLogTypes"
)

func (d *DynamoDBLogTypes) IndexLogTypes(ctx context.Context) ([]string, error) {
	input := dynamodb.GetItemInput{
		TableName:            aws.String(d.TableName),
		ProjectionExpression: aws.String(attrAvailableLogTypes),
		Key:                  statusRecordKey(),
	}

	output, err := d.DB.GetItemWithContext(ctx, &input)
	if err != nil {
		L(ctx).Error(`failed to get DynamoDB item`, zap.Error(err))
		return nil, err
	}

	item := struct {
		AvailableLogTypes []string
	}{}
	if err := dynamodbattribute.UnmarshalMap(output.Item, &item); err != nil {
		L(ctx).Error(`failed to unmarshal DynamoDB item`, zap.Error(err))
		return nil, err
	}

	return item.AvailableLogTypes, nil
}

func (d *DynamoDBLogTypes) GetCustomLog(ctx context.Context, id string, revision int64) (*CustomLogRecord, error) {
	input := dynamodb.GetItemInput{
		TableName: aws.String(d.TableName),
		Key:       customRecordKey(id, revision),
	}
	output, err := d.DB.GetItemWithContext(ctx, &input)
	if err != nil {
		return nil, err
	}
	L(ctx).Debug("custom log record",
		zap.String("logType", id),
		zap.Int64("revision", revision),
		zap.Any("item", output.Item))

	record := customLogRecord{}
	if err := dynamodbattribute.UnmarshalMap(output.Item, &record); err != nil {
		return nil, err
	}
	if record.Deleted || record.LogType == "" {
		return nil, nil
	}
	return &record.CustomLogRecord, nil
}

func (d *DynamoDBLogTypes) BatchGetCustomLogs(ctx context.Context, ids ...string) ([]*CustomLogRecord, error) {
	var records []*CustomLogRecord
	const maxItems = 25
	for _, ids := range chunkStrings(ids, maxItems) {
		keys := make([]map[string]*dynamodb.AttributeValue, len(ids))
		for i := range keys {
			keys[i] = customRecordKey(ids[i], 0)
		}
		input := dynamodb.BatchGetItemInput{
			RequestItems: map[string]*dynamodb.KeysAndAttributes{
				d.TableName: {
					Keys: keys,
				},
			},
		}
		output, err := d.DB.BatchGetItemWithContext(ctx, &input)
		if err != nil {
			return nil, err
		}
		items := output.Responses[d.TableName]
		for _, item := range items {
			record := customLogRecord{}
			if err := dynamodbattribute.UnmarshalMap(item, &record); err != nil {
				return nil, err
			}
			if record.Deleted || record.LogType == "" {
				continue
			}
			records = append(records, &record.CustomLogRecord)
		}
	}
	return records, nil
}

func (d *DynamoDBLogTypes) DeleteCustomLog(ctx context.Context, id string, revision int64) error {
	tx, err := buildDeleteRecordTx(d.TableName, id, revision)
	if err != nil {
		return WrapAPIError(errors.Wrap(err, "cannot prepare delete transaction"))
	}

	if _, err := d.DB.TransactWriteItemsWithContext(ctx, tx); err != nil {
		if txErr, ok := err.(*dynamodb.TransactionCanceledException); ok {
			switch reason := txErr.CancellationReasons[0]; cancellationReasonCode(reason) {
			case dynamodb.ErrCodeConditionalCheckFailedException:
				rec := customLogRecord{}
				if e := dynamodbattribute.UnmarshalMap(reason.Item, &rec); err != nil {
					return multierr.Append(err, e)
				}
				if rec.Deleted {
					return NewAPIError(ErrNotFound, fmt.Sprintf("record %q already deleted", rec.RecordID))
				}
				return NewAPIError(ErrRevisionConflict, fmt.Sprintf("record %q was updated", rec.RecordID))
			}
		}
		return WrapAPIError(err)
	}

	//for i := int64(1); i < revision; i++ {
	//	input := dynamodb.DeleteItemInput{
	//		TableName: aws.String(d.TableName),
	//		Key:       customRecordKey(id, i),
	//	}
	//	if _, err := d.DB.DeleteItemWithContext(ctx, &input); err != nil {
	//		return err
	//	}
	//}
	return nil
}
func buildDeleteRecordTx(tbl, id string, rev int64) (*dynamodb.TransactWriteItemsInput, error) {
	key, err := dynamodbattribute.MarshalMap(&recordKey{
		RecordID:   customRecordID(id, 0),
		RecordKind: recordKindCustom,
	})
	if err != nil {
		return nil, err
	}
	cond := expression.Name(attrRevision).Equal(expression.Value(rev))
	cond = cond.And(expression.Name(attrDeleted).NotEqual(expression.Value(true)))
	upd := expression.Set(expression.Name(attrDeleted), expression.Value(true))
	expr, err := expression.NewBuilder().WithUpdate(upd).WithCondition(cond).Build()
	if err != nil {
		return nil, err
	}
	delAvailable, err := expression.NewBuilder().WithUpdate(
		expression.Delete(expression.Name(attrAvailableLogTypes), expression.Value(&dynamodb.AttributeValue{
			SS: aws.StringSlice([]string{id}),
		})),
	).Build()
	if err != nil {
		return nil, err
	}
	return &dynamodb.TransactWriteItemsInput{
		TransactItems: []*dynamodb.TransactWriteItem{
			{
				Update: &dynamodb.Update{
					TableName:                           aws.String(tbl),
					Key:                                 key,
					ConditionExpression:                 expr.Condition(),
					UpdateExpression:                    expr.Update(),
					ExpressionAttributeValues:           expr.Values(),
					ExpressionAttributeNames:            expr.Names(),
					ReturnValuesOnConditionCheckFailure: aws.String(dynamodb.ReturnValueAllOld),
				},
			},
			{
				Update: &dynamodb.Update{
					TableName:                 aws.String(tbl),
					Key:                       statusRecordKey(),
					UpdateExpression:          delAvailable.Update(),
					ExpressionAttributeNames:  delAvailable.Names(),
					ExpressionAttributeValues: delAvailable.Values(),
				},
			},
		},
	}, nil
}

func (d *DynamoDBLogTypes) CreateCustomLog(ctx context.Context, id string, params *CustomLog) (*CustomLogRecord, error) {
	now := time.Now().UTC()
	result := CustomLogRecord{
		LogType:   id,
		Revision:  1,
		CustomLog: *params,
		UpdatedAt: now,
	}
	tx, err := buildCreateRecordTx(d.TableName, id, *params)
	if err != nil {
		return nil, WrapAPIError(errors.Wrap(err, "cannot prepare create transaction"))
	}

	if _, err := d.DB.TransactWriteItemsWithContext(ctx, tx); err != nil {
		if txErr, ok := err.(*dynamodb.TransactionCanceledException); ok {
			switch reason := txErr.CancellationReasons[0]; cancellationReasonCode(reason) {
			case dynamodb.ErrCodeConditionalCheckFailedException:
				return nil, NewAPIError(ErrAlreadyExists, fmt.Sprintf("record %q already exists", id))
			}
			switch reason := txErr.CancellationReasons[1]; cancellationReasonCode(reason) {
			case dynamodb.ErrCodeConditionalCheckFailedException:
				return nil, NewAPIError(ErrAlreadyExists, fmt.Sprintf("record %q already exists", id))
			}
		}
		return nil, WrapAPIError(errors.Wrap(err, "transaction failed"))
	}

	return &result, nil
}

func buildCreateRecordTx(tbl, id string, params CustomLog) (*dynamodb.TransactWriteItemsInput, error) {
	head, err := dynamodbattribute.MarshalMap(&customLogRecord{
		recordKey: recordKey{
			RecordID:   customRecordID(id, 0),
			RecordKind: recordKindCustom,
		},
		CustomLogRecord: CustomLogRecord{
			LogType:   id,
			Revision:  1,
			UpdatedAt: time.Now(),
			CustomLog: params,
		},
	})
	if err != nil {
		return nil, err
	}
	item, err := dynamodbattribute.MarshalMap(&customLogRecord{
		recordKey: recordKey{
			RecordID:   customRecordID(id, 1),
			RecordKind: recordKindCustom,
		},
		CustomLogRecord: CustomLogRecord{
			LogType:   id,
			Revision:  1,
			UpdatedAt: time.Now(),
			CustomLog: params,
		},
	})
	if err != nil {
		return nil, err
	}
	ifNotExists, err := expression.NewBuilder().WithCondition(
		expression.AttributeNotExists(expression.Name(attrRecordKind)),
	).Build()
	if err != nil {
		return nil, err
	}
	pushAvailable, err := expression.NewBuilder().WithUpdate(
		expression.Add(expression.Name(attrAvailableLogTypes), expression.Value(&dynamodb.AttributeValue{
			SS: aws.StringSlice([]string{id}),
		})),
	).Build()

	if err != nil {
		return nil, err
	}

	return &dynamodb.TransactWriteItemsInput{
		TransactItems: []*dynamodb.TransactWriteItem{
			{
				Put: &dynamodb.Put{
					TableName:                           aws.String(tbl),
					ConditionExpression:                 ifNotExists.Condition(),
					ExpressionAttributeNames:            ifNotExists.Names(),
					ExpressionAttributeValues:           ifNotExists.Values(),
					Item:                                head,
					ReturnValuesOnConditionCheckFailure: aws.String(dynamodb.ReturnValueAllOld),
				},
			},
			{
				Put: &dynamodb.Put{
					TableName:                           aws.String(tbl),
					ConditionExpression:                 ifNotExists.Condition(),
					ExpressionAttributeNames:            ifNotExists.Names(),
					ExpressionAttributeValues:           ifNotExists.Values(),
					Item:                                item,
					ReturnValuesOnConditionCheckFailure: aws.String(dynamodb.ReturnValueAllOld),
				},
			},
			{
				Update: &dynamodb.Update{
					TableName:                 aws.String(tbl),
					UpdateExpression:          pushAvailable.Update(),
					ExpressionAttributeValues: pushAvailable.Values(),
					ExpressionAttributeNames:  pushAvailable.Names(),
					Key:                       statusRecordKey(),
				},
			},
		},
	}, nil
}

func (d *DynamoDBLogTypes) UpdateCustomLog(ctx context.Context, id string, revision int64, params *CustomLog) (*CustomLogRecord, error) {
	now := time.Now().UTC()
	record := CustomLogRecord{
		CustomLog: *params,
		LogType:   id,
		Revision:  revision + 1,
		UpdatedAt: now,
	}
	tx, err := buildUpdateTx(d.TableName, id, revision, record)
	if err != nil {
		return nil, NewAPIError(dynamodb.ErrCodeInternalServerError, fmt.Sprintf("failed to prepare update transaction: %s", err))
	}
	if err := tx.Validate(); err != nil {
		return nil, NewAPIError(dynamodb.ErrCodeInternalServerError, fmt.Sprintf("prepared transaction is not valid: %s", err))
	}

	if _, err := d.DB.TransactWriteItemsWithContext(ctx, tx); err != nil {
		if txErr, ok := err.(*dynamodb.TransactionCanceledException); ok {
			switch reason := txErr.CancellationReasons[0]; cancellationReasonCode(reason) {
			case dynamodb.ErrCodeConditionalCheckFailedException:
				rec := customLogRecord{}
				if e := dynamodbattribute.UnmarshalMap(reason.Item, &rec); e != nil {
					return nil, multierr.Append(err, e)
				}
				if rec.Revision != revision {
					return nil, NewAPIError(ErrRevisionConflict, fmt.Sprintf("log record %q is at revision %d", rec.RecordID, rec.Revision))
				}
				if rec.Deleted {
					return nil, NewAPIError(ErrNotFound, fmt.Sprintf("log record %q was deleted", rec.RecordID))
				}
			}
			switch reason := txErr.CancellationReasons[1]; cancellationReasonCode(reason) {
			case dynamodb.ErrCodeConditionalCheckFailedException:
				return nil, NewAPIError(ErrRevisionConflict, fmt.Sprintf("log record %s@%d already exists", id, revision))
			}
		}
		return nil, WrapAPIError(err)
	}

	return &record, nil
}

func buildUpdateTx(tbl, id string, rev int64, record CustomLogRecord) (*dynamodb.TransactWriteItemsInput, error) {
	updValues, err := dynamodbattribute.MarshalMap(&record.CustomLog)
	if err != nil {
		return nil, err
	}
	upd := expression.Set(expression.Name(attrRevision), expression.Value(record.Revision))
	for name, value := range updValues {
		upd = upd.Set(expression.Name(name), expression.Value(value))
	}
	cond := expression.Name(attrRevision).Equal(expression.Value(rev))
	cond = cond.And(expression.Name(attrDeleted).NotEqual(expression.Value(true)))
	expr, err := expression.NewBuilder().WithUpdate(upd).WithCondition(cond).Build()
	if err != nil {
		return nil, err
	}
	item, err := dynamodbattribute.MarshalMap(&customLogRecord{
		recordKey: recordKey{
			RecordID:   customRecordID(id, record.Revision),
			RecordKind: recordKindCustom,
		},
		CustomLogRecord: record,
	})
	if err != nil {
		return nil, err
	}
	ifNotExists, err := expression.NewBuilder().WithCondition(
		expression.AttributeNotExists(expression.Name(attrRecordKind)),
	).Build()
	if err != nil {
		return nil, err
	}
	key, err := dynamodbattribute.MarshalMap(recordKey{
		RecordID:   customRecordID(id, 0),
		RecordKind: recordKindCustom,
	})
	if err != nil {
		return nil, err
	}
	return &dynamodb.TransactWriteItemsInput{
		TransactItems: []*dynamodb.TransactWriteItem{
			{
				Update: &dynamodb.Update{
					TableName:                           aws.String(tbl),
					ConditionExpression:                 expr.Condition(),
					UpdateExpression:                    expr.Update(),
					ExpressionAttributeValues:           expr.Values(),
					ExpressionAttributeNames:            expr.Names(),
					Key:                                 key,
					ReturnValuesOnConditionCheckFailure: aws.String(dynamodb.ReturnValueAllOld),
				},
			},
			{
				Put: &dynamodb.Put{
					TableName:                 aws.String(tbl),
					Item:                      item,
					ConditionExpression:       ifNotExists.Condition(),
					ExpressionAttributeNames:  ifNotExists.Names(),
					ExpressionAttributeValues: ifNotExists.Values(),
				},
			},
		},
	}, nil
}

func mustMarshalMap(val interface{}) map[string]*dynamodb.AttributeValue {
	attr, err := dynamodbattribute.MarshalMap(val)
	if err != nil {
		panic(err)
	}
	return attr
}

type recordKey struct {
	RecordID   string `json:"RecordID" validate:"required"`
	RecordKind string `json:"RecordKind" validate:"required,oneof=native custom"`
}

func statusRecordKey() map[string]*dynamodb.AttributeValue {
	return mustMarshalMap(&recordKey{
		RecordID:   "Status",
		RecordKind: recordKindStatus,
	})
}
func customRecordKey(id string, rev int64) map[string]*dynamodb.AttributeValue {
	return mustMarshalMap(&recordKey{
		RecordID:   customRecordID(id, rev),
		RecordKind: recordKindCustom,
	})
}

func customRecordID(id string, rev int64) string {
	id = customlogs.LogType(id)
	if rev > 0 {
		id = fmt.Sprintf(`%s-%d`, id, rev)
	}
	return strings.ToUpper(id)
}

type customLogRecord struct {
	recordKey
	Deleted bool `json:"IsDeleted,omitempty"  description:"Log record is deleted"`
	CustomLogRecord
}

func chunkStrings(values []string, maxSize int) (chunks [][]string) {
	if len(values) == 0 {
		return
	}
	for {
		if len(values) <= maxSize {
			return append(chunks, values)
		}
		chunks, values = append(chunks, values[:maxSize]), values[maxSize:]
	}
}

// fixes exception codes to match const values in dynamodb package
func cancellationReasonCode(reason *dynamodb.CancellationReason) string {
	if reason == nil {
		return ""
	}
	switch code := aws.StringValue(reason.Code); code {
	case dynamodb.ErrCodeConditionalCheckFailedException:
		return code
	case strings.TrimSuffix(dynamodb.ErrCodeConditionalCheckFailedException, "Exception"):
		return dynamodb.ErrCodeConditionalCheckFailedException
	default:
		return code
	}
}
