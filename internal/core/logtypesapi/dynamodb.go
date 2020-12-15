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
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
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
		output, err := d.DB.BatchGetItem(&input)
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
	input := dynamodb.TransactWriteItemsInput{
		TransactItems: []*dynamodb.TransactWriteItem{
			{
				Update: &dynamodb.Update{
					Key: mustMarshalMap(recordKey{
						RecordID:   customRecordID(id, 0),
						RecordKind: recordKindCustom,
					}),
					TableName:           aws.String(d.TableName),
					ConditionExpression: aws.String(fmt.Sprintf(`%s = :revision AND %s <> :isDeleted`, attrRevision, attrDeleted)),
					UpdateExpression:    aws.String(fmt.Sprintf("SET %s = :isDeleted", attrDeleted)),
					ExpressionAttributeValues: mustMarshalMap(map[string]interface{}{
						":revision":  revision,
						":isDeleted": true,
					}),
				},
			},
			{
				Update: removeAvailableLogType(d.TableName, id),
			},
		},
	}

	if _, err := d.DB.TransactWriteItemsWithContext(ctx, &input); err != nil {
		if txErr, ok := err.(*dynamodb.TransactionCanceledException); ok {
			for _, reason := range txErr.CancellationReasons {
				switch code := cancellationReasonCode(reason); code {
				case dynamodb.ErrCodeConditionalCheckFailedException:
					msg := fmt.Sprintf("record %q does not exist", customRecordID(id, 0))
					return NewAPIError(ErrNotFound, msg)
				}
			}
		}
		return mapError(err)
	}

	for i := int64(1); i < revision; i++ {
		input := dynamodb.DeleteItemInput{
			TableName: aws.String(d.TableName),
			Key:       customRecordKey(id, i),
		}
		if _, err := d.DB.DeleteItemWithContext(ctx, &input); err != nil {
			return err
		}
	}
	return nil
}

func (d *DynamoDBLogTypes) CreateCustomLog(ctx context.Context, id string, params *CustomLog) (*CustomLogRecord, error) {
	now := time.Now().UTC()
	result := CustomLogRecord{
		LogType:   id,
		Revision:  1,
		CustomLog: *params,
		UpdatedAt: now,
	}
	head, item, err := recordPair(id, 1, &result)
	if err != nil {
		return nil, err
	}
	input := dynamodb.TransactWriteItemsInput{
		TransactItems: []*dynamodb.TransactWriteItem{
			// We create the head record that tracks the latest revision
			{
				Put: &dynamodb.Put{
					TableName: aws.String(d.TableName),
					// We check the record does not exist
					ConditionExpression: aws.String(fmt.Sprintf(`attribute_not_exists(%s)`, attrRecordKind)),
					Item:                head,
				},
			},
			// We put also the record for revision 1
			{
				Put: &dynamodb.Put{
					TableName: aws.String(d.TableName),
					Item:      item,
				},
			},
			// We update the set of available log types
			{
				Update: addAvailableLogType(d.TableName, id),
			},
		},
	}

	if _, err := d.DB.TransactWriteItemsWithContext(ctx, &input); err != nil {
		if txErr, ok := err.(*dynamodb.TransactionCanceledException); ok {
			for _, reason := range txErr.CancellationReasons {
				switch code := cancellationReasonCode(reason); code {
				case dynamodb.ErrCodeConditionalCheckFailedException:
					msg := fmt.Sprintf("record %q already exists", customRecordID(id, 0))
					return nil, NewAPIError(ErrAlreadyExists, msg)
				}
			}
		}
		return nil, mapError(err)
	}

	return &result, nil
}

func mapError(err error) *APIError {
	type ddbError interface {
		Code() string
		Message() string
	}

	if e, ok := err.(ddbError); ok {
		switch e.Code() {
		case dynamodb.ErrCodeConditionalCheckFailedException:
			return NewAPIError(ErrRevisionConflict, "record revision mismatch")
		default:
			return NewAPIError(e.Code(), e.Message())
		}
	}
	return WrapAPIError(err)
}

func (d *DynamoDBLogTypes) UpdateCustomLog(ctx context.Context, id string, revision int64, params *CustomLog) (*CustomLogRecord, error) {
	now := time.Now().UTC()
	result := CustomLogRecord{
		CustomLog: *params,
		LogType:   id,
		Revision:  revision + 1,
		UpdatedAt: now,
	}
	head, item, err := recordPair(id, 1, &result)
	if err != nil {
		return nil, err
	}

	input := dynamodb.TransactWriteItemsInput{
		TransactItems: []*dynamodb.TransactWriteItem{
			// We update the head record with the latest revision
			{
				Put: &dynamodb.Put{
					TableName:           aws.String(d.TableName),
					ConditionExpression: aws.String(fmt.Sprintf(`%s = :revision`, attrRevision)),
					ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
						":revision": {
							N: aws.String(strconv.FormatInt(revision, 10)),
						},
					},
					Item: head,
				},
			},
			// We put also the revision record
			{
				Put: &dynamodb.Put{
					TableName: aws.String(d.TableName),
					Item:      item,
				},
			},
			// We update the set of available log types
			{
				Update: addAvailableLogType(d.TableName, id),
			},
		},
	}

	if _, err := d.DB.TransactWriteItemsWithContext(ctx, &input); err != nil {
		return nil, mapError(err)
	}

	return &result, nil
}

func recordPair(logType string, rev int64, result *CustomLogRecord) (head, item map[string]*dynamodb.AttributeValue, err error) {
	head, err = dynamodbattribute.MarshalMap(&customLogRecord{
		recordKey: recordKey{
			RecordID:   customRecordID(logType, 0),
			RecordKind: recordKindCustom,
		},
		CustomLogRecord: *result,
	})
	if err != nil {
		return nil, nil, err
	}
	item, err = dynamodbattribute.MarshalMap(&customLogRecord{
		recordKey: recordKey{
			RecordID:   customRecordID(logType, rev),
			RecordKind: recordKindCustom,
		},
		CustomLogRecord: *result,
	})
	if err != nil {
		return nil, nil, err
	}
	return head, item, nil
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

func removeAvailableLogType(tableName, id string) *dynamodb.Update {
	return &dynamodb.Update{
		TableName: aws.String(tableName),
		Key:       statusRecordKey(),
		UpdateExpression: aws.String(
			fmt.Sprintf("DELETE %s :logType", attrAvailableLogTypes),
		),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":logType": {
				SS: aws.StringSlice([]string{id}),
			},
		},
	}
}
func addAvailableLogType(tableName, id string) *dynamodb.Update {
	return &dynamodb.Update{
		TableName: aws.String(tableName),
		Key:       statusRecordKey(),
		UpdateExpression: aws.String(
			fmt.Sprintf("ADD %s :logType", attrAvailableLogTypes),
		),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":logType": {
				SS: aws.StringSlice([]string{id}),
			},
		},
	}
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
	code := aws.StringValue(reason.Code)
	if code == "" {
		return ""
	}
	if strings.HasSuffix(code, "Exception") {
		return code
	}
	return code + "Exception"
}
