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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/customlogs"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/stringset"
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
	attrLogType    = "logType"

	recordKindStatus      = "status"
	attrAvailableLogTypes = "AvailableLogTypes"
)

func (d *DynamoDBLogTypes) IndexLogTypes(ctx context.Context) ([]string, error) {
	input := dynamodb.GetItemInput{
		TableName:            aws.String(d.TableName),
		ProjectionExpression: aws.String(attrAvailableLogTypes),
		Key:                  mustMarshalMap(statusRecordKey()),
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
		Key:       mustMarshalMap(customRecordKey(id, revision)),
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
			keys[i] = mustMarshalMap(customRecordKey(ids[i], 0))
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
	tx := buildDeleteRecordTx(d.TableName, id, revision)
	input, err := tx.Build()
	if err != nil {
		return errors.WithMessage(err, "failed to build delete transaction")
	}

	if _, err := d.DB.TransactWriteItemsWithContext(ctx, input); err != nil {
		return errors.Wrap(tx.ExplainTransactionError(err), "delete transaction failed")
	}
	return nil
}

func buildDeleteRecordTx(tbl, id string, rev int64) transact.Transaction {
	headRecordID := customRecordID(id, 0)
	key := &recordKey{
		RecordID:   headRecordID,
		RecordKind: recordKindCustom,
	}
	ifRevEquals := expression.Name(attrRevision).Equal(expression.Value(rev))
	ifNotDeleted := expression.Name(attrDeleted).NotEqual(expression.Value(true))
	cancel := func(r *dynamodb.CancellationReason) error {
		if transact.IsConditionalCheckFailed(r) {
			rec := customLogRecord{}
			if e := dynamodbattribute.UnmarshalMap(r.Item, &rec); e != nil {
				return e
			}
			if rec.Deleted {
				return NewAPIError(ErrNotFound, fmt.Sprintf("record %q already deleted", headRecordID))
			}
			return NewAPIError(ErrRevisionConflict, fmt.Sprintf("record %q was updated", headRecordID))
		}
		return nil
	}
	return transact.Transaction{
		// Mark the head record as deleted
		&transact.Update{
			TableName: tbl,
			Key:       key,
			Set: map[string]interface{}{
				attrDeleted: true,
			},
			Condition:                           expression.And(ifRevEquals, ifNotDeleted),
			ReturnValuesOnConditionCheckFailure: dynamodb.ReturnValueAllOld,
			Cancel:                              cancel,
		},
		// Remove the log type from the index of available log types
		&transact.Update{
			TableName: tbl,
			Key:       statusRecordKey(),
			Delete: map[string]interface{}{
				attrAvailableLogTypes: newStringSet(id),
			},
		},
	}
}

func (d *DynamoDBLogTypes) CreateCustomLog(ctx context.Context, id string, params *CustomLog) (*CustomLogRecord, error) {
	now := time.Now().UTC()
	result := CustomLogRecord{
		LogType:   id,
		Revision:  1,
		CustomLog: *params,
		UpdatedAt: now,
	}
	tx := buildCreateRecordTx(d.TableName, result)
	input, err := tx.Build()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to prepare create transaction")
	}
	if _, err := d.DB.TransactWriteItemsWithContext(ctx, input); err != nil {
		return nil, errors.Wrap(tx.ExplainTransactionError(err), "create transaction failed")
	}
	return &result, nil
}

func buildCreateRecordTx(tbl string, record CustomLogRecord) transact.Transaction {
	return transact.Transaction{
		// Insert the 'head' record that tracks the latest revision
		&transact.Put{
			TableName: tbl,
			Item: &customLogRecord{
				recordKey:       customRecordKey(record.LogType, 0),
				CustomLogRecord: record,
			},
			// Check that there's no record with this id
			Condition: expression.AttributeNotExists(expression.Name(attrRecordKind)),
			// To check the exact reason of failure we need the values in the record
			ReturnValues: true,
			// If the condition fails, it means that either
			// - the record already exists
			// - or that it used to exist but was deleted (we do not allow reusing names)
			Cancel: func(r *dynamodb.CancellationReason) error {
				if transact.IsConditionalCheckFailed(r) {
					rec := customLogRecord{}
					if e := dynamodbattribute.UnmarshalMap(r.Item, &rec); e != nil {
						return e
					}
					if rec.Deleted {
						return NewAPIError(ErrAlreadyExists, fmt.Sprintf("log record %q used to exist and it is reserved", rec.RecordID))
					}
					if rec.Revision != 0 {
						return NewAPIError(ErrAlreadyExists, fmt.Sprintf("record %q already exists", rec.RecordID))
					}
				}
				return nil
			},
		},
		// Insert a new record for the first revision
		&transact.Put{
			TableName: tbl,
			Item: &customLogRecord{
				recordKey:       customRecordKey(record.LogType, 1),
				CustomLogRecord: record,
			},
		},
		// Add the id to available log types index
		&transact.Update{
			TableName: tbl,
			Add: map[string]interface{}{
				attrAvailableLogTypes: newStringSet(record.LogType),
			},
			Key: statusRecordKey(),
		},
	}
}

func (d *DynamoDBLogTypes) UpdateCustomLog(ctx context.Context, id string, revision int64, params *CustomLog) (*CustomLogRecord, error) {
	now := time.Now().UTC()
	record := CustomLogRecord{
		CustomLog: *params,
		LogType:   id,
		Revision:  revision + 1,
		UpdatedAt: now,
	}
	tx := buildUpdateTx(d.TableName, record)
	input, err := tx.Build()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to build update transaction")
	}
	if _, err := d.DB.TransactWriteItemsWithContext(ctx, input); err != nil {
		return nil, errors.Wrap(tx.ExplainTransactionError(err), "update transaction failed")
	}
	return &record, nil
}

func buildUpdateTx(tableName string, record CustomLogRecord) transact.Transaction {
	currentRevision := record.Revision - 1
	return transact.Transaction{
		// Update the 'head' (rev 0) record
		&transact.Update{
			TableName: tableName,
			Key:       customRecordKey(record.LogType, 0),
			Set: map[string]interface{}{
				// Set the revision to the new one
				attrRevision: record.Revision,
				// Set the user-modifiable properties of the record
				// NOTE: SetAll will set all fields of the value
				transact.SetAll: &record.CustomLog,
			},
			Condition: expression.And(
				// Check that the current revision is the previous one
				expression.Name(attrRevision).Equal(expression.Value(currentRevision)),
				// Check that the record is not deleted
				expression.Name(attrDeleted).NotEqual(expression.Value(true)),
			),
			// Possible failures of the condition are
			// - The record was already updated by someone else
			// - The record was deleted by someone else
			// To distinguish between the two we need to get the record values and check its revision and deleted attrs
			ReturnValuesOnConditionCheckFailure: dynamodb.ReturnValueAllOld,
			// We convert these failures to APIErrors here
			Cancel: func(r *dynamodb.CancellationReason) error {
				if transact.IsConditionalCheckFailed(r) {
					rec := customLogRecord{}
					if e := dynamodbattribute.UnmarshalMap(r.Item, &rec); e != nil {
						return e
					}
					if rec.Revision != currentRevision {
						return NewAPIError(ErrRevisionConflict, fmt.Sprintf("log record %q is at revision %d", rec.RecordID, rec.Revision))
					}
					if rec.Deleted {
						return NewAPIError(ErrNotFound, fmt.Sprintf("log record %q was deleted", rec.RecordID))
					}
				}
				return nil
			},
		},
		// Insert a new record for this revision
		&transact.Put{
			TableName: tableName,
			Item: &customLogRecord{
				recordKey:       customRecordKey(record.LogType, record.Revision),
				CustomLogRecord: record,
			},
		},
	}
}

type recordKey struct {
	RecordID   string `json:"RecordID" validate:"required"`
	RecordKind string `json:"RecordKind" validate:"required,oneof=native custom"`
}

func statusRecordKey() recordKey {
	return recordKey{
		RecordID:   "Status",
		RecordKind: recordKindStatus,
	}
}
func mustMarshalMap(val interface{}) map[string]*dynamodb.AttributeValue {
	attr, err := dynamodbattribute.MarshalMap(val)
	if err != nil {
		panic(err)
	}
	return attr
}
func customRecordKey(id string, rev int64) recordKey {
	return recordKey{
		RecordID:   customRecordID(id, rev),
		RecordKind: recordKindCustom,
	}
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

// newStringSet is inlined and helps create a dynamodb.AttributeValue of type StringSet
func newStringSet(strings ...string) *dynamodb.AttributeValue {
	return &dynamodb.AttributeValue{
		SS: aws.StringSlice(strings),
	}
}

func (d *DynamoDBLogTypes) ListDeletedLogTypes(ctx context.Context) ([]string, error) {
	// Filter deleted
	cond := expression.Name(attrDeleted).Equal(expression.Value(true))
	cond = cond.And(expression.Name(attrRecordKind).Equal(expression.Value(recordKindCustom)))
	// Only fetch 'logType' attr
	proj := expression.NamesList(expression.Name(attrLogType))
	expr, err := expression.NewBuilder().WithFilter(cond).WithProjection(proj).Build()
	if err != nil {
		return nil, errors.Wrap(err, "failed to build DynamoDB expression for listing deleted log types")
	}
	input := dynamodb.ScanInput{
		TableName:                 aws.String(d.TableName),
		ProjectionExpression:      expr.Projection(),
		FilterExpression:          expr.Filter(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}
	var out []string
	var itemErr error
	scan := func(p *dynamodb.ScanOutput, _ bool) bool {
		for _, item := range p.Items {
			row := struct {
				LogType string `json:"logType"`
			}{}
			if err := dynamodbattribute.UnmarshalMap(item, &row); err != nil {
				itemErr = errors.Wrap(err, "failed to unmarshal DynamoDB item while scanning for deleted log types")
				return false
			}
			out = stringset.Append(out, row.LogType)
		}
		return true
	}
	if err := d.DB.ScanPagesWithContext(ctx, &input, scan); err != nil {
		return nil, errors.Wrap(err, "failed to scan DynamoDB for deleted log types")
	}
	if itemErr != nil {
		return nil, itemErr
	}
	return out, nil
}
