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

	"github.com/panther-labs/panther/internal/core/logtypesapi/ddbextras"
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
		Key:                  ddbextras.MustMarshalMap(statusRecordKey()),
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
	tx := buildDeleteRecordTx(d.TableName, id, revision)
	input, err := tx.Input()
	if err != nil {
		return errors.WithMessage(err, "failed to build delete transaction")
	}

	if _, err := d.DB.TransactWriteItemsWithContext(ctx, input); err != nil {
		if err := tx.Check(err); err != nil {
			return err
		}
		return errors.Wrap(err, "delete transaction failed")
	}
	return nil
}

func buildDeleteRecordTx(tbl, id string, rev int64) *ddbextras.WriteTransaction {
	headRecordID := customRecordID(id, 0)
	key := &recordKey{
		RecordID:   headRecordID,
		RecordKind: recordKindCustom,
	}
	ifRevEquals := expression.Name(attrRevision).Equal(expression.Value(rev))
	ifNotDeleted := expression.Name(attrDeleted).NotEqual(expression.Value(true))
	cancel := func(r *dynamodb.CancellationReason) error {
		if ddbextras.IsConditionalCheckFailed(r) {
			rec := customLogRecord{}
			if e := dynamodbattribute.UnmarshalMap(r.Item, &rec); e != nil {
				return e
			}
			if rec.Deleted {
				return NewAPIError(ErrRevisionConflict, fmt.Sprintf("record %q was updated", headRecordID))
			}
			return NewAPIError(ErrNotFound, fmt.Sprintf("record %q already deleted", headRecordID))
		}
		return nil
	}
	return &ddbextras.WriteTransaction{
		// Mark the head record as deleted
		&ddbextras.Update{
			TableName: tbl,
			Key:       key,
			Set: map[string]interface{}{
				attrDeleted: true,
			},
			Condition:    expression.And(ifRevEquals, ifNotDeleted),
			ReturnValues: dynamodb.ReturnValueAllOld,
			Cancel:       cancel,
		},
		// Remove the log type from the index of available log types
		&ddbextras.Update{
			TableName: tbl,
			Key:       statusRecordKey(),
			Delete: map[string]interface{}{
				attrAvailableLogTypes: ddbextras.StringSet(id),
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
	input, err := tx.Input()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to prepare create transaction")
	}
	if _, err := d.DB.TransactWriteItemsWithContext(ctx, input); err != nil {
		if err := tx.Check(err); err != nil {
			return nil, err
		}
		return nil, errors.WithMessage(err, "create transaction failed")
	}
	return &result, nil
}

func buildCreateRecordTx(tbl string, record CustomLogRecord) *ddbextras.WriteTransaction {
	// Record id for the 'head' record is special (has no rev suffix)
	headRecordID := customRecordID(record.LogType, 0)
	headRecord := &customLogRecord{
		recordKey: recordKey{
			RecordID:   headRecordID,
			RecordKind: recordKindCustom,
		},
		CustomLogRecord: record,
	}
	revRecordID := customRecordID(record.LogType, 1)
	revRecord := &customLogRecord{
		recordKey: recordKey{
			RecordID:   revRecordID,
			RecordKind: recordKindCustom,
		},
		CustomLogRecord: record,
	}

	// Check that there's no record with this id
	ifNotExists := expression.AttributeNotExists(expression.Name(attrRecordKind))
	// The error conditions are the same for both PUT operations
	cancel := func(r *dynamodb.CancellationReason) error {
		if ddbextras.IsConditionalCheckFailed(r) {
			rec := customLogRecord{}
			if e := dynamodbattribute.UnmarshalMap(r.Item, &rec); e != nil {
				return e
			}
			if rec.Deleted {
				return NewAPIError(ErrAlreadyExists, fmt.Sprintf("log record %q used to exist and it is reserved", headRecordID))
			}
			return NewAPIError(ErrAlreadyExists, fmt.Sprintf("record %q already exists", headRecordID))
		}
		return nil
	}

	return &ddbextras.WriteTransaction{
		// Insert the 'head' record that tracks the latest revision
		&ddbextras.Put{
			TableName: tbl,
			Condition: ifNotExists,
			Item:      headRecord,
			// We return the values so that we can differentiate between deleted and existing records
			ReturnValues: dynamodb.ReturnValueAllOld,
			Cancel:       cancel,
		},
		// Insert a new record for the first revision
		&ddbextras.Put{
			TableName:    tbl,
			Item:         revRecord,
			ReturnValues: dynamodb.ReturnValueAllOld,
		},
		// Add the id to available log types index
		&ddbextras.Update{
			TableName: tbl,
			Add: map[string]interface{}{
				attrAvailableLogTypes: ddbextras.StringSet(record.LogType),
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
	input, err := tx.Input()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to build update transaction")
	}
	if _, err := d.DB.TransactWriteItemsWithContext(ctx, input); err != nil {
		if err := tx.Check(err); err != nil {
			return nil, err
		}
		// We don't know what kind of error this is
		return nil, err
	}
	return &record, nil
}

func buildUpdateTx(tbl string, record CustomLogRecord) *ddbextras.WriteTransaction {
	headRecordID := customRecordID(record.LogType, 0)
	headItemKey := &recordKey{
		RecordID:   headRecordID,
		RecordKind: recordKindCustom,
	}
	revRecordID := customRecordID(record.LogType, record.Revision)
	itemAtRevision := &customLogRecord{
		recordKey: recordKey{
			RecordID:   revRecordID,
			RecordKind: recordKindCustom,
		},
		CustomLogRecord: record,
	}
	currentRevision := record.Revision - 1
	// Check that the current revision is the previous one
	ifRevEquals := expression.Name(attrRevision).Equal(expression.Value(currentRevision))
	// Check that the record is not deleted
	ifNotDeleted := expression.Name(attrDeleted).NotEqual(expression.Value(true))

	// handle transaction errors here
	cancel := func(r *dynamodb.CancellationReason) error {
		if !ddbextras.IsConditionalCheckFailed(r) {
			return nil
		}
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
		return nil
	}
	return &ddbextras.WriteTransaction{
		// Update the 'head' (rev 0) record
		&ddbextras.Update{
			TableName: tbl,
			Set: map[string]interface{}{
				// Set the revision to the new one
				attrRevision: record.Revision,
				// Set the user-modifiable properties of the record
				// NOTE: SetAll will set all fields of the value
				ddbextras.SetAll: &record.CustomLog,
			},
			Condition:    expression.And(ifRevEquals, ifNotDeleted),
			Key:          headItemKey,
			ReturnValues: dynamodb.ReturnValueAllOld,
			Cancel:       cancel,
		},
		// Insert a new record for this revision
		&ddbextras.Put{
			TableName: tbl,
			Item:      itemAtRevision,
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
func customRecordKey(id string, rev int64) map[string]*dynamodb.AttributeValue {
	return ddbextras.MustMarshalMap(&recordKey{
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
