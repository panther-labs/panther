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

	attrRecordKind   = "RecordKind"
	attrDisabled     = "IsDeleted"
	attrRevision     = "revision"
	attrDescription  = "description"
	attrReferenceURL = "referenceURL"
	attrSpec         = "logSpec"
	attrManaged      = "managed"

	recordKindStatus      = "status"
	attrAvailableLogTypes = "AvailableLogTypes"
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
			record := SchemaRecord{}
			if itemErr = dynamodbattribute.UnmarshalMap(item, &record); itemErr != nil {
				return false
			}
			if !scan(&record) {
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

func (d *DynamoDBSchemas) GetSchema(ctx context.Context, id string, revision int64) (*SchemaRecord, error) {
	input := dynamodb.GetItemInput{
		TableName: aws.String(d.TableName),
		Key:       mustMarshalMap(schemaRecordKey(id, revision)),
	}
	output, err := d.DB.GetItemWithContext(ctx, &input)
	if err != nil {
		return nil, err
	}
	L(ctx).Debug("retrieved schema record",
		zap.String("logType", id),
		zap.Int64("revision", revision),
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
func (d *DynamoDBSchemas) UpdateManagedSchema(ctx context.Context, id string, rev int64, release string, upd SchemaUpdate) (*SchemaRecord, error) {
	now := time.Now().UTC()
	record := SchemaRecord{
		Name:         id,
		Revision:     rev,
		Managed:      true,
		Release:      release,
		UpdatedAt:    now,
		SchemaUpdate: upd,
	}
	tx := buildUpdateManagedSchemaTx(d.TableName, record)
	input, err := tx.Build()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to build update managed schema transaction")
	}
	if _, err := d.DB.TransactWriteItemsWithContext(ctx, input); err != nil {
		return nil, errors.Wrap(tx.ExplainTransactionError(err), "update managed schema transaction failed")
	}
	return &record, nil
}

func buildUpdateManagedSchemaTx(tableName string, record SchemaRecord) transact.Transaction {
	currentRevision := record.Revision - 1
	return transact.Transaction{
		&transact.Update{
			TableName: tableName,
			Key:       schemaRecordKey(record.Name, 0),
			Set: map[string]interface{}{
				// Set if the record is being put for the first time
				transact.SetIfNotExists: struct {
					CreatedAt time.Time `dynamodbav:"createdAt"`
					Name      string    `dynamodbav:"logType"`
					Managed   bool      `dynamodbav:"managed"`
					Disabled  bool      `dynamodbav:"IsDeleted"`
				}{
					CreatedAt: record.UpdatedAt,
					Name:      record.Name,
					Managed:   true,
					Disabled:  false,
				},
				// Update fields of the schema record
				transact.SetAll: struct {
					UpdatedAt    time.Time `dynamodbav:"updatedAt"`
					Release      string    `dynamodbav:"release"`
					Revision     int64     `dynamodbav:"revision"`
					Description  string    `dynamodbav:"description"`
					ReferenceURL string    `dynamodbav:"referenceURL"`
					Spec         string    `dynamodbav:"logSpec"`
				}{
					UpdatedAt:    record.UpdatedAt,
					Revision:     record.Revision,
					Release:      record.Release,
					Description:  record.Description,
					ReferenceURL: record.ReferenceURL,
					Spec:         record.Spec,
				},
			},
			Condition: expression.Or(
				// Check that the record does not exist
				expression.Name(attrRecordKind).AttributeNotExists(),
				// OR
				expression.And(
					// Check that the record is managed
					expression.Name(attrManaged).Equal(expression.Value(true)),
					// Check that the record has not incremented its revision
					expression.Name(attrRevision).Equal(expression.Value(currentRevision)),
				),
			),
			// Possible failures of the condition are
			// - The record is not managed
			// - The record is already at a newer release
			// To distinguish between the two we need to get the record values and check its revision and deleted attrs
			ReturnValuesOnConditionCheckFailure: dynamodb.ReturnValueAllOld,
			// We convert these failures to APIErrors here
			Cancel: func(r *dynamodb.CancellationReason) error {
				if transact.IsConditionalCheckFailed(r) {
					rec := ddbSchemaRecord{}
					if e := dynamodbattribute.UnmarshalMap(r.Item, &rec); e != nil {
						return e
					}
					if !rec.Managed {
						return NewAPIError(ErrAlreadyExists, fmt.Sprintf("schema record %q is not managed", rec.RecordID))
					}
					if rec.Revision != currentRevision {
						return NewAPIError(ErrRevisionConflict, fmt.Sprintf("managed schema record %q is at revision %d", rec.RecordID, rec.Revision))
					}
				}
				return nil
			},
		},
	}
}

func (d *DynamoDBSchemas) ToggleSchema(ctx context.Context, id string, enabled bool) error {
	tx := toggleSchemaTX(d.TableName, id, enabled)
	input, err := tx.Build()
	if err != nil {
		return errors.WithMessage(err, "failed to build delete transaction")
	}

	if _, err := d.DB.TransactWriteItemsWithContext(ctx, input); err != nil {
		return errors.Wrap(tx.ExplainTransactionError(err), "delete transaction failed")
	}
	return nil
}

func toggleSchemaTX(tbl, id string, enabled bool) transact.Transaction {
	headRecordID := schemaRecordID(id, 0)
	key := &recordKey{
		RecordID:   headRecordID,
		RecordKind: recordKindSchema,
	}
	tx := transact.Transaction{
		// Mark the head record as deleted
		&transact.Update{
			TableName: tbl,
			Key:       key,
			Set: map[string]interface{}{
				attrDisabled: !enabled,
			},
		},
	}
	attr := map[string]interface{}{
		attrAvailableLogTypes: newStringSet(id),
	}
	updIndex := &transact.Update{
		TableName: tbl,
		Key:       statusRecordKey(),
	}
	if enabled {
		updIndex.Add = attr
	} else {
		updIndex.Delete = attr
	}
	return append(tx, updIndex)
}

func (d *DynamoDBSchemas) CreateUserSchema(ctx context.Context, id string, upd SchemaUpdate) (*SchemaRecord, error) {
	now := time.Now().UTC()
	record := SchemaRecord{
		Name:         id,
		Revision:     1,
		Managed:      false,
		UpdatedAt:    now,
		CreatedAt:    now,
		Disabled:     false,
		SchemaUpdate: upd,
	}
	tx := createUserSchemaTX(d.TableName, record)
	input, err := tx.Build()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to prepare create transaction")
	}
	if _, err := d.DB.TransactWriteItemsWithContext(ctx, input); err != nil {
		return nil, errors.Wrap(tx.ExplainTransactionError(err), "create transaction failed")
	}
	return &record, nil
}

func createUserSchemaTX(tbl string, record SchemaRecord) transact.Transaction {
	return transact.Transaction{
		// Insert the 'head' record that tracks the latest revision
		&transact.Put{
			TableName: tbl,
			Item: &ddbSchemaRecord{
				recordKey:    schemaRecordKey(record.Name, 0),
				SchemaRecord: record,
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
					rec := ddbSchemaRecord{}
					if e := dynamodbattribute.UnmarshalMap(r.Item, &rec); e != nil {
						return e
					}
					if rec.Disabled {
						return NewAPIError(ErrAlreadyExists, fmt.Sprintf("schema record %q already exists but is disabled", rec.RecordID))
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
			Item: &ddbSchemaRecord{
				recordKey:    schemaRecordKey(record.Name, 1),
				SchemaRecord: record,
			},
		},
		// Add the id to available log types index
		&transact.Update{
			TableName: tbl,
			Add: map[string]interface{}{
				attrAvailableLogTypes: newStringSet(record.Name),
			},
			Key: statusRecordKey(),
		},
	}
}

func (d *DynamoDBSchemas) UpdateUserSchema(ctx context.Context, id string, rev int64, upd SchemaUpdate) (*SchemaRecord, error) {
	now := time.Now().UTC()
	record := SchemaRecord{
		Name:         id,
		Revision:     rev,
		UpdatedAt:    now,
		SchemaUpdate: upd,
	}
	tx := updateUserSchemaTX(d.TableName, record)
	input, err := tx.Build()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to build update transaction")
	}
	if _, err := d.DB.TransactWriteItemsWithContext(ctx, input); err != nil {
		return nil, errors.Wrap(tx.ExplainTransactionError(err), "update transaction failed")
	}
	return &record, nil
}

func updateUserSchemaTX(tableName string, record SchemaRecord) transact.Transaction {
	currentRevision := record.Revision - 1
	return transact.Transaction{
		// Update the 'head' (rev 0) record
		&transact.Update{
			TableName: tableName,
			Key:       schemaRecordID(record.Name, 0),
			Set: map[string]interface{}{
				attrRevision:     record.Revision,
				attrDescription:  record.Description,
				attrReferenceURL: record.ReferenceURL,
				attrSpec:         record.Spec,
			},
			Condition: expression.And(
				// Check that the current revision is the previous one
				expression.Name(attrRevision).Equal(expression.Value(currentRevision)),
				// Check that the record is not deleted
				expression.Name(attrDisabled).NotEqual(expression.Value(true)),
			),
			// Possible failures of the condition are
			// - The record was already updated by someone else
			// - The record was deleted by someone else
			// To distinguish between the two we need to get the record values and check its revision and deleted attrs
			ReturnValuesOnConditionCheckFailure: dynamodb.ReturnValueAllOld,
			// We convert these failures to APIErrors here
			Cancel: func(r *dynamodb.CancellationReason) error {
				if transact.IsConditionalCheckFailed(r) {
					rec := ddbSchemaRecord{}
					if e := dynamodbattribute.UnmarshalMap(r.Item, &rec); e != nil {
						return e
					}
					if rec.Revision != currentRevision {
						return NewAPIError(ErrRevisionConflict, fmt.Sprintf("user schema record %q is at revision %d", rec.RecordID, rec.Revision))
					}
					if rec.Disabled {
						return NewAPIError(ErrNotFound, fmt.Sprintf("user schema record %q is deleted", rec.RecordID))
					}
				}
				return nil
			},
		},
		// Insert a new record for this revision
		&transact.Put{
			TableName: tableName,
			Item: &ddbSchemaRecord{
				recordKey:    schemaRecordKey(record.Name, record.Revision),
				SchemaRecord: record,
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
func schemaRecordKey(id string, rev int64) recordKey {
	return recordKey{
		RecordID:   schemaRecordID(id, rev),
		RecordKind: recordKindSchema,
	}
}

func schemaRecordID(id string, rev int64) string {
	if rev > 0 {
		id = fmt.Sprintf(`%s-%d`, id, rev)
	}
	return strings.ToUpper(id)
}

type ddbSchemaRecord struct {
	recordKey
	SchemaRecord
}

// newStringSet is inlined and helps create a dynamodb.AttributeValue of type StringSet
func newStringSet(strings ...string) *dynamodb.AttributeValue {
	return &dynamodb.AttributeValue{
		SS: aws.StringSlice(strings),
	}
}
