// Package ddbextras provides a builder for DynamoDB transactions.
package transact

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
	"errors"
	"reflect"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
)

// Transaction describes a write transaction and builds a dynamodb.TransactWriteItemsInput.
// It also allows to bind transaction cancellation reasons to errors for each dynamodb.TransactWriteItem.
// For more info on how the write transactions work see
// https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
type Transaction []ItemBuilder

type ItemBuilder interface {
	BuildItem() (*dynamodb.TransactWriteItem, error)
	cancelled(r *dynamodb.CancellationReason) error
	buildExpression() (expression.Expression, error)
}

func BuildExpression(item ItemBuilder) (expression.Expression, error) {
	return item.buildExpression()
}

// ExplainTransactionError maps transaction cancelled errors to the error handlers specified in the batch items.
func (tx Transaction) ExplainTransactionError(err error) error {
	var txErr *dynamodb.TransactionCanceledException
	if errors.As(err, &txErr) {
		reasons := txErr.CancellationReasons
		for i, item := range tx {
			if err := item.cancelled(reasons[i]); err != nil {
				return err
			}
		}
	}
	return err
}

// Build builds a dynamodb.TransactWriteItemsInput from a batch
func (tx Transaction) Build() (*dynamodb.TransactWriteItemsInput, error) {
	input := dynamodb.TransactWriteItemsInput{
		TransactItems: make([]*dynamodb.TransactWriteItem, len(tx)),
	}
	for i, builder := range tx {
		item, err := builder.BuildItem()
		if err != nil {
			return nil, err
		}
		input.TransactItems[i] = item
	}
	return &input, input.Validate()
}

// Cannot use dynamodb.ErrCodeConditionalCheckFailedException, the code in the cancellation reason has no 'Exception' suffix
const ErrCodeConditionalCheckFailed = "ConditionalCheckFailed"

func IsConditionalCheckFailed(r *dynamodb.CancellationReason) bool {
	return IsCancelReason(r, ErrCodeConditionalCheckFailed)
}

func IsCancelReason(r *dynamodb.CancellationReason, code string) bool {
	if r == nil {
		return false
	}

	switch c := aws.StringValue(r.Code); c {
	case code:
		return true
	case strings.TrimSuffix(code, "Exception"):
		return true
	default:
		return false
	}
}

// Put creates or replaces a key value
type Put struct {
	// TableName is the DynamoDB table name
	TableName string
	// Item to put in the table (gets marshalled to map[string]*dynamodb.AttributeValue)
	Item interface{}
	// Condition to check before the item is put
	Condition expression.ConditionBuilder
	// ReturnValues values if the condition fails
	ReturnValues bool
	// Cancel maps a cancellation reason to an error
	Cancel func(r *dynamodb.CancellationReason) error
}

var _ ItemBuilder = (*Put)(nil)

func (p *Put) BuildItem() (*dynamodb.TransactWriteItem, error) {
	item, err := dynamodbattribute.MarshalMap(p.Item)
	if err != nil {
		return nil, err
	}
	expr, err := p.buildExpression()
	if err != nil {
		return nil, err
	}
	put := dynamodb.Put{
		TableName:                           aws.String(p.TableName),
		Item:                                item,
		ConditionExpression:                 expr.Condition(),
		ExpressionAttributeNames:            expr.Names(),
		ExpressionAttributeValues:           expr.Values(),
		ReturnValuesOnConditionCheckFailure: returnValuesOnConditionCheckFailure(p.ReturnValues),
	}
	return &dynamodb.TransactWriteItem{
		Put: &put,
	}, nil
}
func (p *Put) buildExpression() (expression.Expression, error) {
	return buildConditionExpression(p.Condition)
}

func returnValuesOnConditionCheckFailure(ok bool) *string {
	if ok {
		return aws.String(dynamodb.ReturnValueAllOld)
	}
	return nil
}
func HasCondition(cond expression.ConditionBuilder) bool {
	return !reflect.DeepEqual(cond, expression.ConditionBuilder{})
}

func (p *Put) cancelled(r *dynamodb.CancellationReason) error {
	if p.Cancel != nil {
		return p.Cancel(r)
	}
	return nil
}

// Update updates attributes of an item.
type Update struct {
	// TableName is the DynamoDB table name
	TableName string
	// Key to update (gets marshalled to map[string]*dynamodb.AttributeValue)
	Key interface{}
	// Set attributes to values
	Set map[string]interface{}
	// Add values to attributes
	Add map[string]interface{}
	// Delete values from attributes
	Delete map[string]interface{}
	// Remove attribute names
	Remove []string
	// Condition check if the update should happen
	Condition expression.ConditionBuilder
	// ReturnValuesOnConditionCheckFailure controls how to get the item attributes if the
	// Update condition fails. For ReturnValuesOnConditionCheckFailure, the valid
	// values are: NONE, ALL_OLD, UPDATED_OLD, ALL_NEW, UPDATED_NEW.
	ReturnValuesOnConditionCheckFailure string
	// Cancel maps a cancellation reason to an error
	Cancel func(r *dynamodb.CancellationReason) error
}

var _ ItemBuilder = (*Update)(nil)

// SetAll is a special attribute name that will set all attributes of a struct/map value.
const SetAll = "*"
const SetIfNotExists = "?"

func (u *Update) BuildItem() (*dynamodb.TransactWriteItem, error) {
	key, err := dynamodbattribute.MarshalMap(u.Key)
	if err != nil {
		return nil, err
	}
	expr, err := u.buildExpression()
	if err != nil {
		return nil, err
	}
	update := dynamodb.Update{
		TableName:                 aws.String(u.TableName),
		Key:                       key,
		ConditionExpression:       expr.Condition(),
		UpdateExpression:          expr.Update(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}
	if u.ReturnValuesOnConditionCheckFailure != "" {
		update.ReturnValuesOnConditionCheckFailure = aws.String(u.ReturnValuesOnConditionCheckFailure)
	}
	return &dynamodb.TransactWriteItem{
		Update: &update,
	}, nil
}

func (u Update) buildExpression() (expression.Expression, error) {
	upd := expression.UpdateBuilder{}
	if ifNot, ok := u.Set[SetIfNotExists]; ok {
		values, err := dynamodbattribute.MarshalMap(ifNot)
		if err != nil {
			return expression.Expression{}, err
		}
		for name, value := range values {
			upd = upd.Set(expression.Name(name), expression.Name(name).IfNotExists(expression.Value(value)))
		}
	}
	if all, ok := u.Set[SetAll]; ok {
		values, err := dynamodbattribute.MarshalMap(all)
		if err != nil {
			return expression.Expression{}, err
		}
		for name, value := range values {
			upd = upd.Set(expression.Name(name), expression.Value(value))
		}
	}
	for name, value := range u.Set {
		switch name {
		case SetAll, SetIfNotExists:
			continue
		}
		if op, ok := value.(expression.OperandBuilder); ok {
			upd = upd.Set(expression.Name(name), op)
			continue
		}
		upd = upd.Set(expression.Name(name), expression.Value(value))
	}
	for name, value := range u.Delete {
		upd = upd.Delete(expression.Name(name), expression.Value(value))
	}
	for _, name := range u.Remove {
		upd = upd.Remove(expression.Name(name))
	}
	for name, value := range u.Add {
		upd = upd.Add(expression.Name(name), expression.Value(value))
	}
	// update is mandatory to be non-empty
	expr := expression.NewBuilder().WithUpdate(upd)
	// check if condition is empty
	if !reflect.DeepEqual(u.Condition, expression.ConditionBuilder{}) {
		expr = expr.WithCondition(u.Condition)
	}
	return expr.Build()
}

func (u *Update) cancelled(r *dynamodb.CancellationReason) error {
	if u.Cancel != nil {
		return u.Cancel(r)
	}
	return nil
}

var _ ItemBuilder = (*Delete)(nil)

// Delete deletes a key
type Delete struct {
	// TableName is the DynamoDB table name
	TableName string
	// Key to delete
	Key interface{}
	// Condition to check before deleting
	Condition expression.ConditionBuilder
	// ReturnValues values if the condition fails
	ReturnValues bool
	// Cancel maps a cancellation reason to an error
	Cancel func(r *dynamodb.CancellationReason) error
}

func (d *Delete) BuildItem() (*dynamodb.TransactWriteItem, error) {
	expr, err := d.buildExpression()
	if err != nil {
		return nil, err
	}
	key, err := dynamodbattribute.MarshalMap(d.Key)
	if err != nil {
		return nil, err
	}
	del := dynamodb.Delete{
		TableName:                           aws.String(d.TableName),
		Key:                                 key,
		ConditionExpression:                 expr.Condition(),
		ExpressionAttributeNames:            expr.Names(),
		ExpressionAttributeValues:           expr.Values(),
		ReturnValuesOnConditionCheckFailure: returnValuesOnConditionCheckFailure(d.ReturnValues),
	}
	return &dynamodb.TransactWriteItem{
		Delete: &del,
	}, nil
}
func (d *Delete) buildExpression() (expression.Expression, error) {
	return buildConditionExpression(d.Condition)
}

func (d *Delete) cancelled(r *dynamodb.CancellationReason) error {
	if d.Cancel != nil {
		return d.Cancel(r)
	}
	return nil
}

var _ ItemBuilder = (*ConditionCheck)(nil)

// ConditionCheck checks a condition and aborts the transaction if it fails
type ConditionCheck struct {
	// TableName is the DynamoDB table name
	TableName string
	// Key to check the condition against (gets marshalled to map[string]*dynamodb.AttributeValue)
	Key interface{}
	// Condition to check
	Condition expression.ConditionBuilder
	// ReturnValues values if the condition fails
	ReturnValues bool
	// Cancel maps a cancellation reason to an error
	Cancel func(r *dynamodb.CancellationReason) error
}

func (c *ConditionCheck) BuildItem() (*dynamodb.TransactWriteItem, error) {
	expr, err := c.buildExpression()
	if err != nil {
		return nil, err
	}
	key, err := dynamodbattribute.MarshalMap(c.Key)
	if err != nil {
		return nil, err
	}
	cond := dynamodb.ConditionCheck{
		TableName:                           aws.String(c.TableName),
		Key:                                 key,
		ConditionExpression:                 expr.Condition(),
		ExpressionAttributeNames:            expr.Names(),
		ExpressionAttributeValues:           expr.Values(),
		ReturnValuesOnConditionCheckFailure: returnValuesOnConditionCheckFailure(c.ReturnValues),
	}
	return &dynamodb.TransactWriteItem{
		ConditionCheck: &cond,
	}, nil
}
func (c *ConditionCheck) buildExpression() (expression.Expression, error) {
	return expression.NewBuilder().WithCondition(c.Condition).Build()
}

func (c *ConditionCheck) cancelled(r *dynamodb.CancellationReason) error {
	if c.Cancel != nil {
		return c.Cancel(r)
	}
	return nil
}

func buildConditionExpression(cond expression.ConditionBuilder) (expression.Expression, error) {
	if !HasCondition(cond) {
		return expression.Expression{}, nil
	}
	return expression.NewBuilder().WithCondition(cond).Build()
}
