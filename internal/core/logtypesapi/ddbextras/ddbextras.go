package ddbextras

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
	"reflect"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
)

type WriteTransaction []BatchWriteItem

func (b WriteTransaction) Check(err error) error {
	if txErr, ok := err.(*dynamodb.TransactionCanceledException); ok {
		reasons := txErr.CancellationReasons
		for i, item := range b {
			if err := item.Cancelled(reasons[i]); err != nil {
				return err
			}
		}
	}
	return err
}

func (b WriteTransaction) Input() (*dynamodb.TransactWriteItemsInput, error) {
	input := dynamodb.TransactWriteItemsInput{
		TransactItems: make([]*dynamodb.TransactWriteItem, len(b)),
	}
	for i, builder := range b {
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

type ItemBuilder interface {
	BuildItem() (*dynamodb.TransactWriteItem, error)
}

type BatchWriteItem interface {
	ItemBuilder
	Cancelled(r *dynamodb.CancellationReason) error
}

type Put struct {
	TableName    string
	Item         interface{}
	Condition    expression.ConditionBuilder
	ReturnValues string
	Cancel       func(r *dynamodb.CancellationReason) error
}

func (p *Put) BuildItem() (*dynamodb.TransactWriteItem, error) {
	item, err := dynamodbattribute.MarshalMap(p.Item)
	if err != nil {
		return nil, err
	}
	expr, err := BuildConditionExpression(p.Condition)
	if err != nil {
		return nil, err
	}
	put := dynamodb.Put{
		TableName:                 aws.String(p.TableName),
		Item:                      item,
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}
	if p.ReturnValues != "" {
		put.ReturnValuesOnConditionCheckFailure = aws.String(p.ReturnValues)
	}
	return &dynamodb.TransactWriteItem{
		Put: &put,
	}, nil
}

func HasCondition(cond expression.ConditionBuilder) bool {
	return !reflect.DeepEqual(cond, expression.ConditionBuilder{})
}

func (p *Put) Cancelled(r *dynamodb.CancellationReason) error {
	if p.Cancel != nil {
		return p.Cancel(r)
	}
	return nil
}

type Update struct {
	TableName    string
	Key          interface{}
	Set          map[string]interface{}
	Add          map[string]interface{}
	Delete       map[string]interface{}
	Remove       []string
	Condition    expression.ConditionBuilder
	ReturnValues string
	Cancel       func(r *dynamodb.CancellationReason) error
}

const SetAll = "*"

func (u *Update) BuildItem() (*dynamodb.TransactWriteItem, error) {
	key, err := dynamodbattribute.MarshalMap(u.Key)
	if err != nil {
		return nil, err
	}
	expr, err := u.BuildExpression()
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
	if u.ReturnValues != "" {
		update.ReturnValuesOnConditionCheckFailure = aws.String(u.ReturnValues)
	}
	return &dynamodb.TransactWriteItem{
		Update: &update,
	}, nil
}
func (u *Update) BuildExpression() (*expression.Expression, error) {
	upd := expression.UpdateBuilder{}
	if all, ok := u.Set[SetAll]; ok {
		values, err := dynamodbattribute.MarshalMap(all)
		if err != nil {
			return nil, err
		}
		for name, value := range values {
			upd = upd.Set(expression.Name(name), expression.Value(value))
		}
	}
	for name, value := range u.Set {
		if name == SetAll {
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
	out, err := expr.Build()
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (u *Update) Cancelled(r *dynamodb.CancellationReason) error {
	if u.Cancel != nil {
		return u.Cancel(r)
	}
	return nil
}

type Delete struct {
	TableName    string
	Key          interface{}
	Condition    expression.ConditionBuilder
	ReturnValues string
	Cancel       func(r *dynamodb.CancellationReason) error
}

func (d *Delete) BuildItem() (*dynamodb.TransactWriteItem, error) {
	expr, err := BuildConditionExpression(d.Condition)
	if err != nil {
		return nil, err
	}
	key, err := dynamodbattribute.MarshalMap(d.Key)
	if err != nil {
		return nil, err
	}
	del := dynamodb.Delete{
		TableName:                 aws.String(d.TableName),
		Key:                       key,
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}
	if d.ReturnValues != "" {
		del.ReturnValuesOnConditionCheckFailure = aws.String(d.ReturnValues)
	}
	return &dynamodb.TransactWriteItem{
		Delete: &del,
	}, nil
}

func (d *Delete) Cancelled(r *dynamodb.CancellationReason) error {
	if d.Cancel != nil {
		return d.Cancel(r)
	}
	return nil
}

type ConditionCheck struct {
	TableName    string
	Key          interface{}
	Condition    expression.ConditionBuilder
	ReturnValues string
	Cancel       func(r *dynamodb.CancellationReason) error
}

func (c *ConditionCheck) BuildItem() (*dynamodb.TransactWriteItem, error) {
	expr, err := expression.NewBuilder().WithCondition(c.Condition).Build()
	if err != nil {
		return nil, err
	}
	key, err := dynamodbattribute.MarshalMap(c.Key)
	if err != nil {
		return nil, err
	}
	cond := dynamodb.ConditionCheck{
		TableName:                 aws.String(c.TableName),
		Key:                       key,
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}
	if c.ReturnValues != "" {
		cond.ReturnValuesOnConditionCheckFailure = aws.String(c.ReturnValues)
	}
	return &dynamodb.TransactWriteItem{
		ConditionCheck: &cond,
	}, nil
}

func (c *ConditionCheck) Cancelled(r *dynamodb.CancellationReason) error {
	if c.Cancel != nil {
		return c.Cancel(r)
	}
	return nil
}

func StringSet(strings ...string) *dynamodb.AttributeValue {
	return &dynamodb.AttributeValue{
		SS: aws.StringSlice(strings),
	}
}

func MustMarshalMap(val interface{}) map[string]*dynamodb.AttributeValue {
	attr, err := dynamodbattribute.MarshalMap(val)
	if err != nil {
		panic(err)
	}
	return attr
}

func BuildConditionExpression(cond expression.ConditionBuilder) (expression.Expression, error) {
	if !HasCondition(cond) {
		return expression.Expression{}, nil
	}
	return expression.NewBuilder().WithCondition(cond).Build()
}
