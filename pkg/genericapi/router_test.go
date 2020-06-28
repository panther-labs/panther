package genericapi

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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
)

const mockID = "825488f4-10d7-4c29-a4c4-51d85d30c1ce"

type addRuleInput struct {
	Description *string `json:"description,omitempty" genericapi:"redact"`
	Name        *string `json:"name" validate:"required,min=1"`
}

type addRuleOutput struct {
	RuleID *string
}

type deleteRuleInput struct {
	RuleID *string `validate:"required,uuid4"`
}

type updateRuleInput addRuleInput

type lambdaInput struct {
	AddRule    *addRuleInput
	DeleteRule *deleteRuleInput
	UpdateRule *updateRuleInput
}

type enhanceRuleInput deleteRuleInput

// this is how APIs are composed
type composedLambdaInput struct {
	lambdaInput
	EnhanceRule *enhanceRuleInput
}

type routes struct{}

type composedRoutes struct{}

func (*routes) AddRule(input *addRuleInput) (*addRuleOutput, error) {
	if input.Name != nil && *input.Name == "AlreadyExists" {
		return nil, &AlreadyExistsError{}
	}
	return &addRuleOutput{RuleID: aws.String(mockID)}, nil
}

func (*routes) DeleteRule(input *deleteRuleInput) error {
	return nil
}

func (*routes) UpdateRule(input *updateRuleInput) error {
	return errors.New("manual error")
}

func (*composedRoutes) AddRule(input *addRuleInput) (*addRuleOutput, error) {
	return &addRuleOutput{RuleID: aws.String(mockID)}, nil
}

func (*composedRoutes) DeleteRule(input *deleteRuleInput) error {
	return nil
}

func (*composedRoutes) UpdateRule(input *updateRuleInput) error {
	return nil
}

func (*composedRoutes) EnhanceRule(input *enhanceRuleInput) error {
	return nil
}

var (
	testRouter            = NewRouter("testNamespace", "testComponent", nil, &routes{})
	testComposedAPIRouter = NewRouter("testNamespace", "testComponent", nil, &composedRoutes{})
)

func TestHandleNoAction(t *testing.T) {
	result, err := testRouter.Handle(&lambdaInput{})
	assert.Nil(t, result)

	errExpected := &InvalidInputError{
		Route: "nil", Message: "exactly one route must be specified: found none"}
	assert.Equal(t, errExpected, err)
}

func TestHandleTwoActions(t *testing.T) {
	result, err := testRouter.Handle(
		&lambdaInput{AddRule: &addRuleInput{}, DeleteRule: &deleteRuleInput{}})
	assert.Nil(t, result)

	errExpected := &InvalidInputError{
		Route: "", Message: "exactly one route must be specified: [AddRule DeleteRule]"}
	assert.Equal(t, errExpected, err)
}

func TestHandleValidationFailed(t *testing.T) {
	result, err := testRouter.Handle(&lambdaInput{AddRule: &addRuleInput{Name: aws.String("")}})
	assert.Nil(t, result)

	errExpected := &InvalidInputError{
		Route:   "AddRule",
		Message: "Name invalid, failed to satisfy the condition: min=1",
	}
	assert.Equal(t, errExpected, err)
}

func TestHandleOneReturnValue(t *testing.T) {
	input := &lambdaInput{DeleteRule: &deleteRuleInput{RuleID: aws.String(mockID)}}
	result, err := testRouter.Handle(input)
	assert.Nil(t, result)
	assert.NoError(t, err)
}

func TestHandleOneReturnValueError(t *testing.T) {
	input := &lambdaInput{UpdateRule: &updateRuleInput{Name: aws.String("MyRule")}}
	result, err := testRouter.Handle(input)
	assert.Nil(t, result)
	assert.Equal(t, "manual error", err.Error())
}

func TestHandleTwoReturnValues(t *testing.T) {
	input := &lambdaInput{AddRule: &addRuleInput{Name: aws.String("MyRule")}}
	result, err := testRouter.Handle(input)
	assert.Equal(t, &addRuleOutput{RuleID: aws.String(mockID)}, result)
	assert.NoError(t, err)
}

func TestHandleTwoReturnValuesError(t *testing.T) {
	input := &lambdaInput{AddRule: &addRuleInput{Name: aws.String("AlreadyExists")}}
	result, err := testRouter.Handle(input)
	assert.Nil(t, result)
	assert.Equal(t, &AlreadyExistsError{Route: "AddRule"}, err) // route name was injected
}

func TestHandleComposedStruct(t *testing.T) {
	input := &composedLambdaInput{
		lambdaInput: lambdaInput{},
		EnhanceRule: &enhanceRuleInput{RuleID: aws.String(mockID)},
	}
	result, err := testComposedAPIRouter.Handle(input)
	assert.Nil(t, result)
	assert.NoError(t, err)
}

// How expensive is it to look up a method by name?
// 385 ns/op
func BenchmarkNameFinding(b *testing.B) {
	var route string
	val := reflect.ValueOf(&routes{})

	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			route = "AddRule"
		} else {
			route = "DeleteRule"
		}

		handler := val.MethodByName(route)
		if !handler.IsValid() {
			panic("invalid handler")
		}
	}
}

// Caching the reflected method is a 70x speedup!
// 5 ns/op
func BenchmarkNameFindingCached(b *testing.B) {
	var route string
	cache := make(map[string]reflect.Value)
	val := reflect.ValueOf(&routes{})

	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			route = "AddRule"
		} else {
			route = "DeleteRule"
		}

		var handler reflect.Value
		var ok bool
		if handler, ok = cache[route]; !ok {
			handler = val.MethodByName(route)
			cache[route] = handler
		}

		// Do something with the handler
		if !handler.IsValid() {
			panic("invalid handler")
		}
	}
}
