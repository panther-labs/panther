package genericapi

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

type routes struct{}

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

var testRouter = NewRouter("testNamespace", "testComponent", nil, &routes{})

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
		Route: "AddRule", Message: "exactly one route must be specified: also found DeleteRule"}
	assert.Equal(t, errExpected, err)
}

func TestHandleValidationFailed(t *testing.T) {
	result, err := testRouter.Handle(&lambdaInput{AddRule: &addRuleInput{Name: aws.String("")}})
	assert.Nil(t, result)

	errExpected := &InvalidInputError{
		Route: "AddRule",
		Message: ("Key: 'lambdaInput.AddRule.Name' Error:" +
			"Field validation for 'Name' failed on the 'min' tag"),
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
