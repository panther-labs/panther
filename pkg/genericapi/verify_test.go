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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyNoHandlers(t *testing.T) {
	type badinput struct {
		DoStuff *string
	}
	err := testRouter.VerifyHandlers(&badinput{})
	assert.Equal(t, "input has 1 fields but there are 3 handlers", err.(*InternalError).Message)
}

func TestVerifyMissingHandler(t *testing.T) {
	type badinput struct {
		Awesome *string
		Bovine  *string
		Club    *string
	}
	err := testRouter.VerifyHandlers(&badinput{})
	assert.Equal(t, "func Awesome does not exist", err.(*InternalError).Message)
}

type missingArgs struct{}

func (*missingArgs) AddRule() error { return nil }

func TestVerifyMissingArgument(t *testing.T) {
	type input struct{ AddRule *addRuleInput }
	err := NewRouter("testNamespace", "testComponent", nil, &missingArgs{}).VerifyHandlers(&input{})
	assert.Equal(t, "AddRule should have 1 argument, found 0", err.(*InternalError).Message)
}

type wrongArgType struct{}

func (*wrongArgType) AddRule(*deleteRuleInput) error { return nil }

func TestVerifyWrongArgType(t *testing.T) {
	type input struct{ AddRule *addRuleInput }
	err := NewRouter("testNamespace", "testComponent", nil, &wrongArgType{}).VerifyHandlers(&input{})
	assert.Equal(t, "AddRule expects an argument of type *genericapi.deleteRuleInput, "+
		"input has type *genericapi.addRuleInput", err.(*InternalError).Message)
}

type wrongReturnSingle struct{}

func (*wrongReturnSingle) AddRule(*addRuleInput) InternalError { return InternalError{} }

func TestVerifySingleReturnNotError(t *testing.T) {
	type input struct{ AddRule *addRuleInput }
	err := NewRouter("testNamespace", "testComponent", nil, &wrongReturnSingle{}).VerifyHandlers(&input{})
	assert.Equal(
		t,
		"AddRule returns genericapi.InternalError, which does not satisfy error",
		err.(*InternalError).Message,
	)
}

type wrongReturnDouble struct{}

func (*wrongReturnDouble) AddRule(*addRuleInput) (*string, *string) { return nil, nil }

func TestVerifySecondReturnNotError(t *testing.T) {
	type input struct{ AddRule *addRuleInput }
	err := NewRouter("testNamespace", "testComponent", nil, &wrongReturnDouble{}).VerifyHandlers(&input{})
	assert.Equal(
		t,
		"AddRule second return is *string, which does not satisfy error",
		err.(*InternalError).Message,
	)
}

type noReturns struct{}

func (*noReturns) AddRule(*addRuleInput) {}

func TestVerifyNoReturns(t *testing.T) {
	type input struct{ AddRule *addRuleInput }
	err := NewRouter("testNamespace", "testComponent", nil, &noReturns{}).VerifyHandlers(&input{})
	assert.Equal(
		t, "AddRule should have 1 or 2 returns, found 0", err.(*InternalError).Message)
}

func TestVerifyValid(t *testing.T) {
	assert.Nil(t, testRouter.VerifyHandlers(&lambdaInput{}))
}
