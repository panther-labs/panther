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
