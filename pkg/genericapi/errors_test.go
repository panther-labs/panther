package genericapi

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
)

func TestAlreadyExistsError(t *testing.T) {
	err := &AlreadyExistsError{Route: "Do", Message: "name=panther"}
	assert.Equal(t, "name=panther", err.Error())
}

func TestAWSError(t *testing.T) {
	err := &AWSError{Route: "Do", Method: "dynamodb.PutItem", Err: errors.New("not authorized")}
	assert.Equal(t, "not authorized", err.Error())
}

func TestDoesNotExistError(t *testing.T) {
	err := &DoesNotExistError{Route: "Do", Message: "name=panther"}
	assert.Equal(t, "name=panther", err.Error())
}

func TestInternalError(t *testing.T) {
	err := &InternalError{Route: "Do", Message: "can't marshal to JSON"}
	assert.Equal(t, "can't marshal to JSON", err.Error())
}

func TestInUseError(t *testing.T) {
	err := &InUseError{Route: "Do", Message: "name=panther"}
	assert.Equal(t, "name=panther", err.Error())
}

func TestInvalidInputError(t *testing.T) {
	err := &InvalidInputError{Route: "Do", Message: "you forgot something"}
	assert.Equal(t, "you forgot something", err.Error())
}

func TestLambdaErrorEmpty(t *testing.T) {
	err := &LambdaError{}
	assert.Equal(t, "lambda error returned: (nil)", err.Error())
}

func TestLambdaError(t *testing.T) {
	err := &LambdaError{
		Route: "Do", FunctionName: "rules-api", ErrorMessage: aws.String("task timed out")}
	assert.Equal(t, "Do failed: lambda error returned: rules-api: task timed out", err.Error())
}
