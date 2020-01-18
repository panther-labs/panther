package gateway

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestDescribeExecution(t *testing.T) {
	mockSvc := &MockSFN{}
	gw := &StepFunctionGateway{sfnClient: mockSvc}
	describeOut := &sfn.DescribeExecutionOutput{
		StartDate: &time.Time{},
		StopDate:  &time.Time{},
		Status:    aws.String("PASSED"),
	}
	mockSvc.
		On("DescribeExecution", mock.Anything).
		Return(describeOut, nil)

	result, err := gw.DescribeExecution(
		aws.String("fakeExecutionArn"),
	)
	assert.NotNil(t, result)
	assert.NoError(t, err)
}

func TestDescribeExecutionFailed(t *testing.T) {
	mockSvc := &MockSFN{}
	gw := &StepFunctionGateway{sfnClient: mockSvc}
	err := errors.New("sfn does not exist")
	mockSvc.
		On("DescribeExecution", mock.Anything).
		Return(&sfn.DescribeExecutionOutput{}, err)

	result, err := gw.DescribeExecution(
		aws.String("fakeExecutionArn"),
	)
	assert.Nil(t, result)
	assert.Error(t, err)
}
