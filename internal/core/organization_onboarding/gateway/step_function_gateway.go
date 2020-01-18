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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sfn"
	sfnI "github.com/aws/aws-sdk-go/service/sfn/sfniface"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/api/lambda/onboarding/models"
)

// API defines the interface for the user gateway which can be used for mocking.
type API interface {
	DescribeExecution(executionArn *string) (*models.GetOnboardingStatusOutput, error)
}

// StepFunctionGateway encapsulates a service to AWS Step Function.
type StepFunctionGateway struct {
	sfnClient sfnI.SFNAPI
}

// The StepFunctionGateway must satisfy the API interface.
var _ API = (*StepFunctionGateway)(nil)

// New creates a new StepFunctionClient client.
func New(sess *session.Session) *StepFunctionGateway {
	return &StepFunctionGateway{
		sfnClient: sfn.New(sess),
	}
}

// MockSFN is a mock CloudTrail client.
type MockSFN struct {
	sfnI.SFNAPI
	mock.Mock
}

// DescribeExecution is a mock function to return fake CloudTrail data.
func (m *MockSFN) DescribeExecution(
	in *sfn.DescribeExecutionInput,
) (*sfn.DescribeExecutionOutput, error) {

	args := m.Called(in)
	return args.Get(0).(*sfn.DescribeExecutionOutput), args.Error(1)
}
