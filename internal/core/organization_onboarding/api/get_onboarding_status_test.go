package api

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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/api/lambda/onboarding/models"
	"github.com/panther-labs/panther/internal/core/organization_onboarding/gateway"
	"github.com/panther-labs/panther/pkg/genericapi"
)

type mockGatewayStepFunctionClient struct {
	gateway.API
	stepFunctionGatewayErr bool
}

func (m *mockGatewayStepFunctionClient) DescribeExecution(executionArn *string) (*models.GetOnboardingStatusOutput, error) {
	if m.stepFunctionGatewayErr {
		return nil, &genericapi.AWSError{}
	}
	startDate, _ := time.Parse(time.RFC3339, "2019-04-10T23:00:00Z")
	stopDate, _ := time.Parse(time.RFC3339, "2019-04-10T22:59:00Zs")

	return &models.GetOnboardingStatusOutput{
		Status:    aws.String("PASSING"),
		StartDate: aws.String(startDate.String()),
		StopDate:  aws.String(stopDate.String()),
	}, nil
}

func TestGetOnboardingStatusGateway(t *testing.T) {
	stepFunctionGateway = &mockGatewayStepFunctionClient{}
	result, err := (API{}).GetOnboardingStatus(&models.GetOnboardingStatusInput{
		ExecutionArn: aws.String("fakeExecutionArns"),
	})
	assert.NotNil(t, result)
	assert.Nil(t, err)
}

func TestGetOnboardingStatusGatewayErr(t *testing.T) {
	stepFunctionGateway = &mockGatewayStepFunctionClient{stepFunctionGatewayErr: true}
	result, err := (API{}).GetOnboardingStatus(&models.GetOnboardingStatusInput{
		ExecutionArn: aws.String("fakeExecutionArns"),
	})
	assert.Nil(t, result)
	assert.Error(t, err)
}
