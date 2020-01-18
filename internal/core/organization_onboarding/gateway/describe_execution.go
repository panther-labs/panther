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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sfn"

	"github.com/panther-labs/panther/api/lambda/onboarding/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// DescribeExecution calls step function api to get execution status
func (g *StepFunctionGateway) DescribeExecution(executionArn *string) (*models.GetOnboardingStatusOutput, error) {
	eo, err := g.sfnClient.DescribeExecution(&sfn.DescribeExecutionInput{
		ExecutionArn: executionArn,
	})
	if err != nil {
		return nil, &genericapi.AWSError{Method: "sfn.describeExecution", Err: err}
	}
	return &models.GetOnboardingStatusOutput{
		Status:    eo.Status,
		StartDate: aws.String(eo.StartDate.String()),
		StopDate:  aws.String(eo.StopDate.String()),
	}, nil
}
