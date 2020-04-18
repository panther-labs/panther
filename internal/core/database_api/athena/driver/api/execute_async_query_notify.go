package api

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
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/database/models"
)

// Execute an Athena query via step function workflow.

const (
	stateMachineName = "panther-athena-workflow"
)

func (API) ExecuteAsyncQueryNotify(input *models.ExecuteAsyncQueryNotifyInput) (*models.ExecuteAsyncQueryNotifyOutput, error) {
	output := &models.ExecuteAsyncQueryNotifyOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}

		// allows tracing queries
		var userID string
		if input.UserID != nil {
			userID = *input.UserID
		}
		zap.L().Info("ExecuteAsyncQueryNotify",
			zap.String("userId", userID),
			zap.String("userData", input.UserData),
			zap.String("workflowID", output.WorkflowID),
			zap.Error(err))
	}()

	worflowJSON, err := jsoniter.Marshal(input)
	if err != nil {
		err = errors.Wrapf(err, "failed to marshal %#v", input)
		return output, err
	}

	identity, err := sts.New(awsSession).GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil || identity.Account == nil {
		err = errors.Wrapf(err, "failed to get identity %#v", input)
		return output, err
	}

	if awsSession.Config.Region == nil {
		err = errors.Wrapf(err, "failed to get aws region %#v", input)
		return output, err
	}

	stateMachineARN := fmt.Sprintf("arn:aws:states:%s:%s:stateMachine:%s",
		*awsSession.Config.Region, *identity.Account, stateMachineName)

	startExecutionInput := &sfn.StartExecutionInput{
		Input:           aws.String(string(worflowJSON)),
		Name:            aws.String(uuid.New().String()),
		StateMachineArn: &stateMachineARN,
	}
	startExecutionOutput, err := sfnClient.StartExecution(startExecutionInput)
	if err != nil {
		err = errors.Wrapf(err, "failed to start workflow execution for: %#v", input)
		return output, err
	}
	output.Workflow.WorkflowID = *startExecutionOutput.ExecutionArn

	return output, err
}
