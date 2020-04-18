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
	"github.com/aws/aws-sdk-go/service/athena"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsathena"
)

func (API) ExecuteAsyncQuery(input *models.ExecuteAsyncQueryInput) (*models.ExecuteAsyncQueryOutput, error) {
	var output models.ExecuteAsyncQueryOutput

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
		zap.L().Info("ExecuteAsyncQuery",
			zap.String("userId", userID),
			zap.String("queryId", output.QueryID),
			zap.Error(err))
	}()

	startOutput, err := awsathena.StartQuery(athenaClient, input.DatabaseName, input.SQL, athenaS3ResultsPath)
	if err != nil {
		output.Status = models.QueryFailed

		// try to dig out the athena error if there is one
		if athenaErr, ok := err.(*athena.InvalidRequestException); ok {
			output.SQLError = athenaErr.Message()
			return &output, nil // no lambda err
		}

		return &output, err
	}

	output.Status = models.QueryRunning
	output.QueryID = *startOutput.QueryExecutionId
	return &output, nil
}
