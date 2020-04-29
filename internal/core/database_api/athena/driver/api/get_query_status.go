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

func (API) GetQueryStatus(input *models.GetQueryStatusInput) (*models.GetQueryStatusOutput, error) {
	var output models.GetQueryStatusOutput

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}

		// allows tracing queries
		zap.L().Info("GetQueryStatus",
			zap.String("queryId", input.QueryID),
			zap.Error(err))
	}()

	executionStatus, err := awsathena.Status(athenaClient, input.QueryID)
	if err != nil {
		return &output, err
	}

	output.SQL = *executionStatus.QueryExecution.Query
	output.Status = getQueryStatus(executionStatus)

	switch output.Status {
	case models.QuerySucceeded:
		output.Stats = &models.QueryResultsStats{
			ExecutionTimeMilliseconds: *executionStatus.QueryExecution.Statistics.TotalExecutionTimeInMillis,
			DataScannedBytes:          *executionStatus.QueryExecution.Statistics.DataScannedInBytes,
		}
	case models.QueryFailed: // lambda succeeded BUT query failed (could be for many reasons)
		output.SQLError = *executionStatus.QueryExecution.Status.StateChangeReason
	case models.QueryCancelled:
		output.SQLError = "Query canceled"
	}
	return &output, nil
}

func getQueryStatus(executionStatus *athena.GetQueryExecutionOutput) string {
	switch *executionStatus.QueryExecution.Status.State {
	case
		athena.QueryExecutionStateSucceeded:
		return models.QuerySucceeded
	case
		// failure modes
		athena.QueryExecutionStateFailed:
		return models.QueryFailed
	case
		athena.QueryExecutionStateCancelled:
		return models.QueryCancelled
	case
		// still going
		athena.QueryExecutionStateRunning,
		athena.QueryExecutionStateQueued:
		return models.QueryRunning
	default:
		panic("unknown athena status: " + *executionStatus.QueryExecution.Status.State)
	}
}
