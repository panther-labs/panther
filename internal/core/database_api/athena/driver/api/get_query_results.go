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
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsathena"
)

func (api API) GetQueryResults(input *models.GetQueryResultsInput) (*models.GetQueryResultsOutput, error) {
	var output models.GetQueryResultsOutput

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}

		// allows tracing queries
		zap.L().Info("GetQueryResults",
			zap.String("queryId", input.QueryID),
			zap.Error(err))
	}()

	getStatusOutput, err := api.GetQueryStatus(&input.QueryInfo)
	if err != nil {
		return &output, err
	}

	output.GetQueryStatusOutput = *getStatusOutput

	switch output.Status {
	case models.QuerySucceeded:
		var nextToken *string
		if input.PaginationToken != nil { // paging thru results
			nextToken = input.PaginationToken
		}
		err = getQueryResults(athenaClient, input.QueryID, &output, nextToken, input.PageSize)
		if err != nil {
			return &output, err
		}
	}
	return &output, nil
}

func getQueryResults(client athenaiface.AthenaAPI, queryID string,
	output *models.GetQueryResultsOutput, nextToken *string, maxResults *int64) (err error) {

	queryResult, err := awsathena.Results(client, queryID, nextToken, maxResults)
	if err != nil {
		return err
	}

	// header with types
	for _, columnInfo := range queryResult.ResultSet.ResultSetMetadata.ColumnInfo {
		output.ColumnInfo = append(output.ColumnInfo, &models.Column{
			Value: columnInfo.Name,
			Type:  columnInfo.Type,
		})
	}

	skipHeader := nextToken == nil // athena puts header in first row of first page
	collectResults(skipHeader, queryResult, output)
	return nil
}

func collectResults(skipHeader bool, queryResult *athena.GetQueryResultsOutput, output *models.GetQueryResultsOutput) {
	output.ResultsPage.Rows = make([]*models.Row, 0, len(queryResult.ResultSet.Rows)) // pre-alloc
	for _, row := range queryResult.ResultSet.Rows {
		if skipHeader {
			skipHeader = false
			continue
		}
		columns := make([]*models.Column, len(row.Data))
		for colIndex := range row.Data {
			columns[colIndex] = &models.Column{Value: row.Data[colIndex].VarCharValue}
		}
		output.ResultsPage.Rows = append(output.ResultsPage.Rows, &models.Row{Columns: columns})
	}

	output.ResultsPage.NumRows = len(output.ResultsPage.Rows)
	output.ResultsPage.PaginationToken = queryResult.NextToken
}
