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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsglue"
)

func (API) GetTables(input *models.GetTablesInput) (*models.GetTablesOutput, error) {
	var output models.GetTablesOutput

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	if envConfig.PantherTablesOnly && awsglue.PantherDatabases[input.DatabaseName] == "" {
		return &output, err // nothing
	}

	var partitionErr error
	err = glueClient.GetTablesPages(&glue.GetTablesInput{DatabaseName: aws.String(input.DatabaseName)},
		func(page *glue.GetTablesOutput, lastPage bool) bool {
			for _, table := range page.TableList {
				// Default to only listing tables that have data, if input.IncludePopulatedTablesOnly is set, then
				// defer to the setting. Implemented by checking there is at least 1 partition
				if input.IncludePopulatedTablesOnly == nil || *input.IncludePopulatedTablesOnly {
					var gluePartitionOutput *glue.GetPartitionsOutput
					gluePartitionOutput, partitionErr = glueClient.GetPartitions(&glue.GetPartitionsInput{
						DatabaseName: aws.String(input.DatabaseName),
						TableName:    table.Name,
						MaxResults:   aws.Int64(1),
					})
					if partitionErr != nil {
						return false // stop
					}
					if len(gluePartitionOutput.Partitions) == 0 { // skip if no partitions
						continue
					}
				}
				detail := newTableDetail(input.DatabaseName, *table.Name, table.Description)
				populateTableDetailColumns(detail, table)
				output.Tables = append(output.Tables, detail)
			}
			return true
		})
	if partitionErr != nil {
		err = partitionErr
	}

	return &output, errors.WithStack(err)
}
