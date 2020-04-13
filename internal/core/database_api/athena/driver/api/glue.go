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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/database/models"
)

func (API) GetDatabases(input *models.GetDatabasesInput) (*models.GetDatabasesOutput, error) {
	output := &models.GetDatabasesOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	if input.Name != nil {
		var glueOutput *glue.GetDatabaseOutput
		glueOutput, err = glueClient.GetDatabase(&glue.GetDatabaseInput{
			Name: input.Name,
		})
		if err != nil {
			err = errors.WithStack(err)
			return output, err
		}
		output.Databases = append(output.Databases, &models.NameAndDescription{
			Name:        *glueOutput.Database.Name,
			Description: glueOutput.Database.Description, // optional
		})
		return output, err
	}

	// list
	err = glueClient.GetDatabasesPages(&glue.GetDatabasesInput{},
		func(page *glue.GetDatabasesOutput, lastPage bool) bool {
			for _, database := range page.DatabaseList {
				output.Databases = append(output.Databases, &models.NameAndDescription{
					Name:        *database.Name,
					Description: database.Description, // optional
				})
			}
			return false
		})

	return output, errors.WithStack(err)
}

func (API) GetTables(input *models.GetTablesInput) (*models.GetTablesOutput, error) {
	output := &models.GetTablesOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	var partitionErr error
	err = glueClient.GetTablesPages(&glue.GetTablesInput{DatabaseName: aws.String(input.DatabaseName)},
		func(page *glue.GetTablesOutput, lastPage bool) bool {
			for _, table := range page.TableList {
				if input.OnlyPopulated { // check there is at least 1 partition
					var gluePartitionOutput *glue.GetPartitionsOutput
					gluePartitionOutput, partitionErr = glueClient.GetPartitions(&glue.GetPartitionsInput{
						DatabaseName: aws.String(input.DatabaseName),
						TableName:    table.Name,
						MaxResults:   aws.Int64(1),
					})
					if partitionErr != nil {
						return true // stop
					}
					if len(gluePartitionOutput.Partitions) == 0 { // skip if no partitions
						continue
					}
				}
				detail := &models.TableDetail{
					TableDescription: models.TableDescription{
						Database: models.Database{
							DatabaseName: input.DatabaseName,
						},
						NameAndDescription: models.NameAndDescription{
							Name:        *table.Name,
							Description: table.Description, // optional
						},
					},
				}
				populateTableDetailColumns(detail, table)
				output.Tables = append(output.Tables, detail)
			}
			return false
		})
	if partitionErr != nil {
		err = partitionErr
	}

	return output, errors.WithStack(err)
}

func (API) GetTablesDetail(input *models.GetTablesDetailInput) (*models.GetTablesDetailOutput, error) {
	output := &models.GetTablesDetailOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	for _, tableName := range input.Names {
		var glueTableOutput *glue.GetTableOutput
		glueTableOutput, err = glueClient.GetTable(&glue.GetTableInput{
			DatabaseName: aws.String(input.DatabaseName),
			Name:         aws.String(tableName),
		})
		if err != nil {
			err = errors.WithStack(err)
			return output, err
		}
		detail := &models.TableDetail{
			TableDescription: models.TableDescription{
				Database: models.Database{
					DatabaseName: input.DatabaseName,
				},
				NameAndDescription: models.NameAndDescription{
					Name:        *glueTableOutput.Table.Name,
					Description: glueTableOutput.Table.Description,
				},
			},
		}
		populateTableDetailColumns(detail, glueTableOutput.Table)
		output.Tables = append(output.Tables, detail)
	}
	return output, nil
}

func populateTableDetailColumns(tableDetail *models.TableDetail, glueTableData *glue.TableData) {
	for _, column := range glueTableData.StorageDescriptor.Columns {
		tableDetail.Columns = append(tableDetail.Columns, &models.TableColumn{
			NameAndDescription: models.NameAndDescription{
				Name:        aws.StringValue(column.Name),
				Description: column.Comment,
			},
			Type: aws.StringValue(column.Type),
		})
	}
	for _, column := range glueTableData.PartitionKeys {
		tableDetail.Columns = append(tableDetail.Columns, &models.TableColumn{
			NameAndDescription: models.NameAndDescription{
				Name:        aws.StringValue(column.Name),
				Description: column.Comment,
			},
			Type: aws.StringValue(column.Type),
		})
	}
}
