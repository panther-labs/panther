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

func (API) GetTablesDetail(input *models.GetTablesDetailInput) (*models.GetTablesDetailOutput, error) {
	output := &models.GetTablesDetailOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	if pantherTablesOnly && awsglue.PantherDatabases[input.DatabaseName] == "" {
		return output, err // nothing
	}

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
		detail := newTableDetail(input.DatabaseName, *glueTableOutput.Table.Name, glueTableOutput.Table.Description)
		populateTableDetailColumns(detail, glueTableOutput.Table)
		output.Tables = append(output.Tables, detail)
	}
	return output, nil
}

func populateTableDetailColumns(tableDetail *models.TableDetail, glueTableData *glue.TableData) {
	for _, column := range glueTableData.StorageDescriptor.Columns {
		tableDetail.Columns = append(tableDetail.Columns,
			newTableColumn(aws.StringValue(column.Name), aws.StringValue(column.Type), column.Comment))
	}
	for _, column := range glueTableData.PartitionKeys {
		tableDetail.Columns = append(tableDetail.Columns,
			newTableColumn(aws.StringValue(column.Name), aws.StringValue(column.Type), column.Comment))
	}
}

// wrap complex constructors to make code more readable above

func newTableDetail(databaseName, tableName string, description *string) *models.TableDetail {
	return &models.TableDetail{
		TableDescription: models.TableDescription{
			Database: models.Database{
				DatabaseName: databaseName,
			},
			NameAndDescription: models.NameAndDescription{
				Name:        tableName,
				Description: description, // optional
			},
		},
	}
}

func newTableColumn(colName, colType string, description *string) *models.TableColumn {
	return &models.TableColumn{
		NameAndDescription: models.NameAndDescription{
			Name:        colName,
			Description: description,
		},
		Type: colType,
	}
}
