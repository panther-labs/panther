package driver

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
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/database/models"
)

func GetDatabases(glueClient glueiface.GlueAPI, input *models.GetDatabasesInput) (*models.GetDatabasesOutput, error) {
	output := &models.GetDatabasesOutput{}

	var err error
	defer func() {
		if err != nil {
			output.ErrorMessage = "GetDatabase failed" // simple error message for lambda caller
		}
	}()

	if input.DatabaseName != "" {
		var glueOutput *glue.GetDatabaseOutput
		glueOutput, err = glueClient.GetDatabase(&glue.GetDatabaseInput{
			Name: aws.String(input.DatabaseName),
		})
		if err != nil {
			return output, errors.WithStack(err)
		}
		output.Databases = append(output.Databases, &models.DatabaseDescription{
			DatabaseName: *glueOutput.Database.Name,
			Description:  aws.StringValue(glueOutput.Database.Description), // optional
		})
		return output, err
	}

	// list
	err = glueClient.GetDatabasesPages(&glue.GetDatabasesInput{},
		func(page *glue.GetDatabasesOutput, lastPage bool) bool {
			for _, database := range page.DatabaseList {
				output.Databases = append(output.Databases, &models.DatabaseDescription{
					DatabaseName: *database.Name,
					Description:  aws.StringValue(database.Description), // optional
				})
			}
			return false
		})

	return output, errors.WithStack(err)
}

func GetTables(glueClient glueiface.GlueAPI, input *models.GetTablesInput) (*models.GetTablesOutput, error) {
	output := &models.GetTablesOutput{
		GetTablesInput: *input,
	}

	var err error
	defer func() {
		if err != nil {
			output.ErrorMessage = "GetTables failed" // simple error message for lambda caller
		}
	}()

	err = glueClient.GetTablesPages(&glue.GetTablesInput{DatabaseName: aws.String(input.DatabaseName)},
		func(page *glue.GetTablesOutput, lastPage bool) bool {
			for _, table := range page.TableList {
				output.Tables = append(output.Tables, &models.TableDescription{
					DatabaseName: input.DatabaseName,
					TableName:    *table.Name,
					Description:  aws.StringValue(table.Description), // optional
				})
			}
			return false
		})

	return output, errors.WithStack(err)
}

func GetTablesDetail(glueClient glueiface.GlueAPI, input *models.GetTablesDetailInput) (*models.GetTablesDetailOutput, error) {
	output := &models.GetTablesDetailOutput{}

	var err error
	defer func() {
		if err != nil {
			output.ErrorMessage = "GetTablesDetails failed" // simple error message for lambda caller
		}
	}()

	for _, tableName := range input.TableNames {
		var glueOutput *glue.GetTableOutput
		glueOutput, err = glueClient.GetTable(&glue.GetTableInput{
			DatabaseName: aws.String(input.DatabaseName),
			Name:         aws.String(tableName),
		})
		if err != nil {
			return output, errors.WithStack(err)
		}
		detail := &models.TableDetail{
			TableDescription: models.TableDescription{
				DatabaseName: input.DatabaseName,
				TableName:    *glueOutput.Table.Name,
			},
		}
		for _, column := range glueOutput.Table.StorageDescriptor.Columns {
			detail.Columns = append(detail.Columns, &models.TableColumn{
				Name:        aws.StringValue(column.Name),
				Type:        aws.StringValue(column.Type),
				Description: aws.StringValue(column.Comment),
			})
		}
		output.TablesDetails = append(output.TablesDetails, detail)
	}
	return output, nil
}
