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
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsglue"
)

func (API) GetDatabases(input *models.GetDatabasesInput) (*models.GetDatabasesOutput, error) {
	var output models.GetDatabasesOutput

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	if input.Name != nil {
		if envConfig.PantherTablesOnly && awsglue.PantherDatabases[*input.Name] == "" {
			return &output, err // nothing
		}
		var glueOutput *glue.GetDatabaseOutput
		glueOutput, err = glueClient.GetDatabase(&glue.GetDatabaseInput{
			Name: input.Name,
		})
		if err != nil {
			err = errors.WithStack(err)
			return &output, err
		}
		output.Databases = append(output.Databases, &models.NameAndDescription{
			Name:        *glueOutput.Database.Name,
			Description: glueOutput.Database.Description, // optional
		})
		return &output, err
	}

	// list
	err = glueClient.GetDatabasesPages(&glue.GetDatabasesInput{},
		func(page *glue.GetDatabasesOutput, lastPage bool) bool {
			for _, database := range page.DatabaseList {
				if envConfig.PantherTablesOnly && awsglue.PantherDatabases[*database.Name] == "" {
					continue // skip
				}
				output.Databases = append(output.Databases, &models.NameAndDescription{
					Name:        *database.Name,
					Description: database.Description, // optional
				})
			}
			return false
		})

	return &output, errors.WithStack(err)
}
