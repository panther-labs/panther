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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/glue"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/internal/core/database_api/athena/driver"
)

var (
	sess         = session.Must(session.NewSession())
	glueClient   = glue.New(sess)
	athenaClient = athena.New(sess)
)

// API provides receiver methods for each route handler.
type API struct{}

func (api API) GetDatabases(input *models.GetDatabasesInput) (*models.GetDatabasesOutput, error) {
	return driver.GetDatabases(glueClient, input)
}

func (api API) GetTables(input *models.GetTablesInput) (*models.GetTablesOutput, error) {
	return driver.GetTables(glueClient, input)
}

func (api API) GetTablesDetails(input *models.GetTablesDetailInput) (*models.GetTablesDetailOutput, error) {
	return driver.GetTablesDetails(glueClient, input)
}

func (api API) DoQuery(input *models.DoQueryInput) (*models.DoQueryOutput, error) {
	return driver.DoQuery(athenaClient, input)
}

func (api API) StartQuery(input *models.StartQueryInput) (*models.StartQueryOutput, error) {
	return driver.StartQuery(athenaClient, input)
}

func (api API) GetQueryStatus(input *models.GetQueryStatusInput) (*models.GetQueryStatusOutput, error) {
	return driver.GetQueryStatus(athenaClient, input)
}

func (api API) GetQueryResults(input *models.GetQueryResultsInput) (*models.GetQueryResultsOutput, error) {
	return driver.GetQueryResults(athenaClient, input)
}
