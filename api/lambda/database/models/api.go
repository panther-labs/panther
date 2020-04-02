package models

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

// NOTE: different kinds of databases (e.g., Athena, Snowflake) will use different endpoints (lambda functions), same api.

const (
	QuerySucceeded = "succeeded"
	QueryFailed    = "failed"
	QueryRunning   = "running"
)

// LambdaInput is the collection of all possible args to the Lambda function.
type LambdaInput struct {
	GetDatabases           *GetDatabasesInput           `json:"getDatabases"`
	GetTables              *GetTablesInput              `json:"getTables"`
	GetTablesDetail        *GetTablesDetailInput        `json:"getTablesDetail"`
	StartQuery             *StartQueryInput             `json:"startQuery"`
	GetQueryStatus         *GetQueryStatusInput         `json:"getQueryStatus"`
	GetQueryResults        *GetQueryResultsInput        `json:"getQueryResults"`
	DoQuery                *DoQueryInput                `json:"doQuery"`
	DoPantherSimpleSummary *DoPantherSimpleSummaryInput `json:"doPantherSimpleSummary"`
}

type GetDatabasesInput struct {
	DatabaseName string `json:"database_name,omitempty"` // if empty get all databases
}

// NOTE: we will assume this is small an not paginate
type GetDatabasesOutput struct {
	Error
	GetDatabasesInput
	Databases []*DatabaseDescription `json:"databases,omitempty"`
}

type DatabaseDescription struct {
	DatabaseName string `json:"database_name,omitempty"`
	Description  string `json:"description,omitempty"`
	// other stuff? CreateDate?
}

type GetTablesInput struct {
	DatabaseName string `json:"database_name" validate:"required"`
}

// NOTE: we will assume this is small an not paginate
type GetTablesOutput struct {
	Error
	GetTablesInput
	Tables []*TableDescription `json:"tables,omitempty"`
}

type TableDescription struct {
	DatabaseName string `json:"database_name,omitempty"`
	TableName    string `json:"table_name,omitempty"`
	Description  string `json:"description,omitempty"`
	// other stuff? CreateDate?
}

type TableDetail struct {
	TableDescription
	Columns []*TableColumn `json:"columns,omitempty"`
}

type GetTablesDetailInput struct {
	DatabaseName string   `json:"database_name" validate:"required"`
	TableNames   []string `json:"table_names" validate:"required"`
}

// NOTE: we will assume this is small an not paginate
type GetTablesDetailOutput struct {
	Error
	TablesDetails []*TableDetail `json:"tables_details,omitempty"`
}

type TableColumn struct {
	Name        string `json:"name,omitempty" validate:"required"`
	Type        string `json:"type,omitempty" validate:"required"`
	Description string `json:"description,omitempty"`
}

// Async query
type StartQueryInput struct {
	DatabaseName string `json:"database_name" validate:"required"`
	SQL          string `json:"sql" validate:"required"`
	MaxResults   *int64 `json:"max_results"` // only return this many per call
}

type StartQueryOutput struct {
	Error
	GetQueryResultsOutput // might be filled in if query ran fast
}

type GetQueryStatusInput struct {
	QueryID string `json:"query_id" validate:"required"`
}

type GetQueryStatusOutput struct {
	Error
	GetQueryStatusInput
	Status string `json:"status" validate:"required,oneof=running,succeeded,failed"`
}

type GetQueryResultsInput struct {
	QueryID         string `json:"query_id" validate:"required"`
	PaginationToken string `results:"pagination_token,omitempty"`
	MaxResults      *int64 `json:"max_results"` // only return this many per call
}

type GetQueryResultsOutput struct {
	Error
	GetQueryResultsInput
	Status   string `json:"status" validate:"required,oneof=running,succeeded,failed"`
	NumRows  int    `results:"num_rows"`
	JSONData string `results:"json_data,omitempty"`
}

// Blocking query
type DoQueryInput StartQueryInput

type DoQueryOutput GetQueryResultsOutput // call GetQueryResults() to page thu results

type DoPantherSimpleSummaryInput struct {
	SearchItems string `json:"search_items" validate:"required"`
}

type DoPantherSimpleSummaryOutput GetQueryResultsOutput // GetQueryResults() to page thu results

type Error struct {
	ErrorMessage string `json:"error_message,omitempty"`
}
