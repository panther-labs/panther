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
	ExecuteAsyncQuery    *ExecuteAsyncQueryInput    `json:"executeAsyncQuery"`
	ExecuteQuery         *ExecuteQueryInput         `json:"executeQuery"`
	ExecuteSimpleSummary *ExecuteSimpleSummaryInput `json:"executeSimpleSummary"`
	GetDatabases         *GetDatabasesInput         `json:"getDatabases"`
	GetQueryStatus       *GetQueryStatusInput       `json:"getQueryStatus"`
	GetQueryResults      *GetQueryResultsInput      `json:"getQueryResults"`
	GetTables            *GetTablesInput            `json:"getTables"`
	GetTablesDetail      *GetTablesDetailInput      `json:"getTablesDetail"`
}

type GetDatabasesInput struct {
	DatabaseName *string `json:"databaseName,omitempty"` // if empty get all databases
}

// NOTE: we will assume this is small an not paginate
type GetDatabasesOutput struct {
	Error
	Databases []*DatabaseDescription `json:"databases,omitempty"`
}

type DatabaseDescription struct {
	DatabaseName string  `json:"databaseName"`
	Description  *string `json:"description,omitempty"`
	// other stuff? CreateDate?
}

type GetTablesInput struct {
	DatabaseName  string `json:"databaseName" validate:"required"`
	OnlyPopulated bool   `json:"onlyPopulated,omitempty"` // if true, only return table containing data
}

// NOTE: we will assume this is small an not paginate
type GetTablesOutput struct {
	Error
	Tables []*TableDescription `json:"tables,omitempty"`
}

type TableDescription struct {
	DatabaseName string  `json:"databaseName"`
	TableName    string  `json:"tableName"`
	Description  *string `json:"description,omitempty"`
	// other stuff? CreateDate?
}

type TableDetail struct {
	TableDescription
	Columns []*TableColumn `json:"columns,omitempty"`
}

type GetTablesDetailInput struct {
	DatabaseName string   `json:"databaseName" validate:"required"`
	TableNames   []string `json:"tableNames" validate:"required"`
}

// NOTE: we will assume this is small an not paginate
type GetTablesDetailOutput struct {
	Error
	TablesDetails []*TableDetail `json:"tables_details,omitempty"`
}

type TableColumn struct {
	Name        string  `json:"name,omitempty" validate:"required"`
	Type        string  `json:"type,omitempty" validate:"required"`
	Description *string `json:"description,omitempty"`
}

type ExecuteAsyncQueryInput struct {
	DatabaseName       string `json:"databaseName" validate:"required"`
	SQL                string `json:"sql" validate:"required"`
	ResultsMaxPageSize *int64 `json:"resultsMaxPageSize"` // only return this many per call
}

type ExecuteAsyncQueryOutput struct {
	Error
	QueryID string `json:"queryId" validate:"required"`
}

type GetQueryStatusInput struct {
	QueryID string `json:"queryId" validate:"required"`
}

type GetQueryStatusOutput struct {
	Error
	Status string `json:"status" validate:"required,oneof=running,succeeded,failed"`
}

type GetQueryResultsInput struct {
	QueryID            string  `json:"queryId" validate:"required"`
	PaginationToken    *string `json:"paginationToken,omitempty"`
	ResultsMaxPageSize *int64  `json:"resultsMaxPageSize"` // only return this many per call
}

type GetQueryResultsOutput struct {
	Error
	QueryID         string  `json:"queryId" validate:"required"`
	Status          string  `json:"status" validate:"required,oneof=running,succeeded,failed"`
	NumRows         int     `json:"numRows"`
	Rows            []*Row  `json:"rows"`
	PaginationToken *string `json:"paginationToken,omitempty"`
}

// Blocking query
type ExecuteQueryInput ExecuteAsyncQueryInput

type ExecuteQueryOutput GetQueryResultsOutput // call GetQueryResults() to page thu results

// Google-like search returning a summary table
type ExecuteSimpleSummaryInput struct {
	SearchString string `json:"searchString" validate:"required"`
}

type ExecuteSimpleSummaryOutput GetQueryResultsOutput // GetQueryResults() to page thu results

type Row struct {
	Columns []*Column `json:"columns"`
}

type Column struct {
	Value string `json:"value"`
}

type Error struct {
	ErrorMessage string `json:"errorMessage,omitempty"`
}
