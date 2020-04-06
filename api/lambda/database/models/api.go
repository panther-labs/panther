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
	ExecuteAsyncQuery       *ExecuteAsyncQueryInput       `json:"executeAsyncQuery"`
	ExecuteAsyncQueryNotify *ExecuteAsyncQueryNotifyInput `json:"executeAsyncQueryNotify"`
	ExecuteQuery            *ExecuteQueryInput            `json:"executeQuery"`
	ExecuteSimpleSummary    *ExecuteSimpleSummaryInput    `json:"executeSimpleSummary"`
	GetDatabases            *GetDatabasesInput            `json:"getDatabases"`
	GetQueryResults         *GetQueryResultsInput         `json:"getQueryResults"`
	GetQueryStatus          *GetQueryStatusInput          `json:"getQueryStatus"`
	GetTables               *GetTablesInput               `json:"getTables"`
	GetTablesDetail         *GetTablesDetailInput         `json:"getTablesDetail"`
	NotifyAppSync           *NotifyAppSyncInput           `json:"notifyAppSync"`
}

type GetDatabasesInput struct {
	Name *string `json:"name,omitempty"` // if empty get all databases
}

// NOTE: we will assume this is small an not paginate
type GetDatabasesOutput struct {
	Databases []*DatabaseDescription `json:"databases,omitempty"`
}

type DatabaseDescription struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	// other stuff? CreateDate?
}

type GetTablesInput struct {
	DatabaseName  string `json:"databaseName" validate:"required"`
	OnlyPopulated bool   `json:"onlyPopulated,omitempty"` // if true, only return table containing data
}

// NOTE: we will assume this is small an not paginate
type GetTablesOutput struct {
	Tables []*TableDescription `json:"tables"`
}

type TableDescription struct {
	DatabaseName string  `json:"databaseName" validate:"required"`
	Name         string  `json:"name" validate:"required"`
	Description  *string `json:"description,omitempty"`
	// other stuff? CreateDate?
}

type TableDetail struct {
	TableDescription
	Columns []*TableColumn `json:"columns"`
}

type GetTablesDetailInput struct {
	DatabaseName string   `json:"databaseName" validate:"required"`
	Names        []string `json:"names" validate:"required"`
}

// NOTE: we will assume this is small an not paginate
type GetTablesDetailOutput struct {
	TablesDetails []*TableDetail `json:"tablesDetails,omitempty"`
}

type TableColumn struct {
	Name        string  `json:"name" validate:"required"`
	Type        string  `json:"type" validate:"required"`
	Description *string `json:"description,omitempty"`
}

type ExecuteAsyncQueryNotifyInput struct {
	ExecuteAsyncQueryInput
}

type ExecuteAsyncQueryNotifyOutput struct {
	ExecuteAsyncQueryOutput
	WorkflowID string `json:"workflowId" validate:"required"`
}

// Blocking query
type ExecuteQueryInput = ExecuteAsyncQueryInput

type ExecuteQueryOutput = GetQueryResultsOutput // call GetQueryResults() to page thu results

type ExecuteAsyncQueryInput struct {
	DatabaseName string `json:"databaseName" validate:"required"`
	SQL          string `json:"sql" validate:"required"`
}

type ExecuteAsyncQueryOutput struct {
	QueryID string `json:"queryId" validate:"required"`
}

type GetQueryStatusInput struct {
	QueryID string `json:"queryId" validate:"required"`
}

type GetQueryStatusOutput struct {
	QueryError
	Status string `json:"status" validate:"required,oneof=running,succeeded,failed"`
	SQL    string `json:"sql" validate:"required"`
}

type GetQueryResultsInput struct {
	QueryID         string  `json:"queryId" validate:"required"`
	PaginationToken *string `json:"paginationToken,omitempty"`
	PageSize        *int64  `json:"pageSize" validate:"omitempty,gt=0,lt=1000"` // only return this many rows per call
}

type GetQueryResultsOutput struct {
	QueryError
	QueryID     string           `json:"queryId" validate:"required"`
	Status      string           `json:"status" validate:"required,oneof=running,succeeded,failed"`
	SQL         string           `json:"sql" validate:"required"`
	ResultsPage QueryResultsPage `json:"resultsPage" validate:"required"`
}

type QueryResultsPage struct {
	NumRows         int     `json:"numRows"` // number of rows in page of results, len(Rows)
	Rows            []*Row  `json:"rows"`
	PaginationToken *string `json:"paginationToken,omitempty"`
}

type NotifyAppSyncInput = GetQueryStatusInput

type NotifyAppSyncOutput = GetQueryStatusOutput

// Google-like search returning a summary table
type ExecuteSimpleSummaryInput struct {
	SearchString string `json:"searchString" validate:"required"`
}

type ExecuteSimpleSummaryOutput = GetQueryResultsOutput // GetQueryResults() to page thu results

type Row struct {
	Columns []*Column `json:"columns"`
}

type Column struct {
	Value string `json:"value"`
}

type QueryError struct {
	Message string `json:"message,omitempty"`
}
