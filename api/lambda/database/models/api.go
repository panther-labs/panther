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
	QueryCanceled  = "canceled"
)

// LambdaInput is the collection of all possible args to the Lambda function.
type LambdaInput struct {
	ExecuteAsyncQuery       *ExecuteAsyncQueryInput       `json:"executeAsyncQuery"`
	ExecuteAsyncQueryNotify *ExecuteAsyncQueryNotifyInput `json:"executeAsyncQueryNotify"` // uses Step functions
	ExecuteQuery            *ExecuteQueryInput            `json:"executeQuery"`
	GetDatabases            *GetDatabasesInput            `json:"getDatabases"`
	GetQueryResults         *GetQueryResultsInput         `json:"getQueryResults"`
	GetQueryStatus          *GetQueryStatusInput          `json:"getQueryStatus"`
	GetTables               *GetTablesInput               `json:"getTables"`
	GetTablesDetail         *GetTablesDetailInput         `json:"getTablesDetail"`
	InvokeNotifyLambda      *InvokeNotifyLambdaInput      `json:"invokeNotifyLambda"`
	NotifyAppSync           *NotifyAppSyncInput           `json:"notifyAppSync"`
	StopQuery               *StopQueryInput               `json:"stopQuery"`
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
}

type GetTablesInput struct {
	DatabaseName  string `json:"databaseName" validate:"required"`
	OnlyPopulated bool   `json:"onlyPopulated,omitempty"` // if true, only return table containing data
}

// NOTE: we will assume this is small an not paginate
type GetTablesOutput struct {
	Tables []*TableDetail `json:"tables"`
}

type TableDescription struct {
	DatabaseName string  `json:"databaseName" validate:"required"`
	Name         string  `json:"name" validate:"required"`
	Description  *string `json:"description,omitempty"`
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
	Tables []*TableDetail `json:"tables,omitempty"`
}

type TableColumn struct {
	Name        string  `json:"name" validate:"required"`
	Type        string  `json:"type" validate:"required"`
	Description *string `json:"description,omitempty"`
}

type ExecuteAsyncQueryNotifyInput struct {
	ExecuteAsyncQueryInput
	LambdaInvoke
	UserData     string `json:"userData" validate:"required,gt=0"`      // token passed though to notifications (usually the userid)
	DelaySeconds int    `json:"delaySeconds" validate:"omitempty,gt=0"` // wait this long before starting workflow (default 0)
}

type ExecuteAsyncQueryNotifyOutput struct {
	WorkflowID string `json:"workflowId" validate:"required"`
}

type LambdaInvoke struct {
	LambdaName string `json:"lambdaName" validate:"required"` // the name of the lambda to call when done
	MethodName string `json:"methodName" validate:"required"` // the method to call on the lambda
}

// Blocking query
type ExecuteQueryInput = ExecuteAsyncQueryInput

type ExecuteQueryOutput = GetQueryResultsOutput // call GetQueryResults() to page thu results

type ExecuteAsyncQueryInput struct {
	DatabaseName string `json:"databaseName" validate:"required"`
	SQL          string `json:"sql" validate:"required"`
}

type ExecuteAsyncQueryOutput struct {
	QueryError
	QueryIdentifier
}

type GetQueryStatusInput = QueryIdentifier

type GetQueryStatusOutput struct {
	QueryError
	Status string `json:"status" validate:"required,oneof=running,succeeded,failed"`
	SQL    string `json:"sql" validate:"required"`
}

type GetQueryResultsInput struct {
	QueryIdentifier
	PaginationToken *string `json:"paginationToken,omitempty"`
	PageSize        *int64  `json:"pageSize" validate:"omitempty,gt=0,lt=1000"` // only return this many rows per call
}

type GetQueryResultsOutput struct {
	GetQueryStatusOutput
	ResultsPage QueryResultsPage `json:"resultsPage" validate:"required"`
}

type QueryResultsPage struct {
	NumRows         int     `json:"numRows"` // number of rows in page of results, len(Rows)
	Rows            []*Row  `json:"rows"`
	PaginationToken *string `json:"paginationToken,omitempty"`
}

type StopQueryInput = QueryIdentifier

type StopQueryOutput = GetQueryStatusOutput

type InvokeNotifyLambdaInput struct {
	LambdaInvoke
	ExecuteAsyncQueryOutput
	ExecuteAsyncQueryNotifyOutput
	UserData string `json:"userData" validate:"required,gt=0"` // token passed though to notifications (usually the userid)
}

type InvokeNotifyLambdaOutput struct {
}

type NotifyAppSyncInput struct {
	NotifyInput
}

type NotifyAppSyncOutput struct {
	StatusCode int `json:"statusCode" validate:"required"` // the http status returned from POSTing callback to appsync
}

type NotifyInput struct { // notify lambdas need to have this as input
	GetQueryStatusInput
	ExecuteAsyncQueryNotifyOutput
	UserData string `json:"userData" validate:"required,gt=0"` // token passed though to notifications (usually the userid)
}

type QueryIdentifier struct {
	QueryID string `json:"queryId" validate:"required"`
}

type Row struct {
	Columns []*Column `json:"columns"`
}

type Column struct {
	Value string `json:"value"`
}

type QueryError struct {
	ErrorMessage string `json:"errorMessage,omitempty"` // this is 'ErrorMessage' not 'Message' because we are composing
}
