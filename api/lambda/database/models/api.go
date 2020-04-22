package models

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

// NOTE: different kinds of databases (e.g., Athena, Snowflake) will use different endpoints (lambda functions), same api.

// NOTE: if a json tag _set_ is used more than once it is factored into a struct to avoid inconsistencies

const (
	QuerySucceeded = "succeeded"
	QueryFailed    = "failed"
	QueryRunning   = "running"
	QueryCancelled = "cancelled"
)

// LambdaInput is the collection of all possible args to the Lambda function.
type LambdaInput struct {
	// run a query, returning immediately with an id for the running query
	ExecuteAsyncQuery *ExecuteAsyncQueryInput `json:"executeAsyncQuery"`
	// run a query, returning immediately with an id for the step function running the query (will invoke lambda callback when done)
	ExecuteAsyncQueryNotify *ExecuteAsyncQueryNotifyInput `json:"executeAsyncQueryNotify"`
	// run a query, waiting for results
	ExecuteQuery *ExecuteQueryInput `json:"executeQuery"`
	// list databases
	GetDatabases *GetDatabasesInput `json:"getDatabases"`
	// given a query id, return paged results
	GetQueryResults *GetQueryResultsInput `json:"getQueryResults"`
	// given a query id, return a presigned s3 link to the results
	GetQueryResultsLink *GetQueryResultsLinkInput `json:"getQueryResultsLink"`
	// given a query id, return the status of the query
	GetQueryStatus *GetQueryStatusInput `json:"getQueryStatus"`
	// given a database, list tables
	GetTables *GetTablesInput `json:"getTables"`
	// given a database and list of tables, return tables
	GetTablesDetail *GetTablesDetailInput `json:"getTablesDetail"`
	// given a lambda and method, execute callback for step function
	InvokeNotifyLambda *InvokeNotifyLambdaInput `json:"invokeNotifyLambda"`
	// used as a callback lambda, will notify appsync that a UI query is complete
	NotifyAppSync *NotifyAppSyncInput `json:"notifyAppSync"`
	// given a query id, cancel query
	StopQuery *StopQueryInput `json:"stopQuery"`
}

type GetDatabasesInput struct {
	OptionalName // if nil get all databases
}

// NOTE: we will assume this is small an not paginate
type GetDatabasesOutput struct {
	Databases []*NameAndDescription `json:"databases,omitempty"`
}

type GetTablesInput struct {
	Database
	IncludePopulatedTablesOnly *bool `json:"includePopulatedTablesOnly,omitempty"` // if true OR nil, return only tables that have data
}

// NOTE: we will assume this is small an not paginate
type GetTablesOutput struct {
	TablesDetail
}

type TablesDetail struct {
	Tables []*TableDetail `json:"tables"`
}

type TableDetail struct {
	TableDescription
	Columns []*TableColumn `json:"columns"`
}

type TableDescription struct {
	Database
	NameAndDescription
}

type GetTablesDetailInput struct {
	Database
	Names []string `json:"names" validate:"required"`
}

// NOTE: we will assume this is small an not paginate
type GetTablesDetailOutput struct {
	TablesDetail
}

type TableColumn struct {
	NameAndDescription
	Type string `json:"type" validate:"required"`
}

type ExecuteAsyncQueryNotifyInput struct {
	ExecuteAsyncQueryInput
	LambdaInvoke
	UserPassThruData
	DelaySeconds int `json:"delaySeconds"` // wait this long before starting workflow (default 0)
}

type ExecuteAsyncQueryNotifyOutput struct {
	Workflow
}

// Blocking query
type ExecuteQueryInput = ExecuteAsyncQueryInput

type ExecuteQueryOutput = GetQueryResultsOutput // call GetQueryResults() to page through results

type ExecuteAsyncQueryInput struct {
	Database
	SQLQuery
	UserID *string `json:"userId,omitempty"`
}

type ExecuteAsyncQueryOutput struct {
	QueryStatus
	QueryInfo
}

type GetQueryStatusInput = QueryInfo

type GetQueryStatusOutput struct {
	QueryStatus
	SQLQuery
	Stats *QueryResultsStats `json:"stats,omitempty"` // present only on successful queries
}

type GetQueryResultsInput struct {
	QueryInfo
	Pagination
	PageSize *int64 `json:"pageSize" validate:"omitempty,gt=1,lt=1000"` // only return this many rows per call
	// NOTE: gt=1 above to ensure there are results on the first page w/header. If PageSize = 1 then
	// user will get no rows for the first page with Athena because Athena returns header as first row and we remove it.
}

type GetQueryResultsOutput struct {
	GetQueryStatusOutput
	ColumnInfo  []*Column        `json:"columnInfo" validate:"required"`
	ResultsPage QueryResultsPage `json:"resultsPage" validate:"required"`
}

type QueryResultsPage struct {
	Pagination
	NumRows int    `json:"numRows"  validate:"required"` // number of rows in page of results, len(Rows)
	Rows    []*Row `json:"rows"  validate:"required"`
}

type QueryResultsStats struct {
	ExecutionTimeMilliseconds int64 `json:"executionTimeMilliseconds"  validate:"required"`
	DataScannedBytes          int64 `json:"dataScannedBytes"  validate:"required"`
}

type GetQueryResultsLinkInput struct {
	QueryInfo
}

type GetQueryResultsLinkOutput struct {
	QueryStatus
	PresignedLink string `json:"presignedLink"` // presigned s3 link to results
}

type StopQueryInput = QueryInfo

type StopQueryOutput = GetQueryStatusOutput

type InvokeNotifyLambdaInput struct {
	LambdaInvoke
	QueryInfo
	Workflow
	UserPassThruData
}

type InvokeNotifyLambdaOutput = InvokeNotifyLambdaInput // so input can be confirmed

type NotifyAppSyncInput struct {
	NotifyInput
}

type NotifyAppSyncOutput struct {
	StatusCode int `json:"statusCode" validate:"required"` // the http status returned from POSTing callback to appsync
}

type NotifyInput struct { // notify lambdas need to have this as input
	GetQueryStatusInput
	ExecuteAsyncQueryNotifyOutput
	UserPassThruData
}

type NameAndDescription struct {
	Name        string  `json:"name" validate:"required"`
	Description *string `json:"description,omitempty"`
}

type OptionalName struct {
	Name *string `json:"name,omitempty"`
}

type SQLQuery struct {
	SQL string `json:"sql" validate:"required"`
}

type QueryInfo struct {
	QueryID string `json:"queryId" validate:"required"`
}

type Database struct {
	DatabaseName string `json:"databaseName" validate:"required"`
}

type Row struct {
	Columns []*Column `json:"columns" validate:"required"`
}

type Column struct {
	Value *string `json:"value"` // NULL values are nil
	Type  *string `json:"type,omitempty"`
}

type Pagination struct {
	PaginationToken *string `json:"paginationToken,omitempty"`
}

type QueryStatus struct {
	Status   string `json:"status" validate:"required,oneof=running,succeeded,failed,canceled"`
	SQLError string `json:"sqlError,omitempty"`
}

type Workflow struct {
	WorkflowID string `json:"workflowId" validate:"required"`
}

type UserPassThruData struct {
	UserData string `json:"userData" validate:"required,gt=0"` // token passed though to notifications (usually the userid)
}

type LambdaInvoke struct {
	LambdaName string `json:"lambdaName" validate:"required"` // the name of the lambda to call when done
	MethodName string `json:"methodName" validate:"required"` // the method to call on the lambda
}
