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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/internal/core/database_api/athena/testutils"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	badExecutingSQL = `select * from nosuchtable` // fails AFTER query starts
	malformedSQL    = `wewewewew`                 // fails when query starts
)

var (
	integrationTest bool

	api = API{}

	s3Client *s3.S3

	testSQL = `select * from ` + testutils.TestTable

	maxRowsPerResult int64 = 1 // force pagination to test
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		SessionInit()
		lambdaClient = lambda.New(awsSession)
		s3Client = s3.New(awsSession)
	}
	os.Exit(m.Run())
}

func TestIntegrationAthenaAPI(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	t.Log("testing direct calls from client")
	testAthenaAPI(t, false)
}

func TestIntegrationLambdaAthenaAPI(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	t.Log("testing indirect calls thru deployed lambdas")
	testAthenaAPI(t, true)
}

func testAthenaAPI(t *testing.T, useLambda bool) {
	testutils.SetupTables(t, glueClient, s3Client)
	defer func() {
		testutils.RemoveTables(t, glueClient, s3Client)
	}()

	// -------- GetDatabases()

	// list
	var getDatabasesInput models.GetDatabasesInput
	getDatabasesOutput, err := runGetDatabases(useLambda, &getDatabasesInput)
	require.NoError(t, err)
	foundDB := false
	for _, db := range getDatabasesOutput.Databases {
		if db.Name == testutils.TestDb {
			foundDB = true
		}
	}
	require.True(t, foundDB)

	// specific lookup
	getDatabasesInput.Name = aws.String(testutils.TestDb)
	getDatabasesOutput, err = runGetDatabases(useLambda, &getDatabasesInput)
	require.NoError(t, err)
	require.Equal(t, 1, len(getDatabasesOutput.Databases))
	require.Equal(t, testutils.TestDb, getDatabasesOutput.Databases[0].Name)

	// -------- GetTables()

	getTablesInput := &models.GetTablesInput{
		Database: models.Database{
			DatabaseName: testutils.TestDb,
		},
		OnlyPopulated: true,
	}
	getTablesOutput, err := runGetTables(useLambda, getTablesInput)
	require.NoError(t, err)
	require.Equal(t, 1, len(getTablesOutput.Tables))
	testutils.CheckTableDetail(t, getTablesOutput.Tables)

	// -------- GetTablesDetail()

	getTablesDetailInput := &models.GetTablesDetailInput{
		Database: models.Database{
			DatabaseName: testutils.TestDb,
		},
		Names: []string{testutils.TestTable},
	}
	getTablesDetailOutput, err := runGetTablesDetail(useLambda, getTablesDetailInput)
	require.NoError(t, err)
	testutils.CheckTableDetail(t, getTablesDetailOutput.Tables)

	// -------- ExecuteQuery()

	executeQueryInput := &models.ExecuteQueryInput{
		Database: models.Database{
			DatabaseName: testutils.TestDb,
		},
		SQLQuery: models.SQLQuery{
			SQL: testSQL,
		},
	}
	executeQueryOutput, err := runExecuteQuery(useLambda, executeQueryInput)
	require.NoError(t, err)
	assert.Equal(t, "", executeQueryOutput.QueryStatus.SQLError)
	require.Equal(t, models.QuerySucceeded, executeQueryOutput.Status)
	checkQueryResults(t, true, len(testutils.TestTableRows)+1, executeQueryOutput.ResultsPage.Rows)

	// -------- ExecuteQuery() BAD SQL

	executeBadQueryInput := &models.ExecuteQueryInput{
		Database: models.Database{
			DatabaseName: testutils.TestDb,
		},
		SQLQuery: models.SQLQuery{
			SQL: malformedSQL,
		},
	}
	executeBadQueryOutput, err := runExecuteQuery(useLambda, executeBadQueryInput)
	require.NoError(t, err) // NO LAMBDA ERROR here!
	require.Equal(t, models.QueryFailed, executeBadQueryOutput.Status)
	assert.True(t, strings.Contains(executeBadQueryOutput.SQLError, "mismatched input 'wewewewew'"))
	assert.Equal(t, malformedSQL, executeBadQueryOutput.SQL)

	//  -------- ExecuteAsyncQuery()

	executeAsyncQueryInput := &models.ExecuteAsyncQueryInput{
		Database: models.Database{
			DatabaseName: testutils.TestDb,
		},
		SQLQuery: models.SQLQuery{
			SQL: testSQL,
		},
	}
	executeAsyncQueryOutput, err := runExecuteAsyncQuery(useLambda, executeAsyncQueryInput)
	require.NoError(t, err)

	//  -------- GetQueryStatus()

	for {
		time.Sleep(time.Second * 10)
		getQueryStatusInput := &models.GetQueryStatusInput{
			QueryID: executeAsyncQueryOutput.QueryID,
		}
		getQueryStatusOutput, err := runGetQueryStatus(useLambda, getQueryStatusInput)
		require.NoError(t, err)
		if getQueryStatusOutput.Status != models.QueryRunning {
			break
		}
	}

	//  -------- GetQueryResults()

	getQueryResultsInput := &models.GetQueryResultsInput{
		QueryIdentifier: models.QueryIdentifier{
			QueryID: executeAsyncQueryOutput.QueryID,
		},
		PageSize: &maxRowsPerResult,
	}
	getQueryResultsOutput, err := runGetQueryResults(useLambda, getQueryResultsInput)
	require.NoError(t, err)

	if getQueryResultsOutput.Status == models.QuerySucceeded {
		resultCount := 0
		checkQueryResults(t, true, int(maxRowsPerResult), getQueryResultsOutput.ResultsPage.Rows)
		resultCount++

		for getQueryResultsOutput.ResultsPage.NumRows > 0 { // when done this is 0
			getQueryResultsInput.PaginationToken = getQueryResultsOutput.ResultsPage.PaginationToken
			getQueryResultsOutput, err = runGetQueryResults(useLambda, getQueryResultsInput)
			require.NoError(t, err)
			if getQueryResultsOutput.ResultsPage.NumRows > 0 {
				checkQueryResults(t, false, int(maxRowsPerResult), getQueryResultsOutput.ResultsPage.Rows)
				resultCount++
			}
		}
		require.Equal(t, len(testutils.TestTableRows)+1, resultCount) // since we page 1 at a time and have a header
	} else {
		assert.Fail(t, "GetQueryResults failed")
	}

	//  -------- ExecuteAsyncQuery() BAD SQL

	executeBadAsyncQueryInput := &models.ExecuteAsyncQueryInput{
		Database: models.Database{
			DatabaseName: testutils.TestDb,
		},
		SQLQuery: models.SQLQuery{
			SQL: badExecutingSQL,
		},
	}
	executeBadAsyncQueryOutput, err := runExecuteAsyncQuery(useLambda, executeBadAsyncQueryInput)
	require.NoError(t, err)

	for {
		time.Sleep(time.Second * 2)
		getQueryStatusInput := &models.GetQueryStatusInput{
			QueryID: executeBadAsyncQueryOutput.QueryID,
		}
		getQueryStatusOutput, err := runGetQueryStatus(useLambda, getQueryStatusInput)
		require.NoError(t, err)
		if getQueryStatusOutput.Status != models.QueryRunning {
			require.Equal(t, models.QueryFailed, getQueryStatusOutput.Status)
			assert.True(t, strings.Contains(getQueryStatusOutput.SQLError, "does not exist"))
			assert.Equal(t, badExecutingSQL, getQueryStatusOutput.SQL)
			break
		}
	}

	//  -------- StopQuery()

	executeStopQueryInput := &models.ExecuteAsyncQueryInput{
		Database: models.Database{
			DatabaseName: testutils.TestDb,
		},
		SQLQuery: models.SQLQuery{
			SQL: testSQL,
		},
	}
	executeStopQueryOutput, err := runExecuteAsyncQuery(useLambda, executeStopQueryInput)
	require.NoError(t, err)

	stopQueryInput := &models.StopQueryInput{
		QueryID: executeStopQueryOutput.QueryID,
	}
	_, err = runStopQuery(useLambda, stopQueryInput)
	require.NoError(t, err)

	for {
		time.Sleep(time.Second * 2)
		getQueryStatusInput := &models.GetQueryStatusInput{
			QueryID: executeStopQueryOutput.QueryID,
		}
		getQueryStatusOutput, err := runGetQueryStatus(useLambda, getQueryStatusInput)
		require.NoError(t, err)
		if getQueryStatusOutput.Status != models.QueryRunning {
			require.Equal(t, models.QueryCanceled, getQueryStatusOutput.Status)
			assert.Equal(t, getQueryStatusOutput.SQLError, "Query canceled")
			assert.Equal(t, testSQL, getQueryStatusOutput.SQL)
			break
		}
	}

	//  -------- ExecuteAsyncQueryNotify()

	/*
				See: https://aws.amazon.com/premiumsupport/knowledge-center/appsync-notify-subscribers-real-time/

				To see queryDone subscriptions work in the AppSync console:
			    - Go to Queries
			    - Pick IAM as auth method
				- Add a subscription below and click "play" button ... you should see "Subscribed to 1 mutations" and a spinner:

			       subscription integQuerySub {
			          queryDone(userData: "testUser") {
			            userData
			            queryId
			            workflowId
			          }
			       }

		        - Run integration tests:
			        pushd internal/core/database_api/athena/driver/api/
			        export INTEGRATION_TEST=true
			        aws-vault exec dev-<you>-admin -d 3h -- go test -v

			    - After a minute or two in the console you should see in the results pane something like:

			        {
			          "data": {
			           "queryDone": {
			             "userData": "testUser",
			             "queryId": "4c223d6e-a41a-418f-b97b-b01f044cbdc9",
			             "workflowId": "arn:aws:states:us-east-2:050603629990:execution:panther-athena-workflow:cf56beb0-7493-42ae-a9fd-a024812b8eac"
			           }
			          }
			        }

			     NOTE: the UI should call the lambda panther-athena-api:ExecuteAsyncQueryNotify as below and set up
			     a subscription filtering by user id (or session id). When the query finishes appsync will be notified.
			     UI should use the queryId to call panther-athena-api:GetQueryResults to display results.
	*/

	userData := "testUser" // this is expected to be passed all the way through the workflow, validations will enforce

	executeAsyncQueryNotifyInput := &models.ExecuteAsyncQueryNotifyInput{
		ExecuteAsyncQueryInput: models.ExecuteAsyncQueryInput{
			Database: models.Database{
				DatabaseName: testutils.TestDb,
			},
			SQLQuery: models.SQLQuery{
				SQL: testSQL,
			},
		},
		LambdaInvoke: models.LambdaInvoke{
			LambdaName: "panther-athena-api",
			MethodName: "notifyAppSync",
		},
		UserDataToken: models.UserDataToken{
			UserData: userData,
		},
	}
	executeAsyncQueryNotifyOutput, err := runExecuteAsyncQueryNotify(useLambda, executeAsyncQueryNotifyInput)
	require.NoError(t, err)

	// wait for workflow to finish
	for {
		time.Sleep(time.Second * 10)
		descExecutionInput := &sfn.DescribeExecutionInput{
			ExecutionArn: &executeAsyncQueryNotifyOutput.WorkflowID,
		}
		descExecutionOutput, err := sfnClient.DescribeExecution(descExecutionInput)
		require.NoError(t, err)
		if *descExecutionOutput.Status != sfn.ExecutionStatusRunning {
			require.Equal(t, sfn.ExecutionStatusSucceeded, *descExecutionOutput.Status)
			break
		}
	}
}

func runGetDatabases(useLambda bool, input *models.GetDatabasesInput) (*models.GetDatabasesOutput, error) {
	if useLambda {
		var getDatabasesInput = struct {
			GetDatabases *models.GetDatabasesInput
		}{
			input,
		}
		var getDatabasesOutput *models.GetDatabasesOutput
		err := genericapi.Invoke(lambdaClient, "panther-athena-api", getDatabasesInput, &getDatabasesOutput)
		return getDatabasesOutput, err
	}
	return api.GetDatabases(input)
}

func runGetTables(useLambda bool, input *models.GetTablesInput) (*models.GetTablesOutput, error) {
	if useLambda {
		var getTablesInput = struct {
			GetTables *models.GetTablesInput
		}{
			input,
		}
		var getTablesOutput *models.GetTablesOutput
		err := genericapi.Invoke(lambdaClient, "panther-athena-api", getTablesInput, &getTablesOutput)
		return getTablesOutput, err
	}
	return api.GetTables(input)
}

func runGetTablesDetail(useLambda bool, input *models.GetTablesDetailInput) (*models.GetTablesDetailOutput, error) {
	if useLambda {
		var getTablesDetailInput = struct {
			GetTablesDetail *models.GetTablesDetailInput
		}{
			input,
		}
		var getTablesDetailOutput *models.GetTablesDetailOutput
		err := genericapi.Invoke(lambdaClient, "panther-athena-api", getTablesDetailInput, &getTablesDetailOutput)
		return getTablesDetailOutput, err
	}
	return api.GetTablesDetail(input)
}

func runExecuteQuery(useLambda bool, input *models.ExecuteQueryInput) (*models.ExecuteQueryOutput, error) {
	if useLambda {
		var executeQueryInput = struct {
			ExecuteQuery *models.ExecuteQueryInput
		}{
			input,
		}
		var executeQueryOutput *models.ExecuteQueryOutput
		err := genericapi.Invoke(lambdaClient, "panther-athena-api", executeQueryInput, &executeQueryOutput)
		return executeQueryOutput, err
	}
	return api.ExecuteQuery(input)
}

func runExecuteAsyncQuery(useLambda bool, input *models.ExecuteAsyncQueryInput) (*models.ExecuteAsyncQueryOutput, error) {
	if useLambda {
		var executeAsyncQueryInput = struct {
			ExecuteAsyncQuery *models.ExecuteAsyncQueryInput
		}{
			input,
		}
		var executeAsyncQueryOutput *models.ExecuteAsyncQueryOutput
		err := genericapi.Invoke(lambdaClient, "panther-athena-api", executeAsyncQueryInput, &executeAsyncQueryOutput)
		return executeAsyncQueryOutput, err
	}
	return api.ExecuteAsyncQuery(input)
}

func runExecuteAsyncQueryNotify(useLambda bool, input *models.ExecuteAsyncQueryNotifyInput) (*models.ExecuteAsyncQueryNotifyOutput, error) {
	if useLambda {
		var executeAsyncQueryNotifyInput = struct {
			ExecuteAsyncQueryNotify *models.ExecuteAsyncQueryNotifyInput
		}{
			input,
		}
		var executeAsyncQueryNotifyOutput *models.ExecuteAsyncQueryNotifyOutput
		err := genericapi.Invoke(lambdaClient, "panther-athena-api", executeAsyncQueryNotifyInput, &executeAsyncQueryNotifyOutput)
		return executeAsyncQueryNotifyOutput, err
	}
	return api.ExecuteAsyncQueryNotify(input)
}

func runGetQueryStatus(useLambda bool, input *models.GetQueryStatusInput) (*models.GetQueryStatusOutput, error) {
	if useLambda {
		var getQueryStatusInput = struct {
			GetQueryStatus *models.GetQueryStatusInput
		}{
			input,
		}
		var getQueryStatusOutput *models.GetQueryStatusOutput
		err := genericapi.Invoke(lambdaClient, "panther-athena-api", getQueryStatusInput, &getQueryStatusOutput)
		return getQueryStatusOutput, err
	}
	return api.GetQueryStatus(input)
}

func runGetQueryResults(useLambda bool, input *models.GetQueryResultsInput) (*models.GetQueryResultsOutput, error) {
	if useLambda {
		var getQueryResultsInput = struct {
			GetQueryResults *models.GetQueryResultsInput
		}{
			input,
		}
		var getQueryResultsOutput *models.GetQueryResultsOutput
		err := genericapi.Invoke(lambdaClient, "panther-athena-api", getQueryResultsInput, &getQueryResultsOutput)
		return getQueryResultsOutput, err
	}
	return api.GetQueryResults(input)
}

func runStopQuery(useLambda bool, input *models.StopQueryInput) (*models.StopQueryOutput, error) {
	if useLambda {
		var stopQueryInput = struct {
			StopQuery *models.StopQueryInput
		}{
			input,
		}
		var stopQueryOutput *models.StopQueryOutput
		err := genericapi.Invoke(lambdaClient, "panther-athena-api", stopQueryInput, &stopQueryOutput)
		return stopQueryOutput, err
	}
	return api.StopQuery(input)
}

func checkQueryResults(t *testing.T, hasHeader bool, expectedRowCount int, rows []*models.Row) {
	require.Equal(t, expectedRowCount, len(rows))
	i := 0
	nResults := len(rows)
	if hasHeader {
		require.Equal(t, "col1", rows[0].Columns[0].Value) // header
		i++
	}
	for ; i < nResults; i++ {
		require.Equal(t, "1", rows[i].Columns[0].Value)
	}
}
