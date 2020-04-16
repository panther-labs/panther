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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
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
	printJSON = false // set to true to print json input/output (useful for sharing with frontend devs)

	testUserID       = "testUserID"
	testSQL          = `select * from ` + testutils.TestTable + ` order by col1 asc`      // tests may break w/out order by
	badExecutingSQL  = `select * from nosuchtable`                                        // fails AFTER query starts
	malformedSQL     = `wewewewew`                                                        // fails when query starts
	dropTableSQL     = `drop table ` + testutils.TestTable                                // tests for mutating permissions
	createTableAsSQL = `create table ishouldfail as select * from ` + testutils.TestTable // tests for mutating permissions
)

var (
	integrationTest bool

	api = API{}

	maxRowsPerResult int64 = 3 // force pagination to test
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

	// ensure we run serially, by default Go will run tests in parallel and we can't have that
	t.Run("direct calls from client", func(t *testing.T) {
		testAthenaAPI(t, false)
	})
	t.Run("indirect calls thru deployed lambdas", func(t *testing.T) {
		testAthenaAPI(t, true)
	})
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

	var getTablesInput models.GetTablesInput
	getTablesInput.DatabaseName = testutils.TestDb
	getTablesInput.OnlyPopulated = true
	getTablesOutput, err := runGetTables(useLambda, &getTablesInput)
	require.NoError(t, err)
	require.Equal(t, 1, len(getTablesOutput.Tables))
	testutils.CheckTableDetail(t, getTablesOutput.Tables)

	// -------- GetTablesDetail()

	var getTablesDetailInput models.GetTablesDetailInput
	getTablesDetailInput.DatabaseName = testutils.TestDb
	getTablesDetailInput.Names = []string{testutils.TestTable}
	getTablesDetailOutput, err := runGetTablesDetail(useLambda, &getTablesDetailInput)
	require.NoError(t, err)
	testutils.CheckTableDetail(t, getTablesDetailOutput.Tables)

	// -------- ExecuteQuery()

	var executeQueryInput models.ExecuteQueryInput
	executeQueryInput.UserID = aws.String(testUserID)
	executeQueryInput.DatabaseName = testutils.TestDb
	executeQueryInput.SQL = testSQL
	executeQueryOutput, err := runExecuteQuery(useLambda, &executeQueryInput)
	require.NoError(t, err)
	assert.Equal(t, "", executeQueryOutput.QueryStatus.SQLError)
	require.Equal(t, models.QuerySucceeded, executeQueryOutput.Status)
	assert.Greater(t, executeQueryOutput.Stats.ExecutionTimeMilliseconds, int64(0)) // at least something
	assert.Greater(t, executeQueryOutput.Stats.DataScannedBytes, int64(0))          // at least something
	assert.Equal(t, len(testutils.TestTableColumns)+len(testutils.TestTablePartitions), len(executeQueryOutput.ColumnInfo))
	for i, c := range executeQueryOutput.ColumnInfo {
		if i < len(testutils.TestTableColumns) {
			assert.Equal(t, c.Value, *testutils.TestTableColumns[i].Name)
		} else { // partitions
			assert.Equal(t, c.Value, *testutils.TestTablePartitions[i-len(testutils.TestTableColumns)].Name)
		}
	}
	assert.Equal(t, len(testutils.TestTableRows), len(executeQueryOutput.ResultsPage.Rows))
	checkQueryResults(t, len(testutils.TestTableRows), 0, executeQueryOutput.ResultsPage.Rows)

	// -------- ExecuteQuery() BAD SQL

	var executeBadQueryInput models.ExecuteQueryInput
	executeBadQueryInput.UserID = aws.String(testUserID)
	executeBadQueryInput.DatabaseName = testutils.TestDb
	executeBadQueryInput.SQL = malformedSQL
	executeBadQueryOutput, err := runExecuteQuery(useLambda, &executeBadQueryInput)
	require.NoError(t, err) // NO LAMBDA ERROR here!
	require.Equal(t, models.QueryFailed, executeBadQueryOutput.Status)
	assert.True(t, strings.Contains(executeBadQueryOutput.SQLError, "mismatched input 'wewewewew'"))
	assert.Equal(t, malformedSQL, executeBadQueryOutput.SQL)

	// -------- ExecuteQuery() DROP TABLE

	if useLambda { // only for lambda to test access restrictions
		var executeDropTableInput models.ExecuteQueryInput
		executeDropTableInput.UserID = aws.String(testUserID)
		executeDropTableInput.DatabaseName = testutils.TestDb
		executeDropTableInput.SQL = dropTableSQL
		executeDropTableOutput, err := runExecuteQuery(useLambda, &executeDropTableInput)
		require.NoError(t, err) // NO LAMBDA ERROR here!
		require.Equal(t, models.QueryFailed, executeDropTableOutput.Status)
		assert.True(t, strings.Contains(executeDropTableOutput.SQLError, "AccessDeniedException"))
		assert.Equal(t, dropTableSQL, executeDropTableOutput.SQL)
	}

	// -------- ExecuteQuery() CREATE TABLE AS

	if useLambda { // only for lambda to test access restrictions
		var executeCreateTableAsInput models.ExecuteQueryInput
		executeCreateTableAsInput.UserID = aws.String(testUserID)
		executeCreateTableAsInput.DatabaseName = testutils.TestDb
		executeCreateTableAsInput.SQL = createTableAsSQL
		executeCreateTableAsOutput, err := runExecuteQuery(useLambda, &executeCreateTableAsInput)
		require.NoError(t, err) // NO LAMBDA ERROR here!
		require.Equal(t, models.QueryFailed, executeCreateTableAsOutput.Status)
		assert.True(t, strings.Contains(executeCreateTableAsOutput.SQLError, "Insufficient permissions"))
		assert.Equal(t, createTableAsSQL, executeCreateTableAsOutput.SQL)
	}

	//  -------- ExecuteAsyncQuery()

	var executeAsyncQueryInput models.ExecuteAsyncQueryInput
	executeAsyncQueryInput.UserID = aws.String(testUserID)
	executeAsyncQueryInput.DatabaseName = testutils.TestDb
	executeAsyncQueryInput.SQL = testSQL
	executeAsyncQueryOutput, err := runExecuteAsyncQuery(useLambda, &executeAsyncQueryInput)
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

	//  -------- GetQueryResults() test paging

	var getQueryResultsInput models.GetQueryResultsInput
	getQueryResultsInput.QueryID = executeAsyncQueryOutput.QueryID
	getQueryResultsInput.PageSize = &maxRowsPerResult
	getQueryResultsOutput, err := runGetQueryResults(useLambda, &getQueryResultsInput)
	require.NoError(t, err)

	if getQueryResultsOutput.Status == models.QuerySucceeded {
		resultRowCount := 0

		// -1 because header is removed
		expectedRowCount := int(maxRowsPerResult) - 1
		require.Equal(t, expectedRowCount, len(getQueryResultsOutput.ResultsPage.Rows))
		checkQueryResults(t, expectedRowCount, 0, getQueryResultsOutput.ResultsPage.Rows)
		resultRowCount += expectedRowCount

		for getQueryResultsOutput.ResultsPage.PaginationToken != nil { // when done this is nil
			getQueryResultsInput.PaginationToken = getQueryResultsOutput.ResultsPage.PaginationToken
			getQueryResultsOutput, err = runGetQueryResults(useLambda, &getQueryResultsInput)
			require.NoError(t, err)
			if getQueryResultsOutput.ResultsPage.NumRows > 0 {
				expectedRowCount = int(maxRowsPerResult)
				// the last page will have 1 less because we remove the header in the first page
				if resultRowCount+len(getQueryResultsOutput.ResultsPage.Rows) == testutils.TestTableDataNrows {
					expectedRowCount--
				}
				require.Equal(t, expectedRowCount, len(getQueryResultsOutput.ResultsPage.Rows))
				checkQueryResults(t, expectedRowCount, resultRowCount, getQueryResultsOutput.ResultsPage.Rows)
				resultRowCount += expectedRowCount
			}
		}
		require.Equal(t, testutils.TestTableDataNrows, resultRowCount)
	} else {
		assert.Fail(t, "GetQueryResults failed")
	}

	// -------- GetQueryResultsLink() for above query

	var getQueryResultsLinkInput models.GetQueryResultsLinkInput
	getQueryResultsLinkInput.QueryID = executeAsyncQueryOutput.QueryID

	getQueryResultsLinkOutput, err := runGetQueryResultsLink(useLambda, &getQueryResultsLinkInput)
	require.NoError(t, err)

	// try it ...
	resultsResponse, err := http.Get(getQueryResultsLinkOutput.PresignedLink)
	require.NoError(t, err)
	require.Equal(t, 200, resultsResponse.StatusCode)

	//  -------- ExecuteAsyncQuery() BAD SQL

	var executeBadAsyncQueryInput models.ExecuteAsyncQueryInput
	executeBadAsyncQueryInput.UserID = aws.String(testUserID)
	executeBadAsyncQueryInput.DatabaseName = testutils.TestDb
	executeBadAsyncQueryInput.SQL = badExecutingSQL
	executeBadAsyncQueryOutput, err := runExecuteAsyncQuery(useLambda, &executeBadAsyncQueryInput)
	require.NoError(t, err)

	for {
		time.Sleep(time.Second * 2)
		var getQueryStatusInput models.GetQueryStatusInput
		getQueryStatusInput.QueryID = executeBadAsyncQueryOutput.QueryID
		getQueryStatusOutput, err := runGetQueryStatus(useLambda, &getQueryStatusInput)
		require.NoError(t, err)
		if getQueryStatusOutput.Status != models.QueryRunning {
			require.Equal(t, models.QueryFailed, getQueryStatusOutput.Status)
			assert.True(t, strings.Contains(getQueryStatusOutput.SQLError, "does not exist"))
			assert.Equal(t, badExecutingSQL, getQueryStatusOutput.SQL)
			break
		}
	}

	// -------- GetQueryResultsLink() for above FAILED query

	var getBadAsyncQueryResultsLinkInput models.GetQueryResultsLinkInput
	getBadAsyncQueryResultsLinkInput.QueryID = executeBadAsyncQueryOutput.QueryID

	getBadAsyncQueryResultsLinkOutput, err := runGetQueryResultsLink(useLambda, &getBadAsyncQueryResultsLinkInput)
	require.NoError(t, err)
	require.Equal(t, models.QueryFailed, getBadAsyncQueryResultsLinkOutput.Status)
	assert.Equal(t, "results not available", getBadAsyncQueryResultsLinkOutput.SQLError)

	//  -------- StopQuery()

	var executeStopQueryInput models.ExecuteAsyncQueryInput
	executeStopQueryInput.DatabaseName = testutils.TestDb
	executeStopQueryInput.SQL = testSQL
	executeStopQueryOutput, err := runExecuteAsyncQuery(useLambda, &executeStopQueryInput)
	require.NoError(t, err)

	var stopQueryInput models.StopQueryInput
	stopQueryInput.QueryID = executeStopQueryOutput.QueryID
	_, err = runStopQuery(useLambda, &stopQueryInput)
	require.NoError(t, err)

	for {
		time.Sleep(time.Second * 2)
		var getQueryStatusInput models.GetQueryStatusInput
		getQueryStatusInput.QueryID = executeStopQueryOutput.QueryID
		getQueryStatusOutput, err := runGetQueryStatus(useLambda, &getQueryStatusInput)
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
			          queryDone(userData: "testUserData") {
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
			             "userData": "testUserData",
			             "queryId": "4c223d6e-a41a-418f-b97b-b01f044cbdc9",
			             "workflowId": "arn:aws:states:us-east-2:050603629990:execution:panther-athena-workflow:cf56beb0-7493-42ae-a9fd-a024812b8eac"
			           }
			          }
			        }

			     NOTE: the UI should call the lambda panther-athena-api:ExecuteAsyncQueryNotify as below and set up
			     a subscription filtering by user id (or session id). When the query finishes appsync will be notified.
			     UI should use the queryId to call panther-athena-api:GetQueryResults to display results.
	*/

	userData := "testUserData" // this is expected to be passed all the way through the workflow, validations will enforce

	var executeAsyncQueryNotifyInput models.ExecuteAsyncQueryNotifyInput
	executeAsyncQueryNotifyInput.UserID = aws.String(testUserID)
	executeAsyncQueryNotifyInput.DatabaseName = testutils.TestDb
	executeAsyncQueryNotifyInput.SQL = testSQL
	executeAsyncQueryNotifyInput.LambdaName = "panther-athena-api"
	executeAsyncQueryNotifyInput.MethodName = "notifyAppSync"
	executeAsyncQueryNotifyInput.UserData = userData
	executeAsyncQueryNotifyOutput, err := runExecuteAsyncQueryNotify(useLambda, &executeAsyncQueryNotifyInput)
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
		printAPI(getDatabasesInput, getDatabasesOutput)
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
		printAPI(getTablesInput, getTablesOutput)
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
		printAPI(getTablesDetailInput, getTablesDetailOutput)
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
		printAPI(executeQueryInput, executeQueryOutput)
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
		printAPI(executeAsyncQueryInput, executeAsyncQueryOutput)
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
		printAPI(executeAsyncQueryNotifyInput, executeAsyncQueryNotifyOutput)
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
		printAPI(getQueryStatusInput, getQueryStatusOutput)
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
		printAPI(getQueryResultsInput, getQueryResultsOutput)
		return getQueryResultsOutput, err
	}
	return api.GetQueryResults(input)
}

func runGetQueryResultsLink(useLambda bool, input *models.GetQueryResultsLinkInput) (*models.GetQueryResultsLinkOutput, error) {
	if useLambda {
		var getQueryResultsLinkInput = struct {
			GetQueryResultsLink *models.GetQueryResultsLinkInput
		}{
			input,
		}
		var getQueryResultsLinkOutput *models.GetQueryResultsLinkOutput
		err := genericapi.Invoke(lambdaClient, "panther-athena-api", getQueryResultsLinkInput, &getQueryResultsLinkOutput)
		printAPI(getQueryResultsLinkInput, getQueryResultsLinkOutput)
		return getQueryResultsLinkOutput, err
	}
	return api.GetQueryResultsLink(input)
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
		printAPI(stopQueryInput, stopQueryOutput)
		return stopQueryOutput, err
	}
	return api.StopQuery(input)
}

func checkQueryResults(t *testing.T, expectedRowCount, offset int, rows []*models.Row) {
	require.Equal(t, expectedRowCount, len(rows))
	for i := 0; i < len(rows); i++ {
		require.Equal(t, strconv.Itoa(i+offset), rows[i].Columns[0].Value)
		require.Equal(t, "NULL", rows[i].Columns[1].Value)
		require.Equal(t, testutils.TestEventTime, rows[i].Columns[2].Value)
	}
}

// useful to share examples of json APi usage
func printAPI(input, output interface{}) {
	if !printJSON {
		return
	}
	inputJSON, _ := json.MarshalIndent(input, "", "   ")
	outputJSON, _ := json.MarshalIndent(output, "", "   ")
	fmt.Printf("\nrequest:\n%s\nreply:\n%s\n", string(inputJSON), string(outputJSON))
}
