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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsbatch/s3batch"
	"github.com/panther-labs/panther/pkg/genericapi"
)

const (
	testBucketPrefix = "panther-athena-api-processeddata-test-"
	testDb           = "panther_athena_api_test_db"
	testTable        = "panther_athena_test_table"

	badSQL = `select * from nosuchtable`
)

var (
	integrationTest bool

	api = API{}

	s3Client *s3.S3

	testBucket        string
	testPartitionName = "part"
	testPartition     = "foo"
	testKey           = testPartitionName + "=" + testPartition + "/testdata.json"

	columns = []*glue.Column{
		{
			Name:    aws.String("col1"),
			Type:    aws.String("int"),
			Comment: aws.String("this is a column"),
		},
	}
	partitions = []*glue.Column{
		{
			Name:    aws.String(testPartitionName),
			Type:    aws.String("string"),
			Comment: aws.String("this is a partition"),
		},
	}

	nrows = 10
	row   = `{"col1": 1}`
	rows  []string

	testSQL = `select * from ` + testTable

	maxRowsPerResult int64 = 1 // force pagination to test
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		SessionInit()
		lambdaClient = lambda.New(awsSession)
		s3Client = s3.New(awsSession)
		testBucket = testBucketPrefix + time.Now().Format("20060102150405")

		for i := 0; i < nrows; i++ {
			rows = append(rows, row)
		}
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
	setupTables(t)
	defer func() {
		removeTables(t)
	}()

	// -------- GetDatabases()

	// list
	getDatabasesInput := &models.GetDatabasesInput{}
	getDatabasesOutput, err := runGetDatabases(useLambda, getDatabasesInput)
	require.NoError(t, err)
	foundDB := false
	for _, db := range getDatabasesOutput.Databases {
		if db.Name == testDb {
			foundDB = true
		}
	}
	require.True(t, foundDB)

	// specific lookup
	getDatabasesInput = &models.GetDatabasesInput{
		Name: aws.String(testDb),
	}
	getDatabasesOutput, err = runGetDatabases(useLambda, getDatabasesInput)
	require.NoError(t, err)
	require.Equal(t, 1, len(getDatabasesOutput.Databases))
	require.Equal(t, testDb, getDatabasesOutput.Databases[0].Name)

	// -------- GetTables()

	getTablesIntput := &models.GetTablesInput{
		DatabaseName:  testDb,
		OnlyPopulated: true,
	}
	getTablesOutput, err := runGetTables(useLambda, getTablesIntput)
	require.NoError(t, err)
	require.Equal(t, 1, len(getTablesOutput.Tables))
	checkTableDetail(t, getTablesOutput.Tables)

	// -------- GetTablesDetail()

	getTablesDetailInput := &models.GetTablesDetailInput{
		DatabaseName: testDb,
		Names:        []string{testTable},
	}
	getTablesDetailOutput, err := runGetTablesDetail(useLambda, getTablesDetailInput)
	require.NoError(t, err)
	checkTableDetail(t, getTablesDetailOutput.Tables)

	// -------- ExecuteQuery()

	executeQueryInput := &models.ExecuteQueryInput{
		DatabaseName: testDb,
		SQL:          testSQL,
	}
	executeQueryOutput, err := runExecuteQuery(useLambda, executeQueryInput)
	require.NoError(t, err)
	assert.Equal(t, "", executeQueryOutput.Message)
	require.Equal(t, models.QuerySucceeded, executeQueryOutput.Status)
	checkQueryResults(t, true, len(rows)+1, executeQueryOutput.ResultsPage.Rows)

	// -------- ExecuteQuery() BAD SQL

	executeBadQueryInput := &models.ExecuteQueryInput{
		DatabaseName: testDb,
		SQL:          badSQL,
	}
	executeBadQueryOutput, err := runExecuteQuery(useLambda, executeBadQueryInput)
	require.NoError(t, err) // NO LAMBDA ERROR here!
	require.Equal(t, models.QueryFailed, executeBadQueryOutput.Status)
	require.True(t, strings.Contains(executeBadQueryOutput.Message, "does not exist"))
	require.Equal(t, badSQL, executeBadQueryOutput.SQL)

	//  -------- ExecuteAsyncQuery()

	executeAsyncQueryInput := &models.ExecuteAsyncQueryInput{
		DatabaseName: testDb,
		SQL:          testSQL,
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
		QueryID:  executeAsyncQueryOutput.QueryID,
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
		require.Equal(t, len(rows)+1, resultCount) // since we page 1 at a time and have a header
	} else {
		assert.Fail(t, "GetQueryResults failed")
	}

	//  -------- ExecuteAsyncQuery() BAD SQL

	executeBadAsyncQueryInput := &models.ExecuteAsyncQueryInput{
		DatabaseName: testDb,
		SQL:          badSQL,
	}
	executeBadAsyncQueryOutput, err := runExecuteAsyncQuery(useLambda, executeBadAsyncQueryInput)
	require.NoError(t, err)

	for {
		time.Sleep(time.Second * 10)
		getBadQueryStatusInput := &models.GetQueryStatusInput{
			QueryID: executeBadAsyncQueryOutput.QueryID,
		}
		getBadQueryStatusOutput, err := runGetQueryStatus(useLambda, getBadQueryStatusInput)
		require.NoError(t, err)
		if getBadQueryStatusOutput.Status != models.QueryRunning {
			require.Equal(t, models.QueryFailed, getBadQueryStatusOutput.Status)
			require.True(t, strings.Contains(getBadQueryStatusOutput.Message, "does not exist"))
			require.Equal(t, badSQL, getBadQueryStatusOutput.SQL)
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
			DatabaseName: testDb,
			SQL:          testSQL,
		},
		LambdaInvoke: models.LambdaInvoke{
			LambdaName: "panther-athena-api",
			MethodName: "notifyAppSync",
		},
		UserData: userData,
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

func checkTableDetail(t *testing.T, tables []*models.TableDetail) {
	require.Equal(t, testTable, tables[0].Name)
	require.Equal(t, len(columns)+len(partitions), len(tables[0].Columns))
	require.Equal(t, *columns[0].Name, tables[0].Columns[0].Name)
	require.Equal(t, *columns[0].Type, tables[0].Columns[0].Type)
	require.Equal(t, *columns[0].Comment, *tables[0].Columns[0].Description)
	require.Equal(t, *partitions[0].Name, tables[0].Columns[1].Name)
	require.Equal(t, *partitions[0].Type, tables[0].Columns[1].Type)
	require.Equal(t, *partitions[0].Comment, *tables[0].Columns[1].Description)
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

func setupTables(t *testing.T) {
	removeTables(t) // in case of left over
	addTables(t)
}

func addTables(t *testing.T) {
	var err error

	bucketInput := &s3.CreateBucketInput{Bucket: aws.String(testBucket)}
	_, err = s3Client.CreateBucket(bucketInput)
	require.NoError(t, err)

	dbInput := &glue.CreateDatabaseInput{
		DatabaseInput: &glue.DatabaseInput{
			Name: aws.String(testDb),
		},
	}
	_, err = glueClient.CreateDatabase(dbInput)
	require.NoError(t, err)

	storageDecriptor := &glue.StorageDescriptor{ // configure as JSON
		Columns:      columns,
		Location:     aws.String("s3://" + testBucket + "/"),
		InputFormat:  aws.String("org.apache.hadoop.mapred.TextInputFormat"),
		OutputFormat: aws.String("org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"),
		SerdeInfo: &glue.SerDeInfo{
			SerializationLibrary: aws.String("org.openx.data.jsonserde.JsonSerDe"),
			Parameters: map[string]*string{
				"serialization.format": aws.String("1"),
				"case.insensitive":     aws.String("TRUE"), // treat as lower case
			},
		},
	}

	tableInput := &glue.CreateTableInput{
		DatabaseName: aws.String(testDb),
		TableInput: &glue.TableInput{
			Name:              aws.String(testTable),
			PartitionKeys:     partitions,
			StorageDescriptor: storageDecriptor,
			TableType:         aws.String("EXTERNAL_TABLE"),
		},
	}
	_, err = glueClient.CreateTable(tableInput)
	require.NoError(t, err)

	putInput := &s3.PutObjectInput{
		Body:   strings.NewReader(strings.Join(rows, "\n")),
		Bucket: &testBucket,
		Key:    &testKey,
	}
	_, err = s3Client.PutObject(putInput)
	require.NoError(t, err)
	time.Sleep(time.Second / 4) // short pause since S3 is eventually consistent

	_, err = glueClient.CreatePartition(&glue.CreatePartitionInput{
		DatabaseName: aws.String(testDb),
		TableName:    aws.String(testTable),
		PartitionInput: &glue.PartitionInput{
			StorageDescriptor: storageDecriptor,
			Values: []*string{
				aws.String(testPartition),
			},
		},
	})
	require.NoError(t, err)
}

func removeTables(t *testing.T) {
	// best effort, no error checks

	tableInput := &glue.DeleteTableInput{
		DatabaseName: aws.String(testDb),
		Name:         aws.String(testTable),
	}
	glueClient.DeleteTable(tableInput) // nolint (errcheck)

	dbInput := &glue.DeleteDatabaseInput{
		Name: aws.String(testDb),
	}
	glueClient.DeleteDatabase(dbInput) // nolint (errcheck)

	removeBucket(testBucket)
}

func removeBucket(bucketName string) {
	input := &s3.ListObjectVersionsInput{Bucket: &bucketName}
	var objectVersions []*s3.ObjectIdentifier

	// List all object versions (including delete markers)
	err := s3Client.ListObjectVersionsPages(input, func(page *s3.ListObjectVersionsOutput, lastPage bool) bool {
		for _, marker := range page.DeleteMarkers {
			objectVersions = append(objectVersions, &s3.ObjectIdentifier{
				Key: marker.Key, VersionId: marker.VersionId})
		}

		for _, version := range page.Versions {
			objectVersions = append(objectVersions, &s3.ObjectIdentifier{
				Key: version.Key, VersionId: version.VersionId})
		}
		return false
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoSuchBucket" {
			return
		}
	}

	err = s3batch.DeleteObjects(s3Client, 2*time.Minute, &s3.DeleteObjectsInput{
		Bucket: &bucketName,
		Delete: &s3.Delete{Objects: objectVersions},
	})
	if err != nil {
		return
	}
	time.Sleep(time.Second / 4) // short pause since S3 is eventually consistent to avoid next call from failing
	if _, err = s3Client.DeleteBucket(&s3.DeleteBucketInput{Bucket: &bucketName}); err != nil {
		return
	}
}
