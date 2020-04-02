package driver

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

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsbatch/s3batch"
)

const (
	testBucketPrefix = "panther-athena-api-test-bucket-"
	testDb           = "panther_athena_api_test_db"
	testTable        = "panther_athena_test_table"
)

var (
	integrationTest bool
	awsSession      *session.Session
	glueClient      *glue.Glue
	athenaClient    *athena.Athena
	s3Client        *s3.S3

	testBucket string
	testKey    = "testdata.json"

	columns = []*glue.Column{
		{
			Name:    aws.String("col1"),
			Type:    aws.String("int"),
			Comment: aws.String("this is a description"),
		},
	}

	nrows = 10
	row   = `{"col1": 1}`
	rows  []string

	maxRowsPerResult int64 = 1 // force pagination to test
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		awsSession = session.Must(session.NewSession())
		glueClient = glue.New(awsSession)
		athenaClient = athena.New(awsSession)
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

	setupTables(t)
	defer func() {
		removeTables(t)
	}()

	// -------- GetDatabases()

	// list
	dbOutput, err := GetDatabases(glueClient, &models.GetDatabasesInput{})
	require.NoError(t, err)
	foundDB := false
	for _, db := range dbOutput.Databases {
		if db.DatabaseName == testDb {
			foundDB = true
		}
	}
	require.True(t, foundDB)

	// specific lookup
	dbOutput, err = GetDatabases(glueClient, &models.GetDatabasesInput{
		DatabaseName: testDb,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(dbOutput.Databases))
	require.Equal(t, testDb, dbOutput.Databases[0].DatabaseName)

	// -------- GetTables()

	tablesOutput, err := GetTables(glueClient, &models.GetTablesInput{
		DatabaseName: testDb,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(tablesOutput.Tables))
	require.Equal(t, testTable, tablesOutput.Tables[0].TableName)

	// -------- GetTablesDetail()

	tableOutput, err := GetTablesDetail(glueClient, &models.GetTablesDetailInput{
		DatabaseName: testDb,
		TableNames:   []string{testTable},
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(tableOutput.TablesDetails))
	require.Equal(t, testTable, tableOutput.TablesDetails[0].TableName)
	require.Equal(t, len(columns), len(tableOutput.TablesDetails[0].Columns))
	require.Equal(t, *columns[0].Name, tableOutput.TablesDetails[0].Columns[0].Name)
	require.Equal(t, *columns[0].Type, tableOutput.TablesDetails[0].Columns[0].Type)
	require.Equal(t, *columns[0].Comment, tableOutput.TablesDetails[0].Columns[0].Description)

	// -------- DoQuery()

	doQueryOutput, err := DoQuery(athenaClient, &models.DoQueryInput{
		DatabaseName: testDb,
		SQL:          `select * from ` + testTable,
	})
	require.NoError(t, err)
	checkQueryResults(t, true, len(rows)+1, doQueryOutput.Rows)

	//  -------- StartQuery()

	startQueryOutput, err := StartQuery(athenaClient, &models.StartQueryInput{
		DatabaseName: testDb,
		SQL:          `select * from ` + testTable,
		MaxResults:   &maxRowsPerResult,
	})
	require.NoError(t, err)
	if startQueryOutput.Status == models.QuerySucceeded {
		t.Log("StartQuery succeeded")
		checkQueryResults(t, true, int(maxRowsPerResult), startQueryOutput.Rows)
	}

	//  -------- GetQueryStatus()

	var queryStatus string
	for {
		t.Log("QueryStatus polling query")
		time.Sleep(time.Second * 10)
		getQueryStatusOutput, err := GetQueryStatus(athenaClient, &models.GetQueryStatusInput{
			QueryID: startQueryOutput.QueryID,
		})
		require.NoError(t, err)
		if getQueryStatusOutput.Status != models.QueryRunning {
			queryStatus = getQueryStatusOutput.Status
			break
		}
	}
	t.Log("QueryStatus returned", queryStatus)

	//  -------- GetQueryResults()

	getQueryResultsInput := &models.GetQueryResultsInput{
		QueryID:    startQueryOutput.QueryID,
		MaxResults: &maxRowsPerResult,
	}
	getQueryResultsOutput, err := GetQueryResults(athenaClient, getQueryResultsInput)
	require.NoError(t, err)

	if getQueryResultsOutput.Status == models.QuerySucceeded {
		resultCount := 0
		t.Log("GetQueryResults succeeded")
		checkQueryResults(t, true, int(maxRowsPerResult), getQueryResultsOutput.Rows)
		resultCount++

		t.Log("Test pagination")
		for getQueryResultsOutput.NumRows > 0 { // when done this is 0
			getQueryResultsInput.PaginationToken = getQueryResultsOutput.PaginationToken
			getQueryResultsOutput, err = GetQueryResults(athenaClient, getQueryResultsInput)
			require.NoError(t, err)
			if getQueryResultsOutput.NumRows > 0 { // not finished paging
				checkQueryResults(t, false, int(maxRowsPerResult), getQueryResultsOutput.Rows)
				resultCount++
			}
		}
		require.Equal(t, len(rows)+1, resultCount) // since we pace 1 at a time and have a header
	} else {
		t.Log("GetQueryResults failed")
	}
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

	tableInput := &glue.CreateTableInput{
		DatabaseName: aws.String(testDb),
		TableInput: &glue.TableInput{
			Name: aws.String(testTable),
			StorageDescriptor: &glue.StorageDescriptor{ // configure as JSON
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
			},
			TableType: aws.String("EXTERNAL_TABLE"),
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
