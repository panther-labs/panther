package main

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

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsglue"
	"github.com/panther-labs/panther/pkg/testutils"
)

var (
	integrationTest bool
	awsSession      *session.Session
	glueClient      *glue.Glue
	athenaClient    *athena.Athena
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		awsSession = session.Must(session.NewSession())
		glueClient = glue.New(awsSession)
		athenaClient = athena.New(awsSession)
	}
	os.Exit(m.Run())
}

func TestIntegrationAthenaAPI(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	// These tests ASSUME you have deployed Panther

	// -------- GetDatabases()

	var getDatabasesOutput *models.GetDatabasesOutput
	var getDatabasesInput = struct {
		GetDatabases *models.GetDatabasesInput
	}{
		&models.GetDatabasesInput{},
	}

	err := testutils.InvokeLambda(awsSession, "panther-athena-api", getDatabasesInput, &getDatabasesOutput)
	require.NoError(t, err)

	// look for expected database
	foundDatabase := false
	for _, db := range getDatabasesOutput.Databases {
		if db.DatabaseName == awsglue.LogProcessingDatabaseName {
			foundDatabase = true
		}
	}
	assert.True(t, foundDatabase)

	// -------- GetTables()

	var getTablesOutput *models.GetTablesOutput
	var getTablesInput = struct {
		GetTables *models.GetTablesInput
	}{
		&models.GetTablesInput{DatabaseName: awsglue.LogProcessingDatabaseName},
	}

	err = testutils.InvokeLambda(awsSession, "panther-athena-api", getTablesInput, &getTablesOutput)
	require.NoError(t, err)

	// look for expected table
	foundTable := false
	for _, table := range getTablesOutput.Tables {
		if table.DatabaseName == awsglue.LogProcessingDatabaseName && table.TableName == "aws_cloudtrail" {
			foundTable = true
		}
	}
	assert.True(t, foundTable)

	// -------- GetTablesDetail()

	var getTablesDetailOutput *models.GetTablesDetailOutput
	var getTablesDetailInput = struct {
		GetTablesDetail *models.GetTablesDetailInput
	}{
		&models.GetTablesDetailInput{
			DatabaseName: awsglue.LogProcessingDatabaseName,
			TableNames:   []string{"aws_cloudtrail"},
			HavingData:   true,
		},
	}

	err = testutils.InvokeLambda(awsSession, "panther-athena-api", getTablesDetailInput, &getTablesDetailOutput)
	require.NoError(t, err)

	// look for expected table and panther column
	foundTableDetail := false
	for _, table := range getTablesDetailOutput.TablesDetails {
		if table.DatabaseName == awsglue.LogProcessingDatabaseName &&
			table.TableName == "aws_cloudtrail" {

			for _, column := range table.Columns {
				if column.Name == "p_event_time" { // required field, must be there
					foundTableDetail = true
				}
			}
		}
	}
	assert.True(t, foundTableDetail)

	const nrows = 5
	const testSQL = `
WITH dataset AS (
 SELECT 1 as c
  UNION ALL
 SELECT 1 as c
  UNION ALL
 SELECT 1 as c
  UNION ALL
 SELECT 1 as c
  UNION ALL
 SELECT 1 as c
)
SELECT * FROM dataset
`

	// -------- DoQuery()

	var doQueryOutput *models.DoQueryOutput
	var doQueryInput = struct {
		DoQuery *models.DoQueryInput
	}{
		&models.DoQueryInput{
			DatabaseName: awsglue.LogProcessingDatabaseName,
			SQL:          testSQL,
		},
	}

	err = testutils.InvokeLambda(awsSession, "panther-athena-api", doQueryInput, &doQueryOutput)
	require.NoError(t, err)

	checkQueryResults(t, true, nrows+1, doQueryOutput.Rows) // has header

	//  -------- StartQuery()

	var startQueryOutput *models.StartQueryOutput
	var startQueryInput = struct {
		StartQuery *models.StartQueryInput
	}{
		&models.StartQueryInput{
			DatabaseName: awsglue.LogProcessingDatabaseName,
			SQL:          testSQL,
		},
	}

	err = testutils.InvokeLambda(awsSession, "panther-athena-api", startQueryInput, &startQueryOutput)
	require.NoError(t, err)

	if startQueryOutput.Status == models.QuerySucceeded {
		t.Log("StartQuery succeeded")
		checkQueryResults(t, true, nrows+1, startQueryOutput.Rows) // has header
	}

	//  -------- GetQueryStatus()

	var queryStatus string
	for {
		t.Log("QueryStatus polling query")
		time.Sleep(time.Second * 10)

		var getQueryStatusOutput *models.GetQueryStatusOutput
		var getQueryStatusInput = struct {
			GetQueryStatus *models.GetQueryStatusInput
		}{
			&models.GetQueryStatusInput{
				QueryID: startQueryOutput.QueryID,
			},
		}

		err = testutils.InvokeLambda(awsSession, "panther-athena-api", getQueryStatusInput, &getQueryStatusOutput)
		require.NoError(t, err)

		if getQueryStatusOutput.Status != models.QueryRunning {
			queryStatus = getQueryStatusOutput.Status
			break
		}
	}
	t.Log("QueryStatus returned", queryStatus)

	//  -------- GetQueryResults()

	var maxResults int64 = 1 // to force paging
	var getQueryResultsOutput *models.GetQueryResultsOutput
	var getQueryResultsInput = struct {
		GetQueryResults *models.GetQueryResultsInput
	}{
		&models.GetQueryResultsInput{
			QueryID:    startQueryOutput.QueryID,
			MaxResults: &maxResults,
		},
	}

	err = testutils.InvokeLambda(awsSession, "panther-athena-api", getQueryResultsInput, &getQueryResultsOutput)
	require.NoError(t, err)

	if getQueryResultsOutput.Status == models.QuerySucceeded {
		resultCount := 0
		t.Log("GetQueryResults succeeded")
		checkQueryResults(t, true, int(maxResults), getQueryResultsOutput.Rows)
		resultCount++

		t.Log("Test pagination")
		for getQueryResultsOutput.NumRows > 0 { // when done this is 0
			getQueryResultsInput.GetQueryResults.PaginationToken = getQueryResultsOutput.PaginationToken
			err = testutils.InvokeLambda(awsSession, "panther-athena-api", getQueryResultsInput, &getQueryResultsOutput)
			require.NoError(t, err)
			if getQueryResultsOutput.NumRows > 0 { // not finished paging
				checkQueryResults(t, false, int(maxResults), getQueryResultsOutput.Rows)
				resultCount++
			}
		}
		require.Equal(t, nrows+1, resultCount) // since we pace 1 at a time and have a header
	} else {
		t.Log("GetQueryResults failed")
	}
}

func checkQueryResults(t *testing.T, hasHeader bool, expectedRowCount int, rows []*models.Row) {
	require.Equal(t, expectedRowCount, len(rows))
	i := 0
	nResults := len(rows)
	if hasHeader {
		require.Equal(t, "c", rows[0].Columns[0].Value) // header
		i++
	}
	for ; i < nResults; i++ {
		require.Equal(t, "1", rows[i].Columns[0].Value)
	}
}
