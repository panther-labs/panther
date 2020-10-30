package awsathena

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
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// this needs to match the CF where we create the WG in bootstrap_gateway.yml
	workgroup = "Panther"
)

var (
	integrationTest bool
	awsSession      *session.Session
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		awsSession = session.Must(session.NewSession())
	}
	os.Exit(m.Run())
}

func TestIntegrationAthenaQuery(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	queryResult, err := RunQuery(athena.New(awsSession), workgroup, "panther_logs", "select 1 as c")
	require.NoError(t, err)
	expectedCol := "c"
	expectedResult := "1"
	rows := queryResult.ResultSet.Rows
	require.Equal(t, 2, len(rows))
	require.Equal(t, expectedCol, *rows[0].Data[0].VarCharValue)
	require.Equal(t, expectedResult, *rows[1].Data[0].VarCharValue)
}

func TestIntegrationAthenaQueryBadSQLParse(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	_, err := RunQuery(athena.New(awsSession), workgroup, "panther_logs", "wwwww")
	require.Error(t, err)
}

func TestIntegrationAthenaQueryBadSQLExecution(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	// to force an execution failure we need to create an error AFTER the SQL planner, create a table with a non-existent bucket
	badTable := `panther_temp.test_table_with_bad_s3path`
	_, err := RunQuery(athena.New(awsSession), workgroup, "panther_logs",
		`create external table if not exists `+badTable+` (col1 string) location 's3://panthernosuchbucket/nosuchtable/'`)
	require.NoError(t, err)

	// now query bad table
	_, err = RunQuery(athena.New(awsSession), workgroup, "panther_logs", `select * from `+badTable)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "query execution failed:")) // confirm we came thru correct code path

	// clean up (best effort)
	_, _ = RunQuery(athena.New(awsSession), workgroup, "panther_logs", `drop table `+badTable)
}

func TestIntegrationAthenaQueryStop(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	athenaClient := athena.New(awsSession)

	startOutput, err := StartQuery(athenaClient, workgroup, "panther_logs", "select 1 as c")
	require.NoError(t, err)

	_, err = StopQuery(athenaClient, *startOutput.QueryExecutionId)
	require.NoError(t, err)

	statusOutput, err := Status(athenaClient, *startOutput.QueryExecutionId)
	require.NoError(t, err)
	require.Equal(t, athena.QueryExecutionStateCancelled, *statusOutput.QueryExecution.Status.State)
}
