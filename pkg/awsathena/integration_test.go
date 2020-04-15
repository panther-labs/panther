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
	"github.com/stretchr/testify/require"
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

	queryResult, err := RunQuery(athena.New(awsSession), "panther_logs", "select 1 as c", nil)
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

	_, err := RunQuery(athena.New(awsSession), "panther_logs", "wwwww", nil)
	require.Error(t, err)
}

func TestIntegrationAthenaQueryBadSQLExecution(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	_, err := RunQuery(athena.New(awsSession), "panther_logs", "select * from idonotexist", nil)
	require.Error(t, err)
}

func TestIntegrationAthenaQueryStop(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	athenaClient := athena.New(awsSession)

	startOutput, err := StartQuery(athenaClient, "panther_logs", "select 1 as c", nil)
	require.NoError(t, err)

	_, err = StopQuery(athenaClient, *startOutput.QueryExecutionId)
	require.NoError(t, err)

	statusOutput, err := Status(athenaClient, *startOutput.QueryExecutionId)
	require.NoError(t, err)
	require.Equal(t, athena.QueryExecutionStateCancelled, *statusOutput.QueryExecution.Status.State)
}
