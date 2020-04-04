package awsathena

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
	var err error
	queryResult, err := RunQuery(athena.New(awsSession), "panther_tables", "select 1 as c", nil)
	require.NoError(t, err)
	expectedCol := "c"
	expectedResult := "1"
	rows := queryResult.ResultSet.Rows
	require.Equal(t, 2, len(rows))
	require.Equal(t, expectedCol, *rows[0].Data[0].VarCharValue)
	require.Equal(t, expectedResult, *rows[1].Data[0].VarCharValue)
}
