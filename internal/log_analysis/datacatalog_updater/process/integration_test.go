package process

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/aws/aws-sdk-go/service/sfn/sfniface"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/core/database_api/athena/testutils"
)

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

var (
	integrationTest bool

	sfnClient sfniface.SFNAPI
	s3Client  s3iface.S3API
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		SessionInit()
		sfnClient = sfn.New(awsSession)
		s3Client = s3.New(awsSession)
	}
	os.Exit(m.Run())
}

func TestGenerateParquet(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	testutils.SetupTables(t, glueClient, s3Client)
	defer func() {
		// testutils.RemoveTables(t, glueClient, s3Client)
	}()

	// execute CTAS via Athena api Step Function
	workflowID, err := GenerateParquet(testutils.TestDb, testutils.TestTable,
		testutils.TestBucket, testutils.TestPartitionTime)
	require.NoError(t, err)

	// wait for workflow to finish
	for {
		time.Sleep(time.Second * 10)
		descExecutionInput := &sfn.DescribeExecutionInput{
			ExecutionArn: &workflowID,
		}
		descExecutionOutput, err := sfnClient.DescribeExecution(descExecutionInput)
		require.NoError(t, err)
		if *descExecutionOutput.Status != sfn.ExecutionStatusRunning {
			require.Equal(t, sfn.ExecutionStatusSucceeded, *descExecutionOutput.Status)
			break
		}
	}

	// do a query over the parquet
}
