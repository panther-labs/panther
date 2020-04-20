package process

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
	"time"

	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sfn"
	"github.com/aws/aws-sdk-go/service/sfn/sfniface"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/core/database_api/athena/testutils"
	"github.com/panther-labs/panther/pkg/awsathena"
)

const (
	TestHistoricalBucketPrefix = "panther-datacatalog-updater-test-"
)

var (
	integrationTest bool

	sfnClient    sfniface.SFNAPI
	s3Client     s3iface.S3API
	athenaClient athenaiface.AthenaAPI

	TestHistoricalBucket string
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		SessionInit()
		sfnClient = sfn.New(awsSession)
		s3Client = s3.New(awsSession)
		athenaClient = athena.New(awsSession)

		ctasDelay = 0 // no delay

		TestHistoricalBucket = TestHistoricalBucketPrefix + time.Now().Format("20060102150405")
	}
	os.Exit(m.Run())
}

func TestGenerateParquet(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	testutils.SetupTables(t, glueClient, s3Client)
	testutils.CreateBucket(t, s3Client, TestHistoricalBucket)
	defer func() {
		testutils.RemoveTables(t, glueClient, s3Client)
		testutils.RemoveBucket(s3Client, TestHistoricalBucket)
	}()

	envConfig.HistoricalDataBucket = testutils.TestBucket

	// execute CTAS via Athena api Step Function
	input := &GenerateParquetInput{
		DatabaseName:         testutils.TestDb,
		TableName:            testutils.TestTable,
		HistoricalBucketName: TestHistoricalBucket,
		PartitionHour:        testutils.TestPartitionTime,
	}
	workflowID, err := GenerateParquet(input)
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
	sqlQuery := `select * from ` + testutils.TestTable + ` order by col1 asc`
	_, err = awsathena.RunQuery(athenaClient, testutils.TestDb, sqlQuery, nil)
	require.NoError(t, err)
}
