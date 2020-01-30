package awsglue

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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testBucket = "panther_glue_test_bucket"
	testDb     = "panther_glue_test_db"
	testTable  = "panther_glue_test_table"
)

type testEvent struct {
	Col1 int
}

var (
	integrationTest bool
	awsSession      *session.Session
	glueClient      *glue.Glue

	columns = []*glue.Column{
		{
			Name: aws.String("Col1"),
			Type: aws.String("int"),
		},
	}

	partitionKeys = []*glue.Column{
		{
			Name: aws.String("year"),
			Type: aws.String("int"),
		},
		{
			Name: aws.String("month"),
			Type: aws.String("int"),
		},
		{
			Name: aws.String("day"),
			Type: aws.String("int"),
		},
		{
			Name: aws.String("hour"),
			Type: aws.String("int"),
		},
	}
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		awsSession = session.Must(session.NewSession())
		glueClient = glue.New(awsSession)
	}
	os.Exit(m.Run())
}

func TestIntegrationGlueMetadataPartitions(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	var err error

	refTime := time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)

	setupTables(t)
	defer func() {
		removeTables(t)
	}()

	gm, err := NewGlueMetadata(testDb, testTable, "test table", GlueTableHourly, false, &testEvent{})
	require.NoError(t, err)

	expectedPath := "s3://" + testBucket + "/logs/" + testTable + "/year=2020/month=01/day=03/hour=01/"
	err = gm.CreateJSONPartition(glueClient, testBucket, refTime)
	require.NoError(t, err)

	// do it again, should fail
	err = gm.CreateJSONPartition(glueClient, testBucket, refTime)
	require.Error(t, err)

	partitionInfo, err := gm.GetPartition(glueClient, refTime)
	require.NoError(t, err)
	assert.Equal(t, expectedPath, *partitionInfo.Partition.StorageDescriptor.Location)

	_, err = gm.DeletePartition(glueClient, refTime)
	require.NoError(t, err)

	// ensure deleted
	_, err = gm.GetPartition(glueClient, refTime)
	require.Error(t, err)
}

func setupTables(t *testing.T) {
	removeTables(t) // in case of left over
	addTables(t)
}

func addTables(t *testing.T) {
	var err error

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
			Name:          aws.String(testTable),
			PartitionKeys: partitionKeys,
			StorageDescriptor: &glue.StorageDescriptor{ // configure as JSON
				Columns:      columns,
				Location:     aws.String("bar"),
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
}
