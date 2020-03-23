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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
)

const (
	testBucket       = "panther-public-cloudformation-templates" // this is a public Panther bucket with CF files we can use to list
	testBucketRegion = "us-west-2"                               // region of above bucket
	testDb           = "panther_glue_test_db"
	testTable        = "panther_glue_test_table"
)

type testEvent struct {
	Col1 int
}

var (
	integrationTest bool
	awsSession      *session.Session
	glueClient      *glue.Glue
	s3Client        *s3.S3

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
		awsSession = session.Must(session.NewSession(aws.NewConfig().WithRegion(testBucketRegion)))
		glueClient = glue.New(awsSession)
		s3Client = s3.New(awsSession)
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

	gm := NewGlueTableMetadata(models.LogData, testTable, "test table", GlueTableHourly, &testEvent{})
	// overwriting default database
	gm.databaseName = testDb

	expectedPath := "s3://" + testBucket + "/logs/" + testTable + "/year=2020/month=01/day=03/hour=01/"
	err = gm.CreateJSONPartition(glueClient, refTime)
	require.NoError(t, err)
	partitionLocation := getPartitionLocation(t, []string{"2020", "01", "03", "01"})
	require.Equal(t, expectedPath, *partitionLocation)

	// sync it (which does an update of schema)
	var startDate time.Time // default unset
	err = gm.SyncPartitions(glueClient, s3Client, startDate)
	require.NoError(t, err)

	partitionLocation = getPartitionLocation(t, []string{"2020", "01", "03", "01"})
	require.Equal(t, expectedPath, *partitionLocation)

	_, err = gm.deletePartition(glueClient, refTime)
	require.NoError(t, err)
	partitionLocation = getPartitionLocation(t, []string{"2020", "01", "03", "01"})
	require.Nil(t, partitionLocation)
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
				Location:     aws.String("s3://" + testBucket + "/logs/" + testTable),
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

// Fetches the location of a partition. Return nil it the partition doesn't exist
func getPartitionLocation(t *testing.T, partitionValues []string) *string {
	response, err := glueClient.GetPartition(&glue.GetPartitionInput{
		DatabaseName:    aws.String(testDb),
		PartitionValues: aws.StringSlice(partitionValues),
		TableName:       aws.String(testTable),
	})
	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == glue.ErrCodeEntityNotFoundException {
		return nil
	}
	require.NoError(t, err)
	return response.Partition.StorageDescriptor.Location
}
