package awsglue

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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
)

const (
	testBucket       = "panther-public-cloudformation-templates" // this is a public Panther bucket with CF files we can use to list
	testBucketRegion = "us-west-2"                               // region of above bucket
	testDB           = "panther_glue_test_db"
	testTable        = "panther_glue_test_table"
)

type testEvent struct {
	Col1 int `description:"test field"`
}

type testEventModified struct {
	Col1 int `description:"test field"`
	Col2 int `description:"test field"`
}

var (
	integrationTest bool
	awsSession      *session.Session
	glueClient      *glue.Glue
	s3Client        *s3.S3
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

	// this is the table created in setupTables
	originalTable := NewGlueTableMetadata(pantherdb.RuleMatchDatabase, testTable, "test table", GlueTableHourly, &testEvent{})
	// overwriting default database
	originalTable.databaseName = testDB

	// get the meta data, note we update the schema from the one used in setupTables()
	table := NewGlueTableMetadata(pantherdb.RuleMatchDatabase, testTable, "test table", GlueTableHourly, &testEventModified{})
	// overwriting default database
	table.databaseName = testDB

	// this has been already created in setupTables(), this tests updating table
	err = table.CreateOrUpdateTable(glueClient, testBucket)
	require.NoError(t, err)

	// confirm that the new schema has been applied
	getTableOutput, err := GetTable(glueClient, table.databaseName, table.tableName)
	require.NoError(t, err)
	require.Equal(t, "col2", *getTableOutput.Table.StorageDescriptor.Columns[1].Name) // what we added

	getPartitionOutput, err := table.GetPartition(glueClient, refTime)
	require.NoError(t, err)
	assert.Nil(t, getPartitionOutput) // should not be there yet

	expectedPath := "s3://" + testBucket + "/rules/" + testTable + "/year=2020/month=01/day=03/hour=01/"
	created, err := table.CreateJSONPartition(glueClient, refTime)
	require.NoError(t, err)
	assert.True(t, created)
	partitionLocation := getPartitionLocation(t, []string{"2020", "01", "03", "01",
		strconv.Itoa(int(time.Date(2020, 1, 3, 1, 0, 0, 0, time.UTC).Unix()))})
	require.Equal(t, expectedPath, *partitionLocation)

	getPartitionOutput, err = table.GetPartition(glueClient, refTime)
	require.NoError(t, err)
	assert.NotNil(t, getPartitionOutput) // should be there now

	// sync it (which does an update of schema)
	var startDate time.Time // default unset
	_, err = table.SyncPartitions(glueClient, s3Client, startDate, nil)
	require.NoError(t, err)

	partitionLocation = getPartitionLocation(t, []string{"2020", "01", "03", "01",
		strconv.Itoa(int(time.Date(2020, 1, 3, 1, 0, 0, 0, time.UTC).Unix()))})
	require.Equal(t, expectedPath, *partitionLocation)

	_, err = table.deletePartition(glueClient, refTime)
	require.NoError(t, err)
	partitionLocation = getPartitionLocation(t, []string{"2020", "01", "03", "01",
		strconv.Itoa(int(time.Date(2020, 1, 3, 1, 0, 0, 0, time.UTC).Unix()))})
	require.Nil(t, partitionLocation)
}

func setupTables(t *testing.T) {
	removeTables(t) // in case of left over
	addTables(t)
}

func addTables(t *testing.T) {
	_, err := CreateDatabase(glueClient, testDB, "integration test database")
	require.NoError(t, err)

	gm := NewGlueTableMetadata(pantherdb.RuleMatchDatabase, testTable, "test table", GlueTableHourly, &testEvent{})
	// overwriting default database
	gm.databaseName = testDB
	err = gm.CreateOrUpdateTable(glueClient, testBucket)
	require.NoError(t, err)
}

func removeTables(t *testing.T) {
	// best effort, no error checks
	DeleteTable(glueClient, testDB, testTable) // nolint (errcheck)
	DeleteDatabase(glueClient, testDB)         // nolint (errcheck)
}

// Fetches the location of a partition. Return nil it the partition doesn't exist
func getPartitionLocation(t *testing.T, partitionValues []string) *string {
	response, err := GetPartition(glueClient, testDB, testTable, aws.StringSlice(partitionValues))
	var awsErr awserr.Error
	if errors.As(err, &awsErr) && awsErr.Code() == glue.ErrCodeEntityNotFoundException {
		return nil
	}
	require.NoError(t, err)
	return response.Partition.StorageDescriptor.Location
}
