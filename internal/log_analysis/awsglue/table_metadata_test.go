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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	metadataTestBucket      = "testbucket"
	metadataTestTablePrefix = "logs/table/"
)

var (
	refTime             = time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)
	nonAWSError         = errors.New("nonAWSError") // nolint:golint
	entityExistsError   = awserr.New(glue.ErrCodeAlreadyExistsException, "PartitionKey already exists.", nil)
	entityNotFoundError = awserr.New(glue.ErrCodeEntityNotFoundException, "Entity not found", nil)
	otherAWSError       = awserr.New("SomeException", "Some problem.", nil) // aws error other than those we code against

	testColumns = []*glue.Column{
		{
			Name: aws.String("col"),
			Type: aws.String("int"),
		},
	}

	testStorageDescriptor = &glue.StorageDescriptor{
		Columns:  testColumns,
		Location: aws.String("s3://" + metadataTestBucket + "/" + metadataTestTablePrefix),
		SerdeInfo: &glue.SerDeInfo{
			SerializationLibrary: aws.String("org.openx.data.jsonserde.JsonSerDe"),
			Parameters: map[string]*string{
				"serialization.format": aws.String("1"),
				"case.insensitive":     aws.String("TRUE"),
			},
		},
	}

	testCreatePartitionOutput = &glue.CreatePartitionOutput{}
	testGetPartitionOutput    = &glue.GetPartitionOutput{
		Partition: &glue.Partition{
			StorageDescriptor: testStorageDescriptor,
		},
	}
	testUpdatePartitionOutput = &glue.UpdatePartitionOutput{}

	testGetTableOutput = &glue.GetTableOutput{
		Table: &glue.TableData{
			CreateTime:        aws.Time(refTime),
			StorageDescriptor: testStorageDescriptor,
		},
	}

	syncStorageDescriptor = &glue.StorageDescriptor{
		Columns: []*glue.Column{ // this should be copied to partitions
			{
				Name: aws.String("updatedCol"),
				Type: aws.String("string"),
			},
		},
		Location: aws.String("s3://" + metadataTestBucket + "/" + metadataTestTablePrefix),
		SerdeInfo: &glue.SerDeInfo{
			SerializationLibrary: aws.String("org.openx.data.jsonserde.JsonSerDe"),
			Parameters: map[string]*string{
				"serialization.format": aws.String("1"),
				"case.insensitive":     aws.String("TRUE"),
			},
		},
	}

	syncGetTableOutput = &glue.GetTableOutput{
		Table: &glue.TableData{
			CreateTime:        aws.Time(time.Now().UTC()), // this should cause 24 updates
			StorageDescriptor: syncStorageDescriptor,
		},
	}
)

type partitionTestEvent struct{}

func TestGetDataPrefix(t *testing.T) {
	assert.Equal(t, logS3Prefix, DataPrefix(pantherdb.LogProcessingDatabase))
	assert.Equal(t, ruleMatchS3Prefix, DataPrefix(pantherdb.RuleMatchDatabase))
	assert.Equal(t, logS3Prefix, DataPrefix("some_test_database"))
}

func TestGlueTableMetadataLogData(t *testing.T) {
	gm := NewGlueTableMetadata(pantherdb.LogProcessingDatabase, "my_logs_type", "description", GlueTableHourly, partitionTestEvent{})

	assert.Equal(t, "description", gm.Description())
	assert.Equal(t, GlueTableHourly, gm.Timebin())
	assert.Equal(t, "my_logs_type", gm.TableName())
	assert.Equal(t, pantherdb.LogProcessingDatabase, gm.DatabaseName())
	assert.Equal(t, "logs/my_logs_type/", gm.Prefix())
	assert.Equal(t, partitionTestEvent{}, gm.eventStruct)
	assert.Equal(t, "logs/my_logs_type/year=2020/month=01/day=03/hour=01/", gm.PartitionPrefix(refTime))
}

func TestGlueTableMetadataRuleMatches(t *testing.T) {
	gm := NewGlueTableMetadata(pantherdb.RuleMatchDatabase, "my_rule", "description", GlueTableHourly, partitionTestEvent{})

	assert.Equal(t, "description", gm.Description())
	assert.Equal(t, GlueTableHourly, gm.Timebin())
	assert.Equal(t, "my_rule", gm.TableName())
	assert.Equal(t, pantherdb.RuleMatchDatabase, gm.DatabaseName())
	assert.Equal(t, "rules/my_rule/", gm.Prefix())
	assert.Equal(t, partitionTestEvent{}, gm.eventStruct)
	assert.Equal(t, "rules/my_rule/year=2020/month=01/day=03/hour=01/", gm.PartitionPrefix(refTime))
}

func TestCreateJSONPartition(t *testing.T) {
	gm := NewGlueTableMetadata(pantherdb.LogProcessingDatabase, "test_logs", "Description", GlueTableHourly, partitionTestEvent{})

	// test no errors and partition does not exist (no error)
	glueClient := &testutils.GlueMock{}
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil).Once()
	created, err := gm.CreateJSONPartition(glueClient, refTime)
	assert.NoError(t, err)
	assert.True(t, created)
	glueClient.AssertExpectations(t)
}

func TestCreateJSONPartitionPartitionExists(t *testing.T) {
	gm := NewGlueTableMetadata(pantherdb.LogProcessingDatabase, "test_logs", "Description", GlueTableHourly, partitionTestEvent{})

	// test partition exists at start
	glueClient := &testutils.GlueMock{}
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil)
	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, entityExistsError)
	created, err := gm.CreateJSONPartition(glueClient, refTime)
	assert.NoError(t, err)
	assert.False(t, created)
	glueClient.AssertExpectations(t)
}

func TestCreateJSONPartitionErrorGettingTable(t *testing.T) {
	gm := NewGlueTableMetadata(pantherdb.LogProcessingDatabase, "test_logs", "Description", GlueTableHourly, partitionTestEvent{})
	// test error in GetTable
	glueClient := &testutils.GlueMock{}
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nonAWSError).Once()
	created, err := gm.CreateJSONPartition(glueClient, refTime)
	assert.Error(t, err)
	assert.False(t, created)
	assert.Equal(t, nonAWSError, err)
	glueClient.AssertExpectations(t)
}

func TestCreateJSONPartitionNonAWSError(t *testing.T) {
	gm := NewGlueTableMetadata(pantherdb.LogProcessingDatabase, "test_logs", "Description", GlueTableHourly, partitionTestEvent{})
	// test error in CreatePartition
	glueClient := &testutils.GlueMock{}
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nonAWSError).Once()
	created, err := gm.CreateJSONPartition(glueClient, refTime)
	assert.Error(t, err)
	assert.False(t, created)
	assert.Equal(t, nonAWSError, err)
	glueClient.AssertExpectations(t)
}

func TestSyncPartitions(t *testing.T) {
	var startDate time.Time // default unset
	gm := NewGlueTableMetadata(pantherdb.LogProcessingDatabase, "test_logs", "Description", GlueTableHourly, partitionTestEvent{})

	glueClient := &testutils.GlueMock{}
	glueClient.On("GetTable", mock.Anything).Return(syncGetTableOutput, nil).Once()
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, nil).Times(24)
	glueClient.On("UpdatePartition", mock.Anything).Return(testUpdatePartitionOutput, nil).Times(24)
	s3Client := &testutils.S3Mock{}
	_, err := gm.SyncPartitions(glueClient, s3Client, startDate, nil)
	assert.NoError(t, err)
	glueClient.AssertExpectations(t)
	s3Client.AssertExpectations(t)

	// check that schema was updated
	for _, updateCall := range glueClient.Calls {
		switch updateInput := updateCall.Arguments.Get(0).(type) {
		case *glue.UpdatePartitionInput:
			assert.Equal(t, syncGetTableOutput.Table.StorageDescriptor.Columns, updateInput.PartitionInput.StorageDescriptor.Columns)
		}
	}
}

func TestSyncPartitionsPartitionDoesntExistAndNoData(t *testing.T) {
	var startDate time.Time // default unset
	gm := NewGlueTableMetadata(pantherdb.LogProcessingDatabase, "test_logs", "Description", GlueTableHourly, partitionTestEvent{})

	// test not exists error in GetPartition (should not fail)
	glueClient := &testutils.GlueMock{}
	glueClient.On("GetTable", mock.Anything).Return(syncGetTableOutput, nil).Once()
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError).Times(24)
	s3Client := &testutils.S3Mock{}
	page := &s3.ListObjectsV2Output{
		Contents: []*s3.Object{}, // no objects
	}
	s3Client.On("ListObjectsV2Pages", mock.Anything, mock.Anything).Return(page, nil).Times(24) // no data found in S3
	// no partitions should be created
	nextPartition, err := gm.SyncPartitions(glueClient, s3Client, startDate, nil)
	assert.NoError(t, err)
	assert.Nil(t, nextPartition)
	glueClient.AssertExpectations(t)
	s3Client.AssertExpectations(t)
}

func TestSyncPartitionsPartitionDoesntExistAndHasData(t *testing.T) {
	gm := NewGlueTableMetadata(pantherdb.LogProcessingDatabase, "test_logs", "Description", GlueTableHourly, partitionTestEvent{})

	// test not exists error in GetPartition (should not fail)
	glueClient := &testutils.GlueMock{}
	glueClient.On("GetTable", mock.Anything).Return(syncGetTableOutput, nil).Once()
	// confirm correct listing calls for some data found in S3
	s3Client := &testutils.S3Mock{}
	page := &s3.ListObjectsV2Output{
		Contents: []*s3.Object{
			{
				Size: aws.Int64(1), // 1 object of some size
			},
		},
	}
	now := time.Now().UTC()
	today := now.Truncate(time.Hour * 24)
	endToday := now.Truncate(time.Hour * 24).Add(time.Hour * 23)
	for partitionTime := today; !partitionTime.After(endToday); partitionTime = partitionTime.Add(time.Hour) {
		expectedListPageInput := s3.ListObjectsV2Input{
			Bucket:  aws.String(metadataTestBucket),
			Prefix:  aws.String(metadataTestTablePrefix + GlueTableHourly.PartitionPathS3(partitionTime)),
			MaxKeys: aws.Int64(1),
		}
		glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError)
		s3Client.On("ListObjectsV2Pages", &expectedListPageInput, mock.Anything).Return(page, nil)
		glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
	}

	nextPartition, err := gm.SyncPartitions(glueClient, s3Client, today, nil)
	assert.NoError(t, err)
	assert.Nil(t, nextPartition)
	glueClient.AssertExpectations(t)
	s3Client.AssertExpectations(t)
}

func TestSyncPartitionsGetPartitionAWSError(t *testing.T) {
	var startDate time.Time // default unset
	gm := NewGlueTableMetadata(pantherdb.LogProcessingDatabase, "test_logs", "Description", GlueTableHourly, partitionTestEvent{})

	// test GetPartition fails (should fail)
	glueClient := &testutils.GlueMock{}
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, otherAWSError) // can be called many times
	s3Client := &testutils.S3Mock{}
	nextPartition, err := gm.SyncPartitions(glueClient, s3Client, startDate, nil)
	assert.Error(t, err)
	assert.Nil(t, nextPartition)
	assert.Equal(t, otherAWSError.Error(), errors.Cause(err).Error())
	glueClient.AssertExpectations(t)
	s3Client.AssertExpectations(t)
}

func TestSyncPartitionsGetPartitionNonAWSError(t *testing.T) {
	var startDate time.Time // default unset
	gm := NewGlueTableMetadata(pantherdb.LogProcessingDatabase, "test_logs", "Description", GlueTableHourly, partitionTestEvent{})

	// test GetPartition fails (should fail)
	glueClient := &testutils.GlueMock{}
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, nonAWSError) // can be called many times
	s3Client := &testutils.S3Mock{}
	nextPartition, err := gm.SyncPartitions(glueClient, s3Client, startDate, nil)
	assert.Error(t, err)
	assert.Nil(t, nextPartition)
	assert.Equal(t, nonAWSError.Error(), errors.Cause(err).Error())
	glueClient.AssertExpectations(t)
	s3Client.AssertExpectations(t)
}

func TestSyncPartitionsDeadline(t *testing.T) {
	var startDate time.Time // default unset
	gm := NewGlueTableMetadata(pantherdb.LogProcessingDatabase, "test_logs", "Description", GlueTableHourly, partitionTestEvent{})

	// test deadline
	glueClient := &testutils.GlueMock{}
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	s3Client := &testutils.S3Mock{}
	deadline := time.Now().UTC().Add(-time.Second) // 1 second in the past, so no work should be done
	nextPartition, err := gm.SyncPartitions(glueClient, s3Client, startDate, &deadline)
	require.NoError(t, err)
	require.NotNil(t, nextPartition)
	assert.Equal(t, refTime.Truncate(time.Hour*24), *nextPartition) // should be the createTime of the table truncated to the day
	glueClient.AssertExpectations(t)
	s3Client.AssertExpectations(t)
}
