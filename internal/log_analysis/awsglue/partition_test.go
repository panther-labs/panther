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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestCreatePartitionFromS3Rule(t *testing.T) {
	s3ObjectKey := "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	partition, err := PartitionFromS3Object("bucket", s3ObjectKey)
	require.NoError(t, err)

	expectedPartitionValues := []PartitionColumnInfo{
		{
			Key:   "year",
			Value: "2020",
		},
		{
			Key:   "month",
			Value: "02",
		},
		{
			Key:   "day",
			Value: "26",
		},
		{
			Key:   "hour",
			Value: "15",
		},
		{
			Key:   "partition_time",
			Value: "1582729200",
		},
	}

	assert.Equal(t, pantherdb.RuleMatchDatabase, partition.GetDatabase())
	assert.Equal(t, "table", partition.GetTable())
	assert.Equal(t, "bucket", partition.GetS3Bucket())
	assert.Equal(t, "s3://bucket/rules/table/year=2020/month=02/day=26/hour=15/", partition.PartitionLocation())
	assert.Equal(t, expectedPartitionValues, partition.GetPartitionColumnsInfo())
}

func TestCreatePartitionFromS3Log(t *testing.T) {
	s3ObjectKey := "logs/table/year=2020/month=02/day=26/hour=15/item.json.gz"
	partition, err := PartitionFromS3Object("bucket", s3ObjectKey)
	require.NoError(t, err)

	expectedPartitionValues := []PartitionColumnInfo{
		{
			Key:   "year",
			Value: "2020",
		},
		{
			Key:   "month",
			Value: "02",
		},
		{
			Key:   "day",
			Value: "26",
		},
		{
			Key:   "hour",
			Value: "15",
		},
		{
			Key:   "partition_time",
			Value: "1582729200",
		},
	}

	assert.Equal(t, pantherdb.LogProcessingDatabase, partition.GetDatabase())
	assert.Equal(t, "table", partition.GetTable())
	assert.Equal(t, "bucket", partition.GetS3Bucket())
	assert.Equal(t, "s3://bucket/logs/table/year=2020/month=02/day=26/hour=15/", partition.PartitionLocation())
	assert.Equal(t, expectedPartitionValues, partition.GetPartitionColumnsInfo())
}

func TestCreatePartitionUnknownPrefix(t *testing.T) {
	s3ObjectKey := "wrong_prefix/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	_, err := PartitionFromS3Object("bucket", s3ObjectKey)
	require.Error(t, err)
}

func TestCreatePartitionWroteYearFormat(t *testing.T) {
	s3ObjectKey := "rules/table/year=no_year/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	_, err := PartitionFromS3Object("bucket", s3ObjectKey)
	require.Error(t, err)
}

func TestCreatePartitionMisingYearPartition(t *testing.T) {
	s3ObjectKey := "rules/table/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	_, err := PartitionFromS3Object("bucket", s3ObjectKey)
	require.Error(t, err)
}

func TestCreatePartitionLog(t *testing.T) {
	s3ObjectKey := "logs/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	partition, err := PartitionFromS3Object("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &testutils.GlueMock{}
	mockClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, nil).Once()

	created, err := partition.GetGlueTableMetadata().CreateJSONPartition(mockClient, partition.GetTime())
	assert.NoError(t, err)
	assert.True(t, created)
	mockClient.AssertExpectations(t)
}

func TestCreateParitionRule(t *testing.T) {
	s3ObjectKey := "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	partition, err := PartitionFromS3Object("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &testutils.GlueMock{}
	mockClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, nil).Once()

	created, err := partition.GetGlueTableMetadata().CreateJSONPartition(mockClient, partition.GetTime())
	assert.NoError(t, err)
	assert.True(t, created)
	mockClient.AssertExpectations(t)
}

func TestCreatePartitionPartitionAlreadExists(t *testing.T) {
	s3ObjectKey := "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	partition, err := PartitionFromS3Object("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &testutils.GlueMock{}
	mockClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockClient.On("CreatePartition", mock.Anything).
		Return(&glue.CreatePartitionOutput{}, awserr.New(glue.ErrCodeAlreadyExistsException, "error", nil)).Once()

	created, err := partition.GetGlueTableMetadata().CreateJSONPartition(mockClient, partition.GetTime())
	assert.NoError(t, err)
	assert.False(t, created)
	mockClient.AssertExpectations(t)
}

func TestCreatePartitionAwsError(t *testing.T) {
	s3ObjectKey := "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	partition, err := PartitionFromS3Object("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &testutils.GlueMock{}
	mockClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockClient.On("CreatePartition", mock.Anything).
		Return(&glue.CreatePartitionOutput{}, awserr.New(glue.ErrCodeInternalServiceException, "error", nil)).Once()

	created, err := partition.GetGlueTableMetadata().CreateJSONPartition(mockClient, partition.GetTime())
	assert.Error(t, err)
	assert.False(t, created)
	mockClient.AssertExpectations(t)
}

func TestCreatePartitionGeneralError(t *testing.T) {
	s3ObjectKey := "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	partition, err := PartitionFromS3Object("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &testutils.GlueMock{}
	mockClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, errors.New("error")).Once()

	created, err := partition.GetGlueTableMetadata().CreateJSONPartition(mockClient, partition.GetTime())
	assert.Error(t, err)
	assert.False(t, created)
	mockClient.AssertExpectations(t)
}
