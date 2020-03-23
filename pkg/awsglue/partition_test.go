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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCreatePartitionFromS3Rule(t *testing.T) {
	s3ObjectKey := "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
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
	}

	assert.Equal(t, RuleMatchDatabaseName, partition.GetDatabase())
	assert.Equal(t, "table", partition.GetTable())
	assert.Equal(t, "bucket", partition.GetS3Bucket())
	assert.Equal(t, "json", partition.GetDataFormat())
	assert.Equal(t, "gzip", partition.GetCompression())
	assert.Equal(t, "s3://bucket/rules/table/year=2020/month=02/day=26/hour=15/", partition.GetPartitionLocation())
	assert.Equal(t, expectedPartitionValues, partition.GetPartitionColumnsInfo())
}

func TestCreatePartitionFromS3Log(t *testing.T) {
	s3ObjectKey := "logs/table/year=2020/month=02/day=26/hour=15/item.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
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
	}

	assert.Equal(t, LogProcessingDatabaseName, partition.GetDatabase())
	assert.Equal(t, "table", partition.GetTable())
	assert.Equal(t, "bucket", partition.GetS3Bucket())
	assert.Equal(t, "json", partition.GetDataFormat())
	assert.Equal(t, "gzip", partition.GetCompression())
	assert.Equal(t, "s3://bucket/logs/table/year=2020/month=02/day=26/hour=15/", partition.GetPartitionLocation())
	assert.Equal(t, expectedPartitionValues, partition.GetPartitionColumnsInfo())
}

func TestCreatePartitionUnknownPrefix(t *testing.T) {
	s3ObjectKey := "wrong_prefix/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	_, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.Error(t, err)
}

func TestCreatePartitionWroteYearFormat(t *testing.T) {
	s3ObjectKey := "rules/table/year=no_year/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	_, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.Error(t, err)
}

func TestCreatePartitionMisingYearPartition(t *testing.T) {
	s3ObjectKey := "rules/table/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	_, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.Error(t, err)
}

func TestCreatePartitionUknownFormat(t *testing.T) {
	s3ObjectKey := "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.parquet"
	_, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.Error(t, err)
}

func TestCreatePartitionLog(t *testing.T) {
	s3ObjectKey := "logs/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &mockGlue{}
	mockClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, nil).Once()

	assert.NoError(t, partition.CreatePartition(mockClient))
	mockClient.AssertExpectations(t)
}

func TestCreatePartitionRule(t *testing.T) {
	s3ObjectKey := "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &mockGlue{}
	mockClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, nil).Once()

	assert.NoError(t, partition.CreatePartition(mockClient))
	mockClient.AssertExpectations(t)
}

func TestCreatePartitionPartitionAlreadExists(t *testing.T) {
	s3ObjectKey := "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &mockGlue{}
	mockClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockClient.On("CreatePartition", mock.Anything).
		Return(&glue.CreatePartitionOutput{}, awserr.New(glue.ErrCodeAlreadyExistsException, "error", nil)).Once()

	assert.NoError(t, partition.CreatePartition(mockClient))
	mockClient.AssertExpectations(t)
}

func TestCreatePartitionAwsError(t *testing.T) {
	s3ObjectKey := "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &mockGlue{}
	mockClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockClient.On("CreatePartition", mock.Anything).
		Return(&glue.CreatePartitionOutput{}, awserr.New(glue.ErrCodeInternalServiceException, "error", nil)).Once()

	assert.Error(t, partition.CreatePartition(mockClient))
	mockClient.AssertExpectations(t)
}

func TestCreatePartitionGeneralError(t *testing.T) {
	s3ObjectKey := "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &mockGlue{}
	mockClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	mockClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, errors.New("error")).Once()

	assert.Error(t, partition.CreatePartition(mockClient))
	mockClient.AssertExpectations(t)
}
