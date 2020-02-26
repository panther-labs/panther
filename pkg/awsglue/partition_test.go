package awsglue

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
)

func TestCreatePartitionFromS3Rule(t *testing.T) {
	s3ObjectKey := "rules/aws_cloudtrail/year=2020/month=02/day=26/hour=15/rule_id=AWS.CloudTrail.All/20200226154932-d76e884b-183f-4e81-b05a-b4fb23918c13.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.NoError(t, err)

	expectedPartitionValues := []*partitionKeyValue{
		{
			key: "year",
			value: "2020",
		},
		{
			key: "month",
			value: "02",
		},
		{
			key: "day",
			value: "26",
		},
		{
			key: "hour",
			value: "15",
		},
	}

	assert.Equal(t, RuleMatchDatabaseName, partition.databaseName)
	assert.Equal(t, models.RuleData, partition.datatype)
	assert.Equal(t, "aws_cloudtrail", partition.tableName)
	assert.Equal(t, "bucket", partition.s3Bucket)
	assert.Equal(t, "json", partition.dataFormat)
	assert.Equal(t, "gzip", partition.compression)
	assert.Equal(t, "s3://bucket/rules/aws_cloudtrail/year=2020/month=02/day=26/hour=15/", partition.partitionPrefix())
	assert.Equal(t, expectedPartitionValues, partition.partitionFields)
}

func TestCreatePartitionFromS3Log(t *testing.T) {
	s3ObjectKey := "logs/aws_cloudtrail/year=2020/month=02/day=26/hour=15/20200226154932-d76e884b-183f-4e81-b05a-b4fb23918c13.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.NoError(t, err)

	expectedPartitionValues := []*partitionKeyValue{
		{
			key: "year",
			value: "2020",
		},
		{
			key: "month",
			value: "02",
		},
		{
			key: "day",
			value: "26",
		},
		{
			key: "hour",
			value: "15",
		},
	}

	assert.Equal(t, LogProcessingDatabaseName, partition.databaseName)
	assert.Equal(t, models.LogData, partition.datatype)
	assert.Equal(t, "aws_cloudtrail", partition.tableName)
	assert.Equal(t, "bucket", partition.s3Bucket)
	assert.Equal(t, "json", partition.dataFormat)
	assert.Equal(t, "gzip", partition.compression)
	assert.Equal(t, "s3://bucket/logs/aws_cloudtrail/year=2020/month=02/day=26/hour=15/", partition.partitionPrefix())
	assert.Equal(t, expectedPartitionValues, partition.partitionFields)
}

func TestCreatePartition(t *testing.T) {
	s3ObjectKey := "rules/aws_cloudtrail/year=2020/month=02/day=26/hour=15/rule_id=AWS.CloudTrail.All/20200226154932-d76e884b-183f-4e81-b05a-b4fb23918c13.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.NoError(t, err)

	expectedCreatePartitionInput := &glue.CreatePartitionInput{
		DatabaseName:   aws.String(RuleMatchDatabaseName),
		TableName:      aws.String("aws_cloudtrail"),
		PartitionInput: &glue.PartitionInput{
			StorageDescriptor: &glue.StorageDescriptor{
				InputFormat:  aws.String("org.apache.hadoop.mapred.TextInputFormat"),
				OutputFormat: aws.String("org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"),
				SerdeInfo: &glue.SerDeInfo{
					SerializationLibrary: aws.String("org.openx.data.jsonserde.JsonSerDe"),
					Parameters: map[string]*string{
						"serialization.format": aws.String("1"),
						"case.insensitive":     aws.String("TRUE"), // treat as lower case
					},
				},
				Location: aws.String("s3://bucket/rules/aws_cloudtrail/year=2020/month=02/day=26/hour=15/"),
			},
			Values:            aws.StringSlice([]string{"2020", "02", "26", "15"}),
		},
	}

	mockClient := &mockGlue{}
	mockClient.On("CreatePartition", expectedCreatePartitionInput).Return(&glue.CreatePartitionOutput{}, nil)

	assert.NoError(t, partition.CreatePartition(mockClient))
	mockClient.AssertExpectations(t)
}

func TestCreatePartitionPartitionAlreadExists(t *testing.T) {
	s3ObjectKey := "rules/aws_cloudtrail/year=2020/month=02/day=26/hour=15/rule_id=AWS.CloudTrail.All/20200226154932-d76e884b-183f-4e81-b05a-b4fb23918c13.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &mockGlue{}
	mockClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, awserr.New(glue.ErrCodeAlreadyExistsException, "error", nil))

	assert.NoError(t, partition.CreatePartition(mockClient))
	mockClient.AssertExpectations(t)
}

func TestCreatePartitionAwsError(t *testing.T) {
	s3ObjectKey := "rules/aws_cloudtrail/year=2020/month=02/day=26/hour=15/rule_id=AWS.CloudTrail.All/20200226154932-d76e884b-183f-4e81-b05a-b4fb23918c13.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &mockGlue{}
	mockClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, awserr.New(glue.ErrCodeInternalServiceException, "error", nil))

	assert.Error(t, partition.CreatePartition(mockClient))
	mockClient.AssertExpectations(t)
}

func TestCreatePartitionGeneralError(t *testing.T) {
	s3ObjectKey := "rules/aws_cloudtrail/year=2020/month=02/day=26/hour=15/rule_id=AWS.CloudTrail.All/20200226154932-d76e884b-183f-4e81-b05a-b4fb23918c13.json.gz"
	partition, err := GetPartitionFromS3("bucket", s3ObjectKey)
	require.NoError(t, err)

	mockClient := &mockGlue{}
	mockClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, errors.New("error"))

	assert.Error(t, partition.CreatePartition(mockClient))
	mockClient.AssertExpectations(t)
}
