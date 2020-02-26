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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
)

const (
	s3Prefix           = "foo/"
	partitionTestDb    = "testDb"
	partitionTestTable = "testTable"
)

var (
	nonAWSError         = errors.New("nonAWSError") // nolint:golint
	entityNotFoundError = awserr.New("EntityNotFoundException", "EntityNotFoundException", nil)
	entityExistsError   = awserr.New("AlreadyExistsException", "PartitionKey already exists.", nil)
	otherAWSError       = awserr.New("SomeException", "Some problem.", nil) // aws error other than those we code against
)

type partitionTestEvent struct{}


func TestGlueTableMetadataLogData(t *testing.T) {
	gm := NewGlueTableMetadata(models.LogData, "My.Logs.Type", "description", GlueTableHourly, partitionTestEvent{} )

	assert.Equal(t, "description", gm.Description())
	assert.Equal(t, "My.Logs.Type", gm.LogType())
	assert.Equal(t, GlueTableHourly, gm.Timebin())
	assert.Equal(t, "my_logs_type", gm.TableName())
	assert.Equal(t, logProcessingDatabaseName, gm.DatabaseName())
	assert.Equal(t, "logs/my_logs_type/", gm.Prefix())
	assert.Equal(t, partitionTestEvent{}, gm.eventStruct)

	refTime := time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)
	assert.Equal(t, "logs/my_logs_type/year=2020/month=01/day=03/hour=01/", gm.GetPartitionPrefix(refTime))
}

func TestGlueTableMetadataRuleMatches(t *testing.T) {
	gm := NewGlueTableMetadata(models.RuleData, "My.Rule", "description", GlueTableHourly, partitionTestEvent{} )

	assert.Equal(t, "description", gm.Description())
	assert.Equal(t, "My.Rule", gm.LogType())
	assert.Equal(t, GlueTableHourly, gm.Timebin())
	assert.Equal(t, "my_rule", gm.TableName())
	assert.Equal(t, ruleMatchDatabaseName, gm.DatabaseName())
	assert.Equal(t, "rules/my_rule/", gm.Prefix())
	assert.Equal(t, partitionTestEvent{}, gm.eventStruct)

	refTime := time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)
	assert.Equal(t, "rules/my_rule/year=2020/month=01/day=03/hour=01/", gm.GetPartitionPrefix(refTime))
}



//
//func TestCreateJSONPartition(t *testing.T) {
//	refTime := time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)
//	gm := NewLogTableMetadata(partitionTestTable, partitionTestTable)
//
//	// test no errors and partition does not exist (no error)
//	glueClient := &mockGlue{}
//	glueClient.On("GetPartitionFromS3", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError).Once()
//	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
//	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil).Once()
//	err := gm.CreateJSONPartition(glueClient, refTime)
//	assert.NoError(t, err)
//
//	// test partition exists at start
//	glueClient = &mockGlue{}
//	glueClient.On("GetPartitionFromS3", mock.Anything).Return(testGetPartitionOutput, entityExistsError).Once()
//	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil)
//	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
//	err = gm.CreateJSONPartition(glueClient, refTime)
//	assert.Error(t, err)
//	assert.Equal(t, entityExistsError, err)
//
//	// test other AWS err in GetPartitionFromS3()
//	glueClient = &mockGlue{}
//	glueClient.On("GetPartitionFromS3", mock.Anything).Return(testGetPartitionOutput, otherAWSError).Once()
//	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil)
//	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
//	err = gm.CreateJSONPartition(glueClient, refTime)
//	assert.Error(t, err)
//	assert.Equal(t, otherAWSError, err)
//
//	// test non AWS err in GetPartitionFromS3()
//	glueClient = &mockGlue{}
//	glueClient.On("GetPartitionFromS3", mock.Anything).Return(testGetPartitionOutput, nonAWSError).Once()
//	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil)
//	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
//	err = gm.CreateJSONPartition(glueClient, refTime)
//	assert.Error(t, err)
//	assert.Equal(t, nonAWSError, err)
//
//	// test error in GetTable
//	glueClient = &mockGlue{}
//	glueClient.On("GetPartitionFromS3", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError).Once()
//	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nonAWSError).Once()
//	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
//	err = gm.CreateJSONPartition(glueClient, refTime)
//	assert.Error(t, err)
//	assert.Equal(t, nonAWSError, err)
//
//	// test error in CreatePartition
//	glueClient = &mockGlue{}
//	glueClient.On("GetPartitionFromS3", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError).Once()
//	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
//	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nonAWSError).Once()
//	err = gm.CreateJSONPartition(glueClient, refTime)
//	assert.Error(t, err)
//	assert.Equal(t, nonAWSError, err)
//}
//
//func TestSyncPartition(t *testing.T) {
//	refTime := time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)
//	gm := NewLogTableMetadata(partitionTestTable, partitionTestTable)
//
//	// test not exists error in DeletePartition (should not fail)
//	glueClient := &mockGlue{}
//	glueClient.On("DeletePartition", mock.Anything).Return(testDeletePartitionOutput, entityNotFoundError).Once()
//	glueClient.On("GetPartitionFromS3", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError).Once()
//	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
//	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil).Once()
//	err := gm.SyncPartition(glueClient, refTime)
//	assert.NoError(t, err)
//
//	// test other AWS error in DeletePartition (should fail)
//	glueClient = &mockGlue{}
//	glueClient.On("DeletePartition", mock.Anything).Return(testDeletePartitionOutput, otherAWSError).Once()
//	glueClient.On("GetPartitionFromS3", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError)
//	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil)
//	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
//	err = gm.SyncPartition(glueClient, refTime)
//	assert.Error(t, err)
//	assert.Equal(t, otherAWSError.Error(), errors.Cause(err).Error())
//
//	// test non AWS error in DeletePartition (should fail)
//	glueClient = &mockGlue{}
//	glueClient.On("DeletePartition", mock.Anything).Return(testDeletePartitionOutput, nonAWSError).Once()
//	glueClient.On("GetPartitionFromS3", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError)
//	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil)
//	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
//	err = gm.SyncPartition(glueClient, refTime)
//	assert.Error(t, err)
//	assert.Equal(t, nonAWSError.Error(), errors.Cause(err).Error())
//}


// fixed for our tests
var (
	testGetPartitionOutput = &glue.GetPartitionOutput{}

	testCreatePartitionOutput = &glue.CreatePartitionOutput{}

	testDeletePartitionOutput = &glue.DeletePartitionOutput{}

	testGetTableOutput = &glue.GetTableOutput{
		Table: &glue.TableData{
			StorageDescriptor: &glue.StorageDescriptor{
				Location: aws.String("s3://testbucket/logs/table"),
				SerdeInfo: &glue.SerDeInfo{
					SerializationLibrary: aws.String("org.openx.data.jsonserde.JsonSerDe"),
					Parameters: map[string]*string{
						"serialization.format": aws.String("1"),
						"case.insensitive":     aws.String("TRUE"),
					},
				},
			},
		},
	}
)

type mockGlue struct {
	glueiface.GlueAPI
	mock.Mock
}


func (m *mockGlue) GetPartitionFromS3(input *glue.GetPartitionInput) (*glue.GetPartitionOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.GetPartitionOutput), args.Error(1)
}

func (m *mockGlue) GetTable(input *glue.GetTableInput) (*glue.GetTableOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.GetTableOutput), args.Error(1)
}

func (m *mockGlue) CreatePartition(input *glue.CreatePartitionInput) (*glue.CreatePartitionOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.CreatePartitionOutput), args.Error(1)
}

func (m *mockGlue) DeletePartition(input *glue.DeletePartitionInput) (*glue.DeletePartitionOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.DeletePartitionOutput), args.Error(1)
}
