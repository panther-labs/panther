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
	"github.com/stretchr/testify/require"
)

const (
	partitionTestDb    = "testDb"
	partitionTestTable = "testTable"
)

var (
	nonAWSError         = errors.New("nonAWSError") // nolint:golint
	entityNotFoundError = awserr.New("EntityNotFoundException", "EntityNotFoundException", nil)
	entityExistsError   = awserr.New("AlreadyExistsException", "Partition already exists.", nil)
	otherAWSError       = awserr.New("SomeException", "Some problem.", nil) // aws error other than those we code against
)

type partitionTestEvent struct{}

func TestCreateJSONPartition(t *testing.T) {
	refTime := time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)
	gm, err := NewGlueMetadata(partitionTestDb, partitionTestTable, partitionTestTable, GlueTableHourly, false, &partitionTestEvent{})
	require.NoError(t, err)

	// test no errors and partition does not exist (no error)
	glueClient := &mockGlue{}
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError).Once()
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil).Once()
	err = gm.CreateJSONPartition(glueClient, refTime)
	assert.NoError(t, err)

	// test partition exists at start
	glueClient = &mockGlue{}
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, entityExistsError).Once()
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil)
	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
	err = gm.CreateJSONPartition(glueClient, refTime)
	assert.Error(t, err)
	assert.Equal(t, entityExistsError, err)

	// test other AWS err in GetPartition()
	glueClient = &mockGlue{}
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, otherAWSError).Once()
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil)
	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
	err = gm.CreateJSONPartition(glueClient, refTime)
	assert.Error(t, err)
	assert.Equal(t, otherAWSError, err)

	// test non AWS err in GetPartition()
	glueClient = &mockGlue{}
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, nonAWSError).Once()
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil)
	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
	err = gm.CreateJSONPartition(glueClient, refTime)
	assert.Error(t, err)
	assert.Equal(t, nonAWSError, err)

	// test error in GetTable
	glueClient = &mockGlue{}
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError).Once()
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nonAWSError).Once()
	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
	err = gm.CreateJSONPartition(glueClient, refTime)
	assert.Error(t, err)
	assert.Equal(t, nonAWSError, err)

	// test error in CreatePartition
	glueClient = &mockGlue{}
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError).Once()
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nonAWSError).Once()
	err = gm.CreateJSONPartition(glueClient, refTime)
	assert.Error(t, err)
	assert.Equal(t, nonAWSError, err)
}

func TestSyncPartition(t *testing.T) {
	refTime := time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)
	gm, err := NewGlueMetadata(partitionTestDb, partitionTestTable, partitionTestTable, GlueTableHourly, false, &partitionTestEvent{})
	require.NoError(t, err)

	// test not exists error in DeletePartition (should not fail)
	glueClient := &mockGlue{}
	glueClient.On("DeletePartition", mock.Anything).Return(testDeletePartitionOutput, entityNotFoundError).Once()
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError).Once()
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil).Once()
	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil).Once()
	err = gm.SyncPartition(glueClient, refTime)
	assert.NoError(t, err)

	// test other AWS error in DeletePartition (should fail)
	glueClient = &mockGlue{}
	glueClient.On("DeletePartition", mock.Anything).Return(testDeletePartitionOutput, otherAWSError).Once()
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError)
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil)
	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
	err = gm.SyncPartition(glueClient, refTime)
	assert.Error(t, err)
	assert.Equal(t, otherAWSError.Error(), errors.Cause(err).Error())

	// test non AWS error in DeletePartition (should fail)
	glueClient = &mockGlue{}
	glueClient.On("DeletePartition", mock.Anything).Return(testDeletePartitionOutput, nonAWSError).Once()
	glueClient.On("GetPartition", mock.Anything).Return(testGetPartitionOutput, entityNotFoundError)
	glueClient.On("GetTable", mock.Anything).Return(testGetTableOutput, nil)
	glueClient.On("CreatePartition", mock.Anything).Return(testCreatePartitionOutput, nil)
	err = gm.SyncPartition(glueClient, refTime)
	assert.Error(t, err)
	assert.Equal(t, nonAWSError.Error(), errors.Cause(err).Error())
}

type mockGlue struct {
	glueiface.GlueAPI
	mock.Mock
}

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

func (m *mockGlue) GetPartition(input *glue.GetPartitionInput) (*glue.GetPartitionOutput, error) {
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
