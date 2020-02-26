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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/pkg/errors"
)

const (
	s3Prefix = "foo/"
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

//
//func TestGlueMetadataPartitionPrefix(t *testing.T) {
//	var gm *GlueTableMetadata
//	var expected string
//
//	refTime := time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)
//
//	gm = &GlueTableMetadata{
//		s3TablePrefix: prefix,
//		timebin:       GlueTableHourly,
//		timeUnpadded:  false,
//	}
//	expected = "foo/year=2020/month=01/day=03/hour=01/"
//	assert.Equal(t, expected, gm.PartitionPrefix(refTime))
//	gm.timeUnpadded = true
//	expected = "foo/year=2020/month=1/day=3/hour=1/"
//	assert.Equal(t, expected, gm.PartitionPrefix(refTime))
//
//	gm = &GlueTableMetadata{
//		s3TablePrefix: prefix,
//		timebin:       GlueTableDaily,
//		timeUnpadded:  false,
//	}
//	expected = "foo/year=2020/month=01/day=03/"
//	assert.Equal(t, expected, gm.PartitionPrefix(refTime))
//	gm.timeUnpadded = true
//	expected = "foo/year=2020/month=1/day=3/"
//	assert.Equal(t, expected, gm.PartitionPrefix(refTime))
//
//	gm = &GlueTableMetadata{
//		s3TablePrefix: prefix,
//		timebin:       GlueTableMonthly,
//		timeUnpadded:  false,
//	}
//	expected = "foo/year=2020/month=01/"
//	assert.Equal(t, expected, gm.PartitionPrefix(refTime))
//	gm.timeUnpadded = true
//	expected = "foo/year=2020/month=1/"
//	assert.Equal(t, expected, gm.PartitionPrefix(refTime))
//}
//
//func TestGlueMetadataPartitionValues(t *testing.T) {
//	var gm *GlueTableMetadata
//	var expected []*string
//
//	refTime := time.Date(2020, 1, 3, 1, 1, 1, 0, time.UTC)
//
//	gm = &GlueTableMetadata{
//		s3TablePrefix: prefix,
//		timebin:       GlueTableHourly,
//		timeUnpadded:  false,
//	}
//	expected = []*string{
//		aws.String(fmt.Sprintf("%d", refTime.Year())),
//		aws.String(fmt.Sprintf("%02d", refTime.Month())),
//		aws.String(fmt.Sprintf("%02d", refTime.Day())),
//		aws.String(fmt.Sprintf("%02d", refTime.Hour())),
//	}
//	assert.Equal(t, expected, gm.partitionValues(refTime))
//	gm.timeUnpadded = true
//	expected = []*string{
//		aws.String(fmt.Sprintf("%d", refTime.Year())),
//		aws.String(fmt.Sprintf("%d", refTime.Month())),
//		aws.String(fmt.Sprintf("%d", refTime.Day())),
//		aws.String(fmt.Sprintf("%d", refTime.Hour())),
//	}
//	assert.Equal(t, expected, gm.partitionValues(refTime))
//
//	gm = &GlueTableMetadata{
//		s3TablePrefix: prefix,
//		timebin:       GlueTableDaily,
//		timeUnpadded:  false,
//	}
//	expected = []*string{
//		aws.String(fmt.Sprintf("%d", refTime.Year())),
//		aws.String(fmt.Sprintf("%02d", refTime.Month())),
//		aws.String(fmt.Sprintf("%02d", refTime.Day())),
//	}
//	assert.Equal(t, expected, gm.partitionValues(refTime))
//	gm.timeUnpadded = true
//	expected = []*string{
//		aws.String(fmt.Sprintf("%d", refTime.Year())),
//		aws.String(fmt.Sprintf("%d", refTime.Month())),
//		aws.String(fmt.Sprintf("%d", refTime.Day())),
//	}
//	assert.Equal(t, expected, gm.partitionValues(refTime))
//
//	gm = &GlueTableMetadata{
//		s3TablePrefix: prefix,
//		timebin:       GlueTableMonthly,
//		timeUnpadded:  false,
//	}
//	expected = []*string{
//		aws.String(fmt.Sprintf("%d", refTime.Year())),
//		aws.String(fmt.Sprintf("%02d", refTime.Month())),
//	}
//	assert.Equal(t, expected, gm.partitionValues(refTime))
//	gm.timeUnpadded = true
//	expected = []*string{
//		aws.String(fmt.Sprintf("%d", refTime.Year())),
//		aws.String(fmt.Sprintf("%d", refTime.Month())),
//	}
//	assert.Equal(t, expected, gm.partitionValues(refTime))
//}
//
//func TestGlueTableTimebinNext(t *testing.T) {
//	var tb GlueTableTimebin
//	refTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
//
//	// hour and day are fixed offsets, so only need simple tests
//
//	// test hour ...
//	tb = GlueTableHourly
//	expectedTime := refTime.Add(time.Hour)
//	next := tb.Next(refTime)
//	assert.Equal(t, expectedTime, next)
//
//	// test day ...
//	tb = GlueTableDaily
//	expectedTime = refTime.Add(time.Hour * 24)
//	next = tb.Next(refTime)
//	assert.Equal(t, expectedTime, next)
//
//	// test month ... this needs to test crossing year boundaries
//	tb = GlueTableMonthly
//	// Jan to Feb
//	refTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
//	expectedTime = time.Date(2020, 2, 1, 0, 0, 0, 0, time.UTC)
//	next = tb.Next(refTime)
//	assert.Equal(t, expectedTime, next)
//	// Dec to Jan, over year boundary
//	refTime = time.Date(2020, 12, 1, 0, 0, 0, 0, time.UTC)
//	expectedTime = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
//	next = tb.Next(refTime)
//	assert.Equal(t, expectedTime, next)
//}
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
//
//type mockGlue struct {
//	glueiface.GlueAPI
//	mock.Mock
//}
//
//// fixed for our tests
//var (
//	testGetPartitionOutput = &glue.GetPartitionOutput{}
//
//	testCreatePartitionOutput = &glue.CreatePartitionOutput{}
//
//	testDeletePartitionOutput = &glue.DeletePartitionOutput{}
//
//	testGetTableOutput = &glue.GetTableOutput{
//		Table: &glue.TableData{
//			StorageDescriptor: &glue.StorageDescriptor{
//				Location: aws.String("s3://testbucket/logs/table"),
//				SerdeInfo: &glue.SerDeInfo{
//					SerializationLibrary: aws.String("org.openx.data.jsonserde.JsonSerDe"),
//					Parameters: map[string]*string{
//						"serialization.format": aws.String("1"),
//						"case.insensitive":     aws.String("TRUE"),
//					},
//				},
//			},
//		},
//	}
//)
//
//func (m *mockGlue) GetPartitionFromS3(input *glue.GetPartitionInput) (*glue.GetPartitionOutput, error) {
//	args := m.Called(input)
//	return args.Get(0).(*glue.GetPartitionOutput), args.Error(1)
//}
//
//func (m *mockGlue) GetTable(input *glue.GetTableInput) (*glue.GetTableOutput, error) {
//	args := m.Called(input)
//	return args.Get(0).(*glue.GetTableOutput), args.Error(1)
//}
//
//func (m *mockGlue) CreatePartition(input *glue.CreatePartitionInput) (*glue.CreatePartitionOutput, error) {
//	args := m.Called(input)
//	return args.Get(0).(*glue.CreatePartitionOutput), args.Error(1)
//}
//
//func (m *mockGlue) DeletePartition(input *glue.DeletePartitionInput) (*glue.DeletePartitionOutput, error) {
//	args := m.Called(input)
//	return args.Get(0).(*glue.DeletePartitionOutput), args.Error(1)
//}
