package process

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
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	metadataTestBucket      = "testbucket"
	metadataTestTablePrefix = "logs/table/"
)

var (
	syncTestGetPartitionOutput = &glue.GetPartitionOutput{
		Partition: &glue.Partition{
			StorageDescriptor: testStorageDescriptor,
		},
	}
	syncTestUpdatePartitionOutput = &glue.UpdatePartitionOutput{}

	syncTestStorageDescriptor = &glue.StorageDescriptor{
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

	syncTestGetTableOutput = &glue.GetTableOutput{
		Table: &glue.TableData{
			CreateTime:        aws.Time(time.Now().UTC()), // this should cause 24 updates
			StorageDescriptor: syncTestStorageDescriptor,
		},
	}
)

func TestSync(t *testing.T) {
	// this will sync 2 tables for a day
	nTableUpates := 3
	nPartitionUpdates := 24 * nTableUpates
	glueMock := &testutils.GlueMock{}
	glueClient = glueMock
	glueMock.On("GetTable", mock.Anything).Return(syncTestGetTableOutput, nil).Times(nTableUpates)
	glueMock.On("GetPartition", mock.Anything).Return(syncTestGetPartitionOutput, nil).Times(nPartitionUpdates)
	glueMock.On("UpdatePartition", mock.Anything).Return(syncTestUpdatePartitionOutput, nil).Times(nPartitionUpdates)
	s3Mock := &testutils.S3Mock{}
	s3Client = s3Mock
	lambdaMock := &testutils.LambdaMock{}
	lambdaClient = lambdaMock
	lambdaMock.On("Invoke", mock.Anything).Return(&lambda.InvokeOutput{}, nil).Once()

	err := Sync(&SyncEvent{
		Sync:     true,
		LogTypes: []string{"AWS.VPCFlow", "AWS.CloudTrail"}, // use 2 so we invoke lambda on the 2nd logType
	}, time.Now().UTC().Add(time.Hour))
	assert.NoError(t, err)
	glueMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
	lambdaMock.AssertExpectations(t)

	// check that schema was updated
	for _, updateCall := range glueMock.Calls {
		switch updateInput := updateCall.Arguments.Get(0).(type) {
		case *glue.UpdatePartitionInput:
			assert.Equal(t, syncTestGetTableOutput.Table.StorageDescriptor.Columns, updateInput.PartitionInput.StorageDescriptor.Columns)
		}
	}
}

func TestSyncContinuationFromLogData(t *testing.T) {
	// this will sync 6 tables (3 from first logType, 3 from 2nd) for a day
	nTableUpates := 6
	nPartitionUpdates := 24 * nTableUpates
	glueMock := &testutils.GlueMock{}
	glueClient = glueMock
	glueMock.On("GetTable", mock.Anything).Return(syncTestGetTableOutput, nil).Times(nTableUpates)
	glueMock.On("GetPartition", mock.Anything).Return(syncTestGetPartitionOutput, nil).Times(nPartitionUpdates)
	glueMock.On("UpdatePartition", mock.Anything).Return(syncTestUpdatePartitionOutput, nil).Times(nPartitionUpdates)
	s3Mock := &testutils.S3Mock{}
	s3Client = s3Mock
	lambdaMock := &testutils.LambdaMock{}
	lambdaClient = lambdaMock

	// start the continuation at the create time of the table to get a full day
	err := Sync(&SyncEvent{
		Sync:     true,
		LogTypes: []string{"AWS.VPCFlow", "AWS.CloudTrail"}, // use 2 so we invoke lambda on the 2nd logType
		Continuation: &Continuation{
			LogType:           "AWS.VPCFlow",
			DataType:          models.LogData,
			NextPartitionTime: (*syncTestGetTableOutput.Table.CreateTime).Truncate(time.Hour),
		},
	}, time.Now().UTC().Add(time.Hour))
	assert.NoError(t, err)
	glueMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
	lambdaMock.AssertExpectations(t)

	// check that schema was updated
	for _, updateCall := range glueMock.Calls {
		switch updateInput := updateCall.Arguments.Get(0).(type) {
		case *glue.UpdatePartitionInput:
			assert.Equal(t, syncTestGetTableOutput.Table.StorageDescriptor.Columns, updateInput.PartitionInput.StorageDescriptor.Columns)
		}
	}
}

func TestSyncContinuationFromRuleData(t *testing.T) {
	// this will sync 5 tables. rule matches, rule errors from first logType
	// Then logs, rule matches, rule errors from 2nd) for a day
	nTableUpates := 5
	nPartitionUpdates := 24 * nTableUpates
	glueMock := &testutils.GlueMock{}
	glueClient = glueMock
	glueMock.On("GetTable", mock.Anything).Return(syncTestGetTableOutput, nil).Times(nTableUpates)
	glueMock.On("GetPartition", mock.Anything).Return(syncTestGetPartitionOutput, nil).Times(nPartitionUpdates)
	glueMock.On("UpdatePartition", mock.Anything).Return(syncTestUpdatePartitionOutput, nil).Times(nPartitionUpdates)
	s3Mock := &testutils.S3Mock{}
	s3Client = s3Mock
	lambdaMock := &testutils.LambdaMock{}
	lambdaClient = lambdaMock

	// start the continuation at the create time of the table to get a full day
	err := Sync(&SyncEvent{
		Sync:     true,
		LogTypes: []string{"AWS.VPCFlow", "AWS.CloudTrail"}, // use 2 so we invoke lambda on the 2nd logType
		Continuation: &Continuation{
			LogType:           "AWS.VPCFlow",
			DataType:          models.RuleData,
			NextPartitionTime: (*syncTestGetTableOutput.Table.CreateTime).Truncate(time.Hour),
		},
	}, time.Now().UTC().Add(time.Hour))
	assert.NoError(t, err)
	glueMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
	lambdaMock.AssertExpectations(t)

	// check that schema was updated
	for _, updateCall := range glueMock.Calls {
		switch updateInput := updateCall.Arguments.Get(0).(type) {
		case *glue.UpdatePartitionInput:
			assert.Equal(t, syncTestGetTableOutput.Table.StorageDescriptor.Columns, updateInput.PartitionInput.StorageDescriptor.Columns)
		}
	}
}

func TestSyncContinuationFromRuleErrorData(t *testing.T) {
	// this will sync 4 tables (rule errors from first logType then logs, rule matches, rule errors from 2nd) for a day
	nTableUpates := 4
	nPartitionUpdates := 24 * nTableUpates
	glueMock := &testutils.GlueMock{}
	glueClient = glueMock
	glueMock.On("GetTable", mock.Anything).Return(syncTestGetTableOutput, nil).Times(nTableUpates)
	glueMock.On("GetPartition", mock.Anything).Return(syncTestGetPartitionOutput, nil).Times(nPartitionUpdates)
	glueMock.On("UpdatePartition", mock.Anything).Return(syncTestUpdatePartitionOutput, nil).Times(nPartitionUpdates)
	s3Mock := &testutils.S3Mock{}
	s3Client = s3Mock
	lambdaMock := &testutils.LambdaMock{}
	lambdaClient = lambdaMock

	// start the continuation at the create time of the table to get a full day
	err := Sync(&SyncEvent{
		Sync:     true,
		LogTypes: []string{"AWS.VPCFlow", "AWS.CloudTrail"}, // use 2 so we invoke lambda on the 2nd logType
		Continuation: &Continuation{
			LogType:           "AWS.VPCFlow",
			DataType:          models.RuleErrors,
			NextPartitionTime: (*syncTestGetTableOutput.Table.CreateTime).Truncate(time.Hour),
		},
	}, time.Now().UTC().Add(time.Hour))
	assert.NoError(t, err)
	glueMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
	lambdaMock.AssertExpectations(t)

	// check that schema was updated
	for _, updateCall := range glueMock.Calls {
		switch updateInput := updateCall.Arguments.Get(0).(type) {
		case *glue.UpdatePartitionInput:
			assert.Equal(t, syncTestGetTableOutput.Table.StorageDescriptor.Columns, updateInput.PartitionInput.StorageDescriptor.Columns)
		}
	}
}
