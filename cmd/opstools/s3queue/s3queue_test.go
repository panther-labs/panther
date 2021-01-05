package s3queue

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
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/cmd/opstools"
	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	testAccount   = "012345678912"
	testBucket    = "foo"
	testKey       = "bar"
	testS3Path    = "s3://" + testBucket + "/" + testKey
	testQueueName = "testQueue"
)

func TestS3Queue(t *testing.T) {
	s3Client := &testutils.S3Mock{}
	page := &s3.ListObjectsV2Output{
		Contents: []*s3.Object{
			{
				Size: aws.Int64(1), // 1 object of some size
				Key:  aws.String(testKey),
			},
		},
	}
	s3Client.On("ListObjectsV2Pages", mock.Anything, mock.Anything).Return(page, nil).Once()
	sqsClient := &testutils.SqsMock{}
	sqsClient.On("GetQueueUrl", mock.Anything).Return(&sqs.GetQueueUrlOutput{QueueUrl: aws.String("arn")}, nil).Once()
	sqsClient.On("SendMessageBatch", mock.Anything).Return(&sqs.SendMessageBatchOutput{}, nil).Once()

	input := &Input{
		DriverInput: DriverInput{
			Logger:      opstools.MustBuildLogger(false),
			Account:     testAccount,
			QueueName:   testQueueName,
			Concurrency: 1,
		},
		S3Path:   testS3Path,
		S3Region: s3Region,
	}
	err := s3Queue(context.TODO(), s3Client, sqsClient, input)
	require.NoError(t, err)
	s3Client.AssertExpectations(t)
	sqsClient.AssertExpectations(t)
	assert.Equal(t, uint64(1), input.Stats.NumFiles)
}

func TestS3QueueLimit(t *testing.T) {
	// list 2 objects but limit send to 1
	s3Client := &testutils.S3Mock{}
	page := &s3.ListObjectsV2Output{
		Contents: []*s3.Object{ // 2 objects
			{
				Size: aws.Int64(1),
				Key:  aws.String(testKey),
			},
			{
				Size: aws.Int64(1),
				Key:  aws.String(testKey),
			},
		},
	}
	s3Client.On("ListObjectsV2Pages", mock.Anything, mock.Anything).Return(page, nil).Once()
	sqsClient := &testutils.SqsMock{}
	sqsClient.On("GetQueueUrl", mock.Anything).Return(&sqs.GetQueueUrlOutput{QueueUrl: aws.String("arn")}, nil).Once()
	sqsClient.On("SendMessageBatch", mock.Anything).Return(&sqs.SendMessageBatchOutput{}, nil).Once()

	input := &Input{
		DriverInput: DriverInput{
			Logger:      opstools.MustBuildLogger(false),
			Account:     testAccount,
			QueueName:   testQueueName,
			Concurrency: 1,
		},
		S3Path:   testS3Path,
		S3Region: s3Region,
		Limit:    1,
	}
	err := s3Queue(context.TODO(), s3Client, sqsClient, input)
	require.NoError(t, err)
	s3Client.AssertExpectations(t)
	sqsClient.AssertExpectations(t)
	assert.Equal(t, uint64(1), input.Stats.NumFiles)
}

func TestS3QueuePaceAndDeadline(t *testing.T) {
	// concurrency 1, 10 files per second for 3+ seconds, should have 30 files sent then stop with a "context deadline exceeded" error
	var contents []*s3.Object
	for i := 0; i < 100; i++ { // generate more than what will be sent
		contents = append(contents, &s3.Object{
			Size: aws.Int64(1), // 1 object of some size
			Key:  aws.String(testKey),
		})
	}
	s3Client := &testutils.S3Mock{}
	page := &s3.ListObjectsV2Output{
		Contents: contents,
	}
	s3Client.On("ListObjectsV2Pages", mock.Anything, mock.Anything).Return(page, nil).Once()
	sqsClient := &testutils.SqsMock{}
	sqsClient.On("GetQueueUrl", mock.Anything).Return(&sqs.GetQueueUrlOutput{QueueUrl: aws.String("arn")}, nil).Once()
	sqsClient.On("SendMessageBatch", mock.Anything).Return(&sqs.SendMessageBatchOutput{}, nil).Times(3) // 3 batches of 10!

	input := &Input{
		DriverInput: DriverInput{
			Logger:         opstools.MustBuildLogger(false),
			Account:        testAccount,
			QueueName:      testQueueName,
			Concurrency:    1,
			FilesPerSecond: 10.0,
			Duration:       (time.Second * 3) + time.Second/2, // between 3 and 4 seconds
		},
		S3Path:   testS3Path,
		S3Region: s3Region,
	}
	err := s3Queue(context.TODO(), s3Client, sqsClient, input)
	require.Error(t, err)
	assert.Equal(t, "context deadline exceeded", err.Error())
	s3Client.AssertExpectations(t)
	sqsClient.AssertExpectations(t)
}

func TestS3QueueBatch(t *testing.T) {
	var contents []*s3.Object
	for i := 0; i < (2*10)+1; i++ { // batch size is 10, so 2 full batches and one partial
		contents = append(contents, &s3.Object{
			Size: aws.Int64(1), // 1 object of some size
			Key:  aws.String(testKey),
		})
	}
	s3Client := &testutils.S3Mock{}
	page := &s3.ListObjectsV2Output{
		Contents: contents,
	}
	s3Client.On("ListObjectsV2Pages", mock.Anything, mock.Anything).Return(page, nil).Once()
	sqsClient := &testutils.SqsMock{}
	sqsClient.On("GetQueueUrl", mock.Anything).Return(&sqs.GetQueueUrlOutput{QueueUrl: aws.String("arn")}, nil).Once()
	sqsClient.On("SendMessageBatch", mock.Anything).Return(&sqs.SendMessageBatchOutput{}, nil).Times(3)

	input := &Input{
		DriverInput: DriverInput{
			Logger:      opstools.MustBuildLogger(false),
			Account:     testAccount,
			QueueName:   testQueueName,
			Concurrency: 1,
		},
		S3Path:   testS3Path,
		S3Region: s3Region,
	}
	err := s3Queue(context.TODO(), s3Client, sqsClient, input)
	require.NoError(t, err)
	s3Client.AssertExpectations(t)
	sqsClient.AssertExpectations(t)
	assert.Equal(t, uint64(len(contents)), input.Stats.NumFiles)
}
