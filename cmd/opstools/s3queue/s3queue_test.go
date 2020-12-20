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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/cmd/opstools"
)

const (
	testAccount   = "012345678912"
	testBucket    = "foo"
	testKey       = "bar"
	testS3Path    = "s3://" + testBucket + "/" + testKey
	testQueueName = "testQueue"
)

func TestS3Queue(t *testing.T) {
	s3Client := &mockS3{}
	page := &s3.ListObjectsV2Output{
		Contents: []*s3.Object{
			{
				Size: aws.Int64(1), // 1 object of some size
				Key:  aws.String(testKey),
			},
		},
	}
	s3Client.On("ListObjectsV2Pages", mock.Anything, mock.Anything).Return(page, nil).Once()
	sqsClient := &mockSQS{}
	sqsClient.On("GetQueueUrl", mock.Anything).Return(&sqs.GetQueueUrlOutput{QueueUrl: aws.String("arn")}, nil).Once()
	sqsClient.On("SendMessageBatch", mock.Anything).Return(&sqs.SendMessageBatchOutput{}, nil).Once()

	input := &Input{
		Logger:      opstools.MustBuildLogger(false),
		Account:     testAccount,
		S3Path:      testS3Path,
		S3Region:    s3Region,
		QueueName:   testQueueName,
		Concurrency: 1,
	}
	err := s3Queue(context.TODO(), s3Client, sqsClient, input)
	require.NoError(t, err)
	s3Client.AssertExpectations(t)
	sqsClient.AssertExpectations(t)
	assert.Equal(t, uint64(1), input.Stats.NumFiles)
}

func TestS3QueueLimit(t *testing.T) {
	// list 2 objects but limit send to 1
	s3Client := &mockS3{}
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
	sqsClient := &mockSQS{}
	sqsClient.On("GetQueueUrl", mock.Anything).Return(&sqs.GetQueueUrlOutput{QueueUrl: aws.String("arn")}, nil).Once()
	sqsClient.On("SendMessageBatch", mock.Anything).Return(&sqs.SendMessageBatchOutput{}, nil).Once()

	input := &Input{
		Logger:      opstools.MustBuildLogger(false),
		Account:     testAccount,
		S3Path:      testS3Path,
		S3Region:    s3Region,
		QueueName:   testQueueName,
		Concurrency: 1,
		Limit:       1,
	}
	err := s3Queue(context.TODO(), s3Client, sqsClient, input)
	require.NoError(t, err)
	s3Client.AssertExpectations(t)
	sqsClient.AssertExpectations(t)
	assert.Equal(t, uint64(1), input.Stats.NumFiles)
}

func TestS3QueueBatch(t *testing.T) {
	var contents []*s3.Object
	for i := 0; i < (2*10)+1; i++ { // batch size is 10, so 2 full batches and one partial
		contents = append(contents, &s3.Object{
			Size: aws.Int64(1), // 1 object of some size
			Key:  aws.String(testKey),
		})
	}
	s3Client := &mockS3{}
	page := &s3.ListObjectsV2Output{
		Contents: contents,
	}
	s3Client.On("ListObjectsV2Pages", mock.Anything, mock.Anything).Return(page, nil).Once()
	sqsClient := &mockSQS{}
	sqsClient.On("GetQueueUrl", mock.Anything).Return(&sqs.GetQueueUrlOutput{QueueUrl: aws.String("arn")}, nil).Once()
	sqsClient.On("SendMessageBatch", mock.Anything).Return(&sqs.SendMessageBatchOutput{}, nil).Times(3)

	input := &Input{
		Logger:      opstools.MustBuildLogger(false),
		Account:     testAccount,
		S3Path:      testS3Path,
		S3Region:    s3Region,
		QueueName:   testQueueName,
		Concurrency: 1,
	}
	err := s3Queue(context.TODO(), s3Client, sqsClient, input)
	require.NoError(t, err)
	s3Client.AssertExpectations(t)
	sqsClient.AssertExpectations(t)
	assert.Equal(t, uint64(len(contents)), input.Stats.NumFiles)
}

type mockS3 struct {
	s3iface.S3API
	mock.Mock
}

func (m *mockS3) ListObjectsV2Pages(input *s3.ListObjectsV2Input, f func(page *s3.ListObjectsV2Output, morePages bool) bool) error {
	args := m.Called(input, f)
	f(args.Get(0).(*s3.ListObjectsV2Output), false)
	return args.Error(1)
}

type mockSQS struct {
	sqsiface.SQSAPI
	mock.Mock
}

// nolint (golint)
func (m *mockSQS) GetQueueUrl(input *sqs.GetQueueUrlInput) (*sqs.GetQueueUrlOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.GetQueueUrlOutput), args.Error(1)
}

func (m *mockSQS) SendMessageBatch(input *sqs.SendMessageBatchInput) (*sqs.SendMessageBatchOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.SendMessageBatchOutput), args.Error(1)
}
