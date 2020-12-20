package s3sns

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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/cmd/opstools"
	"github.com/panther-labs/panther/pkg/testutils"
)

const (
	testAccount = "012345678912"
	testBucket  = "foo"
	testKey     = "bar"
	testS3Path  = "s3://" + testBucket + "/" + testKey
	topic       = "testTopic"
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
	snsClient := &testutils.SnsMock{}
	snsClient.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Once()

	input := &Input{
		Logger:      opstools.MustBuildLogger(false),
		Session:     &session.Session{Config: &aws.Config{Region: aws.String("someregion")}},
		Account:     testAccount,
		S3Path:      testS3Path,
		Topic:       topic,
		Concurrency: 1,
	}
	err := s3sns(context.TODO(), s3Client, snsClient, nil, input)
	require.NoError(t, err)
	s3Client.AssertExpectations(t)
	snsClient.AssertExpectations(t)
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
	snsClient := &testutils.SnsMock{}
	snsClient.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, nil).Once()

	input := &Input{
		Logger:      opstools.MustBuildLogger(false),
		Session:     &session.Session{Config: &aws.Config{Region: aws.String("someregion")}},
		Account:     testAccount,
		S3Path:      testS3Path,
		Topic:       topic,
		Concurrency: 1,
		Limit:       1,
	}
	err := s3sns(context.TODO(), s3Client, snsClient, nil, input)
	require.NoError(t, err)
	s3Client.AssertExpectations(t)
	snsClient.AssertExpectations(t)
	assert.Equal(t, uint64(1), input.Stats.NumFiles)
}
