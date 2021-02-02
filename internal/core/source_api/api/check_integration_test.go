package api

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

type mockAWSError string

func (e mockAWSError) Error() string   { return string(e) }
func (e mockAWSError) Code() string    { return string(e) }
func (e mockAWSError) Message() string { panic("implement me") }
func (e mockAWSError) OrigErr() error  { panic("implement me") }

var _ awserr.Error = (*mockAWSError)(nil)

func Test_CheckGetObject(t *testing.T) {
	listInput := &s3.ListObjectsInput{
		Bucket:              aws.String("bucket-name"),
		ExpectedBucketOwner: aws.String("bucket-owner"),
		MaxKeys:             aws.Int64(1),
	}
	getInput := &s3.GetObjectInput{
		Bucket:              aws.String("bucket-name"),
		ExpectedBucketOwner: aws.String("bucket-owner"),
		Key:                 aws.String("panther-health-check"),
	}

	t.Run("healthy", func(t *testing.T) {
		s3Client := &testutils.S3Mock{}
		s3Client.On("ListObjects", listInput).Return(&s3.ListObjectsOutput{}, nil)
		s3Client.On("GetObject", getInput).Return(&s3.GetObjectOutput{}, nil)

		health := checkGetObject(s3Client, "bucket-name", "bucket-owner")

		s3Client.AssertExpectations(t)
		require.True(t, health.Healthy)
	})
	t.Run(s3.ErrCodeNoSuchKey, func(t *testing.T) {
		s3Client := &testutils.S3Mock{}
		s3Client.On("ListObjects", listInput).Return(&s3.ListObjectsOutput{}, nil)
		s3Client.On("GetObject", getInput).
			Return(&s3.GetObjectOutput{}, mockAWSError(s3.ErrCodeNoSuchKey))

		health := checkGetObject(s3Client, "bucket-name", "bucket-owner")

		s3Client.AssertExpectations(t)
		require.True(t, health.Healthy)
	})
	t.Run("AccessDenied", func(t *testing.T) {
		mockErr := mockAWSError("AccessDenied")
		s3Client := &testutils.S3Mock{}
		s3Client.On("ListObjects", listInput).Return(&s3.ListObjectsOutput{}, nil)
		s3Client.On("GetObject", getInput).
			Return(&s3.GetObjectOutput{}, &mockErr)

		health := checkGetObject(s3Client, "bucket-name", "bucket-owner")

		expected := models.SourceIntegrationItemStatus{
			Healthy:      false,
			Message:      "Unexpected error returned from s3.GetObject",
			ErrorMessage: mockErr.Error(),
		}

		s3Client.AssertExpectations(t)
		require.Equal(t, expected, health)
	})
}
