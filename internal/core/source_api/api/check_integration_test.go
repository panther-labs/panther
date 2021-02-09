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
	"github.com/pkg/errors"
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
	prefixLogTypes := []models.S3PrefixLogtypesMapping{{
		S3Prefix: "prefix/",
		LogTypes: []string{"Some.LogType"}},
	}
	listInput := &s3.ListObjectsInput{
		Bucket:              aws.String("bucket-name"),
		ExpectedBucketOwner: aws.String("bucket-owner"),
		MaxKeys:             aws.Int64(1),
		Prefix:              aws.String(prefixLogTypes[0].S3Prefix),
	}
	headInput := &s3.HeadObjectInput{
		Bucket:              aws.String("bucket-name"),
		ExpectedBucketOwner: aws.String("bucket-owner"),
		Key:                 aws.String("prefixa/file.log"),
	}

	t.Run("healthy", func(t *testing.T) {
		s3Client := &testutils.S3Mock{}
		listOutput := s3.ListObjectsOutput{
			Contents: []*s3.Object{{Key: aws.String("prefixa/file.log")}},
		}
		s3Client.On("ListObjects", listInput).Return(&listOutput, nil)
		s3Client.On("HeadObject", headInput).Return(&s3.HeadObjectOutput{}, nil)

		input := &models.CheckIntegrationInput{
			AWSAccountID:      "bucket-owner",
			S3Bucket:          "bucket-name",
			S3PrefixLogTypes:  prefixLogTypes,
			PantherVersionStr: "1.16.0-dev",
		}
		health, _ := checkGetObject(s3Client, input)

		s3Client.AssertExpectations(t)
		require.True(t, health.Healthy)
	})

	t.Run("not skipped", func(t *testing.T) {
		s3Client := &testutils.S3Mock{}
		s3Client.On("ListObjects", listInput).Return(&s3.ListObjectsOutput{}, nil)

		input := &models.CheckIntegrationInput{
			AWSAccountID:      "bucket-owner",
			S3Bucket:          "bucket-name",
			S3PrefixLogTypes:  prefixLogTypes,
			PantherVersionStr: "1.17.0",
		}
		_, skipped := checkGetObject(s3Client, input)

		require.False(t, skipped)
	})

	t.Run("skipped", func(t *testing.T) {
		s3Client := &testutils.S3Mock{}

		input := &models.CheckIntegrationInput{
			AWSAccountID:      "bucket-owner",
			S3Bucket:          "bucket-name",
			S3PrefixLogTypes:  prefixLogTypes,
			PantherVersionStr: "1.15.x",
		}
		_, skipped := checkGetObject(s3Client, input)

		require.True(t, skipped)
	})

	t.Run("ListObjects error", func(t *testing.T) {
		s3Client := &testutils.S3Mock{}
		s3Client.On("ListObjects", listInput).Return(&s3.ListObjectsOutput{}, errors.New("ListObjects error"))

		input := &models.CheckIntegrationInput{
			AWSAccountID:      "bucket-owner",
			S3Bucket:          "bucket-name",
			S3PrefixLogTypes:  prefixLogTypes,
			PantherVersionStr: "1.16.0",
		}

		health, skipped := checkGetObject(s3Client, input)

		s3Client.AssertExpectations(t)
		require.False(t, skipped)
		require.False(t, health.Healthy)
		require.Equal(t, "s3.ListObjects request failed: ListObjects error", health.ErrorMessage)
	})

	t.Run("HeadObject error", func(t *testing.T) {
		s3Client := &testutils.S3Mock{}
		listOutput := &s3.ListObjectsOutput{
			Contents: []*s3.Object{{Key: aws.String("prefixa/file.log")}},
		}
		s3Client.On("ListObjects", listInput).Return(listOutput, nil)
		s3Client.On("HeadObject", headInput).
			Return(&s3.HeadObjectOutput{}, mockAWSError("AccessDenied"))

		input := &models.CheckIntegrationInput{
			AWSAccountID:      "bucket-owner",
			S3Bucket:          "bucket-name",
			S3PrefixLogTypes:  prefixLogTypes,
			PantherVersionStr: "1.16.0",
		}
		health, _ := checkGetObject(s3Client, input)

		expected := models.SourceIntegrationItemStatus{
			Healthy:      false,
			Message:      "Failed to read S3 object",
			ErrorMessage: "s3.HeadObject request failed for prefixa/file.log: AccessDenied",
		}
		require.Equal(t, expected, health)
		s3Client.AssertExpectations(t)
	})
}
