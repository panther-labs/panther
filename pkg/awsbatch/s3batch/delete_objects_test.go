package s3batch

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/stretchr/testify/assert"
)

type mockS3 struct {
	s3iface.S3API
	unprocessedItems bool // If True, only the first item in each batch will succeed
	err              error
	callCount        int // Counts the number of DeleteObjects calls for tests to verify
}

func (m *mockS3) DeleteObjects(input *s3.DeleteObjectsInput) (*s3.DeleteObjectsOutput, error) {
	m.callCount++

	if m.err != nil {
		return nil, m.err
	}

	result := &s3.DeleteObjectsOutput{}
	for i, object := range input.Delete.Objects {
		if i == 0 || !m.unprocessedItems {
			// Success if this is first record or failure not requested
			result.Deleted = append(result.Deleted, &s3.DeletedObject{
				Key:       object.Key,
				VersionId: object.VersionId,
			})
		} else {
			// All other records fail
			result.Errors = append(result.Errors, &s3.Error{
				Code:      aws.String("InternalError"),
				Key:       object.Key,
				Message:   aws.String("something went wrong"),
				VersionId: object.VersionId,
			})
		}
	}
	return result, nil
}

func testInput() *s3.DeleteObjectsInput {
	return &s3.DeleteObjectsInput{
		Bucket: aws.String("test-bucket"),
		Delete: &s3.Delete{
			Objects: []*s3.ObjectIdentifier{
				{Key: aws.String("k1"), VersionId: aws.String("v1")},
				{Key: aws.String("k2"), VersionId: aws.String("v2")},
			},
		},
	}
}

func TestDeleteObjects(t *testing.T) {
	client := &mockS3{}
	assert.Nil(t, DeleteObjects(client, 5*time.Second, testInput()))
	assert.Equal(t, 1, client.callCount)
}

// Unprocessed items are retried
func TestDeleteObjectsBackoff(t *testing.T) {
	client := &mockS3{unprocessedItems: true}
	assert.Nil(t, DeleteObjects(client, 5*time.Second, testInput()))
	assert.Equal(t, 2, client.callCount)
}

// Service errors are not retried
func TestDeleteObjectsPermanentError(t *testing.T) {
	client := &mockS3{err: errors.New("permanent")}
	assert.NotNil(t, DeleteObjects(client, 5*time.Second, testInput()))
	assert.Equal(t, 1, client.callCount)
}

// A large number of records are broken into multiple requests
func TestDeleteObjectsPagination(t *testing.T) {
	client := &mockS3{}
	input := &s3.DeleteObjectsInput{
		Delete: &s3.Delete{Objects: make([]*s3.ObjectIdentifier, maxObjects*2+1)},
	}
	for i := range input.Delete.Objects {
		input.Delete.Objects[i] = &s3.ObjectIdentifier{
			Key: aws.String("k1"), VersionId: aws.String("v1")}
	}
	assert.Nil(t, DeleteObjects(client, 5*time.Second, input))
	assert.Equal(t, 3, client.callCount)
}
