package s3batch

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
