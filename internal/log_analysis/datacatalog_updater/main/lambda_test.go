package main

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
)

func TestProcessSuccess(t *testing.T) {
	mockClient := &mockGlue{}
	glueClient = mockClient

	mockClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, nil)
	assert.NoError(t, process(getEvent(t, "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz")))
	mockClient.AssertExpectations(t)
}

func TestProcessGlueFailure(t *testing.T) {
	mockClient := &mockGlue{}
	glueClient = mockClient

	mockClient.On("CreatePartition", mock.Anything).Return(&glue.CreatePartitionOutput{}, errors.New("error"))
	assert.Error(t, process(getEvent(t, "rules/table/year=2020/month=02/day=26/hour=15/rule_id=Rule.Id/item.json.gz")))
	mockClient.AssertExpectations(t)
}

func TestProcessInvalidS3Key(t *testing.T) {
	//Invalid keys should just be ignored
	assert.NoError(t, process(getEvent(t, "test")))
}

func getEvent(t *testing.T, s3Keys ...string) events.SQSEvent {
	result := events.SQSEvent{Records: []events.SQSMessage{}}
	for _, s3Key := range s3Keys {
		s3Notification := &models.S3Notification{
			S3Bucket:    aws.String("bucket"),
			S3ObjectKey: aws.String(s3Key),
			Type:        aws.String(models.LogData.String()),
			ID:          aws.String("test"),
		}
		serialized, err := jsoniter.MarshalToString(s3Notification)
		require.NoError(t, err)
		event := events.SQSMessage{
			Body: serialized,
		}
		result.Records = append(result.Records, event)
	}
	return result
}

type mockGlue struct {
	glueiface.GlueAPI
	mock.Mock
}

func (m *mockGlue) CreatePartition(input *glue.CreatePartitionInput) (*glue.CreatePartitionOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*glue.CreatePartitionOutput), args.Error(1)
}
