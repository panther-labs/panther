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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/outputs_api/table"
)

func TestAddOutputSameNameAlreadyExists(t *testing.T) {
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey
	mockOutputTable := &mockOutputTable{}
	outputsTable = mockOutputTable

	mockOutputTable.On("GetOutputByName", aws.String("my-channel")).Return(&table.AlertOutputItem{}, nil)

	input := &models.AddOutputInput{
		DisplayName:  aws.String("my-channel"),
		UserID:       aws.String("userId"),
		OutputConfig: &models.OutputConfig{Slack: &models.SlackConfig{WebhookURL: "hooks.slack.com"}},
	}

	result, err := (API{}).AddOutput(input)
	require.Nil(t, result)
	assert.Error(t, err)
	mockOutputTable.AssertExpectations(t)
	mockEncryptionKey.AssertExpectations(t)
}

func TestAddOutputPutOutputError(t *testing.T) {
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey
	mockOutputTable := &mockOutputTable{}
	outputsTable = mockOutputTable

	mockOutputTable.On("GetOutputByName", aws.String("my-channel")).Return(nil, nil)
	mockOutputTable.On("PutOutput", mock.Anything).Return(errors.New("internal error"))
	mockEncryptionKey.On("EncryptConfig", mock.Anything).Return(make([]byte, 1), nil)

	input := &models.AddOutputInput{
		UserID:       aws.String("userId"),
		DisplayName:  aws.String("my-channel"),
		OutputConfig: &models.OutputConfig{Slack: &models.SlackConfig{WebhookURL: "hooks.slack.com"}},
	}

	result, err := (API{}).AddOutput(input)
	assert.Nil(t, result)
	assert.Error(t, err)

	mockOutputTable.AssertExpectations(t)
	mockEncryptionKey.AssertExpectations(t)
}

func TestAddOutputSlack(t *testing.T) {
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey
	mockOutputTable := &mockOutputTable{}
	outputsTable = mockOutputTable

	mockOutputTable.On("GetOutputByName", aws.String("my-channel")).Return(nil, nil)
	mockEncryptionKey.On("EncryptConfig", mock.Anything).Return(make([]byte, 1), nil)
	mockOutputTable.On("PutOutput", mock.Anything).Return(nil)

	input := &models.AddOutputInput{
		UserID:             aws.String("userId"),
		DisplayName:        aws.String("my-channel"),
		OutputConfig:       &models.OutputConfig{Slack: &models.SlackConfig{WebhookURL: "hooks.slack.com"}},
		DefaultForSeverity: aws.StringSlice([]string{"CRITICAL", "HIGH"}),
		AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
	}

	result, err := (API{}).AddOutput(input)
	require.NoError(t, err)

	expected := &models.AddOutputOutput{
		DisplayName:        aws.String("my-channel"),
		OutputType:         aws.String("slack"),
		LastModifiedBy:     aws.String("userId"),
		CreatedBy:          aws.String("userId"),
		OutputConfig:       &models.OutputConfig{Slack: &models.SlackConfig{WebhookURL: ""}},
		OutputID:           result.OutputID,
		CreationTime:       result.CreationTime,
		LastModifiedTime:   result.LastModifiedTime,
		DefaultForSeverity: aws.StringSlice([]string{"CRITICAL", "HIGH"}),
		AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
	}
	assert.Equal(t, expected, result)

	_, err = uuid.Parse(*result.OutputID)
	assert.NoError(t, err)

	mockOutputTable.AssertExpectations(t)
	mockEncryptionKey.AssertExpectations(t)
}

func TestAddOutputSns(t *testing.T) {
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey
	mockOutputTable := &mockOutputTable{}
	outputsTable = mockOutputTable

	mockOutputTable.On("GetOutputByName", aws.String("my-topic")).Return(nil, nil)
	mockEncryptionKey.On("EncryptConfig", mock.Anything).Return(make([]byte, 1), nil)
	mockOutputTable.On("PutOutput", mock.Anything).Return(nil)

	input := &models.AddOutputInput{
		UserID:       aws.String("userId"),
		DisplayName:  aws.String("my-topic"),
		AlertTypes:   []string{deliverymodel.RuleType},
		OutputConfig: &models.OutputConfig{Sns: &models.SnsConfig{TopicArn: "arn:aws:sns:us-west-2:123456789012:MyTopic"}},
	}

	result, err := (API{}).AddOutput(input)
	require.NoError(t, err)

	expected := &models.AddOutputOutput{
		DisplayName:      aws.String("my-topic"),
		OutputType:       aws.String("sns"),
		LastModifiedBy:   aws.String("userId"),
		CreatedBy:        aws.String("userId"),
		AlertTypes:       []string{deliverymodel.RuleType},
		OutputConfig:     &models.OutputConfig{Sns: &models.SnsConfig{TopicArn: "arn:aws:sns:us-west-2:123456789012:MyTopic"}},
		OutputID:         result.OutputID,
		CreationTime:     result.CreationTime,
		LastModifiedTime: result.LastModifiedTime,
	}
	assert.Equal(t, expected, result)

	_, err = uuid.Parse(*result.OutputID)
	assert.NoError(t, err)
}

func TestAddOutputPagerDuty(t *testing.T) {
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey
	mockOutputTable := &mockOutputTable{}
	outputsTable = mockOutputTable

	mockOutputTable.On("GetOutputByName", aws.String("my-pagerduty-integration")).Return(nil, nil)
	mockEncryptionKey.On("EncryptConfig", mock.Anything).Return(make([]byte, 1), nil)
	mockOutputTable.On("PutOutput", mock.Anything).Return(nil)

	input := &models.AddOutputInput{
		UserID:       aws.String("userId"),
		DisplayName:  aws.String("my-pagerduty-integration"),
		AlertTypes:   []string{deliverymodel.RuleErrorType},
		OutputConfig: &models.OutputConfig{PagerDuty: &models.PagerDutyConfig{IntegrationKey: "93ee508cbfea4604afe1c77c2d9b5bbd"}},
	}

	result, err := (API{}).AddOutput(input)
	require.NoError(t, err)

	expected := &models.AddOutputOutput{
		DisplayName:    aws.String("my-pagerduty-integration"),
		OutputType:     aws.String("pagerduty"),
		LastModifiedBy: aws.String("userId"),
		CreatedBy:      aws.String("userId"),
		AlertTypes:     []string{deliverymodel.RuleErrorType},
		OutputConfig: &models.OutputConfig{
			PagerDuty: &models.PagerDutyConfig{
				IntegrationKey: "",
			},
		},
		OutputID:         result.OutputID,
		CreationTime:     result.CreationTime,
		LastModifiedTime: result.LastModifiedTime,
	}
	assert.Equal(t, expected, result)

	_, err = uuid.Parse(*result.OutputID)
	assert.NoError(t, err)
}

func TestAddOutputSqs(t *testing.T) {
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey
	mockOutputTable := &mockOutputTable{}
	outputsTable = mockOutputTable

	mockOutputTable.On("GetOutputByName", aws.String("my-queue")).Return(nil, nil)
	mockEncryptionKey.On("EncryptConfig", mock.Anything).Return(make([]byte, 1), nil)
	mockOutputTable.On("PutOutput", mock.Anything).Return(nil)

	input := &models.AddOutputInput{
		UserID:      aws.String("userId"),
		DisplayName: aws.String("my-queue"),
		AlertTypes:  []string{deliverymodel.PolicyType},
		OutputConfig: &models.OutputConfig{
			Sqs: &models.SqsConfig{
				QueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/test-output",
			},
		},
	}

	result, err := (API{}).AddOutput(input)
	require.NoError(t, err)

	expected := &models.AddOutputOutput{
		DisplayName:    aws.String("my-queue"),
		OutputType:     aws.String("sqs"),
		LastModifiedBy: aws.String("userId"),
		CreatedBy:      aws.String("userId"),
		AlertTypes:     []string{deliverymodel.PolicyType},
		OutputConfig: &models.OutputConfig{
			Sqs: &models.SqsConfig{
				QueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/test-output",
			},
		},
		OutputID:         result.OutputID,
		CreationTime:     result.CreationTime,
		LastModifiedTime: result.LastModifiedTime,
	}
	assert.Equal(t, expected, result)

	_, err = uuid.Parse(*result.OutputID)
	assert.NoError(t, err)
}

func TestAddOutputAsana(t *testing.T) {
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey
	mockOutputTable := &mockOutputTable{}
	outputsTable = mockOutputTable

	mockOutputTable.On("GetOutputByName", aws.String("my-asana-destination")).Return(nil, nil)
	mockEncryptionKey.On("EncryptConfig", mock.Anything).Return(make([]byte, 1), nil)
	mockOutputTable.On("PutOutput", mock.Anything).Return(nil)

	input := &models.AddOutputInput{
		UserID:      aws.String("userId"),
		DisplayName: aws.String("my-asana-destination"),
		AlertTypes:  []string{deliverymodel.PolicyType},
		OutputConfig: &models.OutputConfig{
			Asana: &models.AsanaConfig{
				PersonalAccessToken: "0/8c26ac5222d539ca0ad7000000000000",
				ProjectGids:         []string{""},
			},
		},
	}

	result, err := (API{}).AddOutput(input)
	require.NoError(t, err)

	expected := &models.AddOutputOutput{
		DisplayName:    aws.String("my-asana-destination"),
		OutputType:     aws.String("asana"),
		LastModifiedBy: aws.String("userId"),
		CreatedBy:      aws.String("userId"),
		AlertTypes:     []string{deliverymodel.PolicyType},
		OutputConfig: &models.OutputConfig{
			Asana: &models.AsanaConfig{
				PersonalAccessToken: "",
				ProjectGids:         []string{""},
			},
		},
		OutputID:         result.OutputID,
		CreationTime:     result.CreationTime,
		LastModifiedTime: result.LastModifiedTime,
	}
	assert.Equal(t, expected, result)

	_, err = uuid.Parse(*result.OutputID)
	assert.NoError(t, err)
}
