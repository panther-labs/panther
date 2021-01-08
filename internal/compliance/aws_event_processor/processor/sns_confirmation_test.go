package processor

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// request from an unknown account is rejected
func TestHandleSnsConfirmationUnknownAccount(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	require.NoError(t, handleSnsConfirmation(arn.ARN{AccountID: "no-such-account"}, nil))

	expected := []observer.LoggedEntry{
		{
			Entry:   zapcore.Entry{Level: zapcore.WarnLevel, Message: "refusing sns confirmation from unknown account"},
			Context: []zapcore.Field{zap.String("accountId", "no-such-account")},
		},
	}
	assert.Equal(t, expected, logs.AllUntimed())
}

func TestHandleSnsConfirmationNoToken(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	require.NoError(t, handleSnsConfirmation(arn.ARN{AccountID: "111111111111"}, nil))

	expected := []observer.LoggedEntry{
		{
			Entry:   zapcore.Entry{Level: zapcore.WarnLevel, Message: "no sns confirmation token"},
			Context: []zapcore.Field{zap.String("topicArn", "arn::::111111111111:")},
		},
	}
	assert.Equal(t, expected, logs.AllUntimed())
}

// client creation failed
func TestHandleSnsConfirmationCreateFailed(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	returnErr := errors.New("no such region")
	snsClientBuilder = func(*string) (snsiface.SNSAPI, error) {
		return nil, returnErr
	}
	require.Error(t, handleSnsConfirmation(arn.ARN{AccountID: "111111111111"}, aws.String("token")))

	expected := []observer.LoggedEntry{
		{
			Entry:   zapcore.Entry{Level: zapcore.InfoLevel, Message: "confirming sns subscription"},
			Context: []zapcore.Field{zap.String("topicArn", "arn::::111111111111:")},
		},
		{
			Entry:   zapcore.Entry{Level: zapcore.ErrorLevel, Message: "sns client creation failed"},
			Context: []zapcore.Field{zap.Error(returnErr)},
		},
	}
	assert.Equal(t, expected, logs.AllUntimed())
}

// error is returned if the confirmation failed
func TestHandleSnsConfirmationConfirmationFailed(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	returnErr := errors.New("topic does not exist")
	mockSnsClient := &mockSns{}
	mockSnsClient.
		On("ConfirmSubscription", mock.Anything).
		Return((*sns.ConfirmSubscriptionOutput)(nil), returnErr)
	snsClientBuilder = func(*string) (snsiface.SNSAPI, error) {
		return mockSnsClient, nil
	}

	require.Error(t, handleSnsConfirmation(arn.ARN{AccountID: "111111111111"}, aws.String("token")))
	mockSnsClient.AssertExpectations(t)

	expected := []observer.LoggedEntry{
		{
			Entry:   zapcore.Entry{Level: zapcore.InfoLevel, Message: "confirming sns subscription"},
			Context: []zapcore.Field{zap.String("topicArn", "arn::::111111111111:")},
		},
		{
			Entry:   zapcore.Entry{Level: zapcore.ErrorLevel, Message: "sns confirmation failed"},
			Context: []zapcore.Field{zap.Error(returnErr)},
		},
	}
	assert.Equal(t, expected, logs.AllUntimed())
}

func TestHandleSnsConfirmation(t *testing.T) {
	logs := mockLogger()
	accounts = exampleAccounts
	mockSnsClient := &mockSns{}
	expectedInput := &sns.ConfirmSubscriptionInput{
		Token:    aws.String("secret-token"),
		TopicArn: aws.String("arn:aws:sns:us-west-2:111111111111:PantherEvents"),
	}
	output := &sns.ConfirmSubscriptionOutput{SubscriptionArn: aws.String("your-new-arn")}
	mockSnsClient.On("ConfirmSubscription", expectedInput).Return(output, nil)
	snsClientBuilder = func(*string) (snsiface.SNSAPI, error) {
		return mockSnsClient, nil
	}

	topicArn := arn.ARN{
		Partition: "aws",
		Service:   "sns",
		Region:    "us-west-2",
		AccountID: "111111111111",
		Resource:  "PantherEvents",
	}
	require.NoError(t, handleSnsConfirmation(topicArn, aws.String("secret-token")))
	mockSnsClient.AssertExpectations(t)

	expected := []observer.LoggedEntry{
		{
			Entry:   zapcore.Entry{Level: zapcore.InfoLevel, Message: "confirming sns subscription"},
			Context: []zapcore.Field{zap.String("topicArn", topicArn.String())},
		},
		{
			Entry:   zapcore.Entry{Level: zapcore.InfoLevel, Message: "sns subscription confirmed successfully"},
			Context: []zapcore.Field{zap.String("subscriptionArn", "your-new-arn")},
		},
	}
	assert.Equal(t, expected, logs.AllUntimed())
}

func TestBuildSnsClient(t *testing.T) {
	result, err := buildSnsClient(aws.String("us-west-2"))
	require.NoError(t, err)
	assert.NotNil(t, result)
}
