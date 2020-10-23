package main

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
	"time"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/testutils"
)

var (
	messagesBelowThreshold = &sqs.GetQueueAttributesOutput{
		Attributes: map[string]*string{
			sqs.QueueAttributeNameApproximateNumberOfMessages:        aws.String("0"),
			sqs.QueueAttributeNameApproximateNumberOfMessagesDelayed: aws.String("0"),
		},
	}
)

// Replace global logger with an in-memory observer for tests.
func mockLogger() *observer.ObservedLogs {
	core, mockLog := observer.New(zap.DebugLevel)
	zap.ReplaceGlobals(zap.New(core))
	return mockLog
}

func TestProcessOpLog(t *testing.T) {
	common.Config.AwsLambdaFunctionMemorySize = 1024
	logs := mockLogger()
	functionName := "myfunction"
	lc := lambdacontext.LambdaContext{
		InvokedFunctionArn: functionName,
	}

	sqsMock := &testutils.SqsMock{}
	common.SqsClient = sqsMock
	// will be called by scalingDecisions() on exit
	sqsMock.On("GetQueueAttributes", mock.Anything).Return(messagesBelowThreshold, nil).Once()

	err := process(&lc, time.Now())
	require.NoError(t, err)
	message := common.OpLogNamespace + ":" + common.OpLogComponent + ":" + functionName
	require.Equal(t, 1, len(logs.FilterMessage(message).All())) // should be just one like this
	assert.Equal(t, zapcore.InfoLevel, logs.FilterMessage(message).All()[0].Level)
	assert.Equal(t, message, logs.FilterMessage(message).All()[0].Entry.Message)
	serviceDim := logs.FilterMessage(message).All()[0].ContextMap()[common.OpLogLambdaServiceDim.Key]
	assert.Equal(t, common.OpLogLambdaServiceDim.String, serviceDim)

	time.Sleep(time.Second / 2) // allow time for all go routines to terminate
	sqsMock.AssertExpectations(t)
}
