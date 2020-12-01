package processor

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
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/pkg/testutils"
)

func TestScaleup(t *testing.T) {
	sqsClient := &testutils.SqsMock{}
	lambdaClient := &testutils.LambdaMock{}

	var wg sync.WaitGroup
	// we want to wait for 2 executions of the scale up go routine
	wg.Add(2)
	// this is what we return showing a queue size big enough to scale
	spikeCount := processingQueueIncreaseThreshold * 2
	streamTestSpikeInEventsQueue := &sqs.GetQueueAttributesOutput{
		Attributes: map[string]*string{
			sqs.QueueAttributeNameApproximateNumberOfMessages: aws.String(strconv.Itoa(spikeCount)),
		},
	}

	streamTestEmptyQueue := &sqs.GetQueueAttributesOutput{
		Attributes: map[string]*string{
			sqs.QueueAttributeNameApproximateNumberOfMessages: aws.String("0"),
		},
	}

	// the scaleup go routine will check the queue, then execute a lambda
	sqsClient.On("GetQueueAttributesWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(streamTestSpikeInEventsQueue, nil).Once().
		Run(func(args mock.Arguments) {
			wg.Done()
		})
	lambdaClient.On("InvokeWithContext", mock.Anything, mock.Anything, mock.Anything).Return(&lambda.InvokeOutput{}, nil).Times(1)

	// this will return a number for the queue size smaller than needed to scale, so no lambda calls
	sqsClient.On("GetQueueAttributesWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(streamTestEmptyQueue, nil).Once().
		Run(func(args mock.Arguments) {
			wg.Done()
		})

	// The method might be called again depending on sync issues
	sqsClient.On("GetQueueAttributesWithContext", mock.Anything, mock.Anything, mock.Anything).Return(streamTestEmptyQueue, nil).Maybe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go RunScalingDecisions(ctx, sqsClient, lambdaClient, time.Millisecond)
	wg.Wait()
	sqsClient.AssertExpectations(t)
	lambdaClient.AssertExpectations(t)
}
