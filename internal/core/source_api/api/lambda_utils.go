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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	messageForwarderLambda = "panther-message-forwarder"
)

func (api *API) AddSourceAsLambdaTrigger(integrationID string) error {
	input := &lambda.CreateEventSourceMappingInput{
		EventSourceArn: aws.String(api.SourceSqsQueueArn(integrationID)),
		FunctionName:   aws.String(messageForwarderLambda),
		Enabled:        aws.Bool(true),
	}
	_, err := api.LambdaClient.CreateEventSourceMapping(input)
	if err != nil {
		return errors.Wrap(err, "failed to configure new trigger for message forwarder lambda")
	}
	return nil
}

func (api *API) RemoveSourceFromLambdaTrigger(integrationID string) error {
	listInput := &lambda.ListEventSourceMappingsInput{
		FunctionName:   aws.String(messageForwarderLambda),
		EventSourceArn: aws.String(api.SourceSqsQueueArn(integrationID)),
		MaxItems:       aws.Int64(1),
	}
	listOutput, err := api.LambdaClient.ListEventSourceMappings(listInput)
	if err != nil {
		return errors.Wrap(err, "failed to list lambda event mappings")
	}

	if len(listOutput.EventSourceMappings) == 0 {
		zap.L().Debug("the panther-message-forwarder lambda doesn't have an event source for the specific integration",
			zap.String("integrationId", integrationID))
		return nil
	}
	eventSourceUUID := listOutput.EventSourceMappings[0].UUID

	deleteInput := &lambda.DeleteEventSourceMappingInput{
		UUID: eventSourceUUID,
	}
	_, err = api.LambdaClient.DeleteEventSourceMapping(deleteInput)
	if err != nil {
		return errors.Wrap(err, "failed to delete source mapping")
	}

	return nil
}
