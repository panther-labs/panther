package pollers

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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	api "github.com/panther-labs/panther/api/lambda/resources/models"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	pollers "github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/oplog"
)

const resourcesAPIBatchSize = 500

// loadMessage marshals the incoming SQS message into a ScanMsg.
func loadMessage(messageBody string) (*pollermodels.ScanMsg, error) {
	msg := &pollermodels.ScanMsg{}
	err := jsoniter.Unmarshal([]byte(messageBody), msg)
	if err != nil {
		return nil, err
	}

	return msg, err
}

// batchResources creates groups of 500 resources to send to the ResourcesAPI.
func batchResources(resources []api.AddResourceEntry) (batches [][]api.AddResourceEntry) {
	for resourcesAPIBatchSize < len(resources) {
		resources, batches = resources[resourcesAPIBatchSize:], append(
			batches,
			resources[0:resourcesAPIBatchSize:resourcesAPIBatchSize],
		)
	}
	batches = append(batches, resources)
	return
}

// Replaced by unit tests with an in-memory logger
var loggerSetupFunc = func(ctx context.Context, initialFields map[string]interface{}) *lambdacontext.LambdaContext {
	lc, _ := lambdalogger.ConfigureGlobal(ctx, initialFields)
	return lc
}

// Handle is the main Lambda Handler.
func Handle(ctx context.Context, event events.SQSEvent) (err error) {
	lc := loggerSetupFunc(ctx, nil)
	operation := oplog.NewManager("cloudsec", "snapshot").
		Start(lc.InvokedFunctionArn).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err, zap.Int("numEvents", len(event.Records)))
	}()

	for indx, message := range event.Records {
		scanRequest, loadErr := loadMessage(message.Body)
		if loadErr != nil || scanRequest == nil {
			operation.LogError(errors.Wrap(loadErr, "unable to load message from the queue"),
				zap.Int("messageNumber", indx),
				zap.String("messageBody", message.Body),
			)
			// This message is badly formatted, so don't bother re-trying it
			continue
		}

		for _, entry := range scanRequest.Entries {
			zap.L().Debug("starting poller",
				zap.Any("sqsEntry", entry),
				zap.Int("messageNumber", indx),
				zap.String("integrationType", "aws"))

			resources, pollErr := pollers.Poll(entry)
			if pollErr != nil {
				operation.LogError(errors.Wrap(pollErr, "poll failed"), zap.Any("sqsEntry", entry))
				return pollErr
			}

			// Send data to the Resources API
			if len(resources) > 0 {
				zap.L().Debug("total resources generated",
					zap.Int("messageNumber", indx),
					zap.Int("numResources", len(resources)),
					zap.String("integrationType", "aws"),
				)

				for _, batch := range batchResources(resources) {
					params := api.LambdaInput{
						AddResources: &api.AddResourcesInput{Resources: batch},
					}
					zap.L().Debug("adding new resources", zap.Any("batch", batch))
					if _, err = apiClient.Invoke(&params, nil); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}
