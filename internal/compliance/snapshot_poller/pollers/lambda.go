package pollers

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
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/resources/client/operations"
	api "github.com/panther-labs/panther/api/gateway/resources/models"
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
func batchResources(resources []*api.AddResourceEntry) (batches [][]*api.AddResourceEntry) {
	for resourcesAPIBatchSize < len(resources) {
		resources, batches = resources[resourcesAPIBatchSize:], append(
			batches,
			resources[0:resourcesAPIBatchSize:resourcesAPIBatchSize],
		)
	}
	batches = append(batches, resources)
	return
}

// Handle is the main Lambda Handler.
func Handle(ctx context.Context, event events.SQSEvent) (err error) {
	lc, _ := lambdalogger.ConfigureGlobal(ctx, nil)
	operation := oplog.NewManager("cloudsec", "snapshot").Start(lc.InvokedFunctionArn).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err, zap.Int("numEvents", len(event.Records)))
	}()

	for indx, message := range event.Records {
		zap.L().Debug("loading message from the queue")
		scanRequest, loadErr := loadMessage(message.Body)
		if loadErr != nil || scanRequest == nil {
			operation.LogError(errors.Wrap(loadErr, "unable to load message from the queue"),
				zap.Int("messageNumber", indx),
				zap.String("messageBody", message.Body),
			)
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
				continue
			}

			// Send data to the Resources API
			if resources != nil {
				zap.L().Debug("total resources generated",
					zap.Int("messageNumber", indx),
					zap.Int("numResources", len(resources)),
					zap.String("integrationType", "aws"),
				)

				for _, batch := range batchResources(resources) {
					params := &operations.AddResourcesParams{
						Body:       &api.AddResources{Resources: batch},
						HTTPClient: httpClient,
					}
					zap.L().Debug("adding new resources", zap.Any("params.Body", params.Body))
					if _, err = apiClient.Operations.AddResources(params); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}
